//! Pseudo-terminal sessions (ADR-0038 §2, §4, §5).
//!
//! - **Parsing** of a `pty-req`'s attacker-controlled fields, every one
//!   bounded: the `TERM` rule, the window dimensions, and the encoded
//!   terminal modes of RFC 4254 §8.
//! - **Allocation** of the pair with `rustix`'s safe `pty` and `termios`
//!   functions: a close-on-exec master, a slave owned by the service
//!   account and set to `0600` while the pair is still locked.
//! - **The re-exec helper** that makes the shell a session leader with
//!   the slave as its controlling terminal, without `pre_exec`: a binary
//!   that hosts PTY sessions calls [`run_helper_if_requested`] first in
//!   `main`. No first-party `unsafe` (ADR-0018).

// `pub(crate)` items are the surface the channel and exec modules use;
// `redundant_pub_crate` would prefer `pub`, but only the helper entry
// point is public API.
#![allow(clippy::redundant_pub_crate)]

use std::ffi::{CStr, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{Mode, OFlags};
use rustix::termios::{
    ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex, Termios,
    Winsize,
};

/// The reserved first argument that selects the helper mode of a binary
/// hosting PTY sessions. An internal contract between one binary and
/// itself, not an operator interface (ADR-0038 §5).
pub const HELPER_ARG: &str = "--quantumssh-internal-pty-helper";
/// The helper's exit status when it cannot run the program: the
/// conventional "could not execute".
const HELPER_FAILED: i32 = 127;

/// Bound on a `pty-req`'s `TERM` string (ADR-0038 §2).
pub(crate) const TERM_BOUND: usize = 64;
/// Bound on a `pty-req`'s encoded terminal modes (ADR-0038 §2).
pub(crate) const MODES_BOUND: usize = 1024;

/// `_POSIX_VDISABLE`: the value that disables a special character. RFC
/// 4254 §8 encodes it as 255.
#[cfg(target_os = "linux")]
const POSIX_VDISABLE: u8 = 0;
#[cfg(not(target_os = "linux"))]
const POSIX_VDISABLE: u8 = 0xff;

/// Runs the PTY helper when the process was started with
/// [`HELPER_ARG`], and never returns in that case (ADR-0038 §5).
///
/// A binary that hosts PTY sessions calls this first in `main`, before
/// command-line parsing, configuration, logging or the runtime, so the
/// helper is single-threaded and never touches server state. The helper
/// makes itself a session leader (`setsid`), takes its stdin — the PTY
/// slave — as its controlling terminal (`TIOCSCTTY`), and then `exec`s
/// the program with the given `argv[0]`. On any failure it exits with
/// status 127 and prints nothing, because fd 2 is the user's terminal.
pub fn run_helper_if_requested() {
    let mut args = std::env::args_os();
    let _ = args.next();
    if args.next().as_deref() != Some(OsStr::new(HELPER_ARG)) {
        return;
    }
    std::process::exit(helper(args));
}

/// The helper body; returns only on failure.
fn helper(mut args: impl Iterator<Item = OsString>) -> i32 {
    use std::os::unix::process::CommandExt;
    let (Some(program), Some(argv0)) = (args.next(), args.next()) else {
        return HELPER_FAILED;
    };
    if rustix::process::setsid().is_err()
        || rustix::process::ioctl_tiocsctty(std::io::stdin()).is_err()
    {
        return HELPER_FAILED;
    }
    // `exec` replaces the process image and returns only on failure.
    let _ = std::process::Command::new(program)
        .arg0(argv0)
        .args(args)
        .exec();
    HELPER_FAILED
}

/// `TERM` rule (ADR-0038 §2): empty means no `TERM` in the child's
/// environment; anything else must match `[A-Za-z0-9._+-]+`.
pub(crate) fn valid_term(term: &[u8]) -> bool {
    term.iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// The four dimensions of a `pty-req` or `window-change`, in RFC 4254
/// order: columns, rows, pixel width, pixel height.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Size {
    pub cols: u32,
    pub rows: u32,
    pub width_px: u32,
    pub height_px: u32,
}

impl Size {
    /// Applies the dimensions to `current`: zero keeps a field ("Zero
    /// dimension parameters MUST be ignored", RFC 4254 §6.2), and a
    /// nonzero value is clamped to the `u16` a `Winsize` holds.
    fn apply(self, current: Winsize) -> Winsize {
        Winsize {
            ws_col: dim(self.cols, current.ws_col),
            ws_row: dim(self.rows, current.ws_row),
            ws_xpixel: dim(self.width_px, current.ws_xpixel),
            ws_ypixel: dim(self.height_px, current.ws_ypixel),
        }
    }
}

fn dim(value: u32, current: u16) -> u16 {
    if value == 0 {
        current
    } else {
        u16::try_from(value).unwrap_or(u16::MAX)
    }
}

/// Applies a `window-change` to the master; the kernel signals `SIGWINCH`
/// to the foreground job.
///
/// # Errors
///
/// The `tcgetwinsize`/`tcsetwinsize` error.
pub(crate) fn resize(master: impl AsFd, size: Size) -> io::Result<()> {
    let current = rustix::termios::tcgetwinsize(&master)?;
    rustix::termios::tcsetwinsize(&master, size.apply(current))?;
    Ok(())
}

/// A mode argument ends before its four bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TruncatedMode;

/// Encoded terminal modes (RFC 4254 §8), parsed from the borrowed blob
/// without allocation. Opcodes 1–159 carry a `uint32`; the last value of
/// a repeated opcode wins.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Modes {
    values: [Option<u32>; 160],
}

impl Modes {
    /// Parses the blob. `TTY_OP_END` (0), an opcode of 160 or more, or
    /// the end of the blob ends it; an empty blob carries no modes.
    ///
    /// # Errors
    ///
    /// [`TruncatedMode`] when an argument is cut short — the only
    /// malformed case.
    pub(crate) fn parse(blob: &[u8]) -> Result<Self, TruncatedMode> {
        let mut values = [None; 160];
        let mut rest = blob;
        while let Some((&opcode, tail)) = rest.split_first() {
            if opcode == 0 || opcode >= 160 {
                break;
            }
            let (arg, tail) = tail.split_first_chunk::<4>().ok_or(TruncatedMode)?;
            values[usize::from(opcode)] = Some(u32::from_be_bytes(*arg));
            rest = tail;
        }
        Ok(Self { values })
    }

    fn get(&self, opcode: u8) -> Option<u32> {
        self.values[usize::from(opcode)]
    }

    /// Applies every mode whose termios field exists on this platform,
    /// starting from the pair's defaults (ADR-0038 §2). Unknown opcodes,
    /// platform gaps and the speeds (128, 129) are ignored.
    fn apply(&self, termios: &mut Termios) {
        for opcode in 1..160u8 {
            let Some(value) = self.get(opcode) else {
                continue;
            };
            if let Some(index) = special_code(opcode) {
                // 255 disables the character; a value above 255 is ignored.
                if let Ok(byte) = u8::try_from(value) {
                    termios.special_codes[index] = if byte == 255 { POSIX_VDISABLE } else { byte };
                }
            } else if let Some(flag) = flag(opcode) {
                flag.set(termios, value != 0);
            }
        }
        // `CS7` (90) and `CS8` (91) are values of the multi-bit `CSIZE`
        // field, not flags. A zero never selects a size, so no client can
        // drive `CSIZE` to `CS5` or `CS6`.
        let size = if self.get(91).is_some_and(|v| v != 0) {
            Some(ControlModes::CS8)
        } else if self.get(90).is_some_and(|v| v != 0) {
            Some(ControlModes::CS7)
        } else {
            None
        };
        if let Some(size) = size {
            termios.control_modes.remove(ControlModes::CSIZE);
            termios.control_modes.insert(size);
        }
    }
}

/// The special character an opcode names (RFC 4254 §8, 1–18), where the
/// platform has the field.
const fn special_code(opcode: u8) -> Option<SpecialCodeIndex> {
    Some(match opcode {
        1 => SpecialCodeIndex::VINTR,
        2 => SpecialCodeIndex::VQUIT,
        3 => SpecialCodeIndex::VERASE,
        4 => SpecialCodeIndex::VKILL,
        5 => SpecialCodeIndex::VEOF,
        6 => SpecialCodeIndex::VEOL,
        7 => SpecialCodeIndex::VEOL2,
        8 => SpecialCodeIndex::VSTART,
        9 => SpecialCodeIndex::VSTOP,
        10 => SpecialCodeIndex::VSUSP,
        #[cfg(target_os = "macos")]
        11 => SpecialCodeIndex::VDSUSP,
        12 => SpecialCodeIndex::VREPRINT,
        13 => SpecialCodeIndex::VWERASE,
        14 => SpecialCodeIndex::VLNEXT,
        #[cfg(target_os = "linux")]
        16 => SpecialCodeIndex::VSWTC,
        #[cfg(target_os = "macos")]
        17 => SpecialCodeIndex::VSTATUS,
        18 => SpecialCodeIndex::VDISCARD,
        _ => return None,
    })
}

/// A single-bit termios flag.
#[derive(Clone, Copy)]
enum Flag {
    Input(InputModes),
    Local(LocalModes),
    Output(OutputModes),
    Control(ControlModes),
}

impl Flag {
    fn set(self, termios: &mut Termios, on: bool) {
        match self {
            Self::Input(f) => termios.input_modes.set(f, on),
            Self::Local(f) => termios.local_modes.set(f, on),
            Self::Output(f) => termios.output_modes.set(f, on),
            Self::Control(f) => termios.control_modes.set(f, on),
        }
    }
}

/// The flag an opcode names (RFC 4254 §8 and RFC 8160), where the
/// platform has it. `CS7`/`CS8` are not here: see [`Modes::apply`].
const fn flag(opcode: u8) -> Option<Flag> {
    Some(match opcode {
        30 => Flag::Input(InputModes::IGNPAR),
        31 => Flag::Input(InputModes::PARMRK),
        32 => Flag::Input(InputModes::INPCK),
        33 => Flag::Input(InputModes::ISTRIP),
        34 => Flag::Input(InputModes::INLCR),
        35 => Flag::Input(InputModes::IGNCR),
        36 => Flag::Input(InputModes::ICRNL),
        #[cfg(target_os = "linux")]
        37 => Flag::Input(InputModes::IUCLC),
        38 => Flag::Input(InputModes::IXON),
        39 => Flag::Input(InputModes::IXANY),
        40 => Flag::Input(InputModes::IXOFF),
        41 => Flag::Input(InputModes::IMAXBEL),
        42 => Flag::Input(InputModes::IUTF8),
        50 => Flag::Local(LocalModes::ISIG),
        51 => Flag::Local(LocalModes::ICANON),
        #[cfg(target_os = "linux")]
        52 => Flag::Local(LocalModes::XCASE),
        53 => Flag::Local(LocalModes::ECHO),
        54 => Flag::Local(LocalModes::ECHOE),
        55 => Flag::Local(LocalModes::ECHOK),
        56 => Flag::Local(LocalModes::ECHONL),
        57 => Flag::Local(LocalModes::NOFLSH),
        58 => Flag::Local(LocalModes::TOSTOP),
        59 => Flag::Local(LocalModes::IEXTEN),
        60 => Flag::Local(LocalModes::ECHOCTL),
        61 => Flag::Local(LocalModes::ECHOKE),
        62 => Flag::Local(LocalModes::PENDIN),
        70 => Flag::Output(OutputModes::OPOST),
        #[cfg(target_os = "linux")]
        71 => Flag::Output(OutputModes::OLCUC),
        72 => Flag::Output(OutputModes::ONLCR),
        73 => Flag::Output(OutputModes::OCRNL),
        74 => Flag::Output(OutputModes::ONOCR),
        75 => Flag::Output(OutputModes::ONLRET),
        92 => Flag::Control(ControlModes::PARENB),
        93 => Flag::Control(ControlModes::PARODD),
        _ => return None,
    })
}

/// A newly allocated pair: the master non-blocking, the slave blocking
/// for the child, the client's modes and size applied (ADR-0038 §4).
pub(crate) struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// Allocates a pair for a `pty-req` (ADR-0038 §4).
///
/// # Errors
///
/// Any failed step: opening `/dev/ptmx`, `grantpt`, a slave that the
/// server's UID does not own, `chmod`, `unlockpt`, opening the slave, a
/// slave whose owner or mode is not as set, or applying the modes or the
/// size. Every descriptor opened so far is closed on return.
pub(crate) fn allocate(modes: &Modes, size: Size) -> io::Result<PtyPair> {
    // Close-on-exec at open, on every platform: a concurrent spawn must
    // never inherit the master, or closing it would not hang up.
    let master = rustix::fs::open(
        "/dev/ptmx",
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::pty::grantpt(&master)?;
    // Owner and mode while the pair is locked and nobody can open the
    // slave: do not rely on the `devpts` mount options.
    let name = rustix::pty::ptsname(&master, Vec::new())?;
    let uid = rustix::process::getuid().as_raw();
    if rustix::fs::stat(name.as_c_str())?.st_uid != uid {
        return Err(io::Error::other("pty slave is not owned by the server"));
    }
    rustix::fs::chmod(name.as_c_str(), Mode::RUSR | Mode::WUSR)?;
    rustix::pty::unlockpt(&master)?;
    let slave = open_slave(&master, &name)?;
    let stat = rustix::fs::fstat(&slave)?;
    if stat.st_uid != uid || Mode::from_raw_mode(stat.st_mode) != Mode::RUSR | Mode::WUSR {
        return Err(io::Error::other("pty slave owner or mode changed"));
    }
    rustix::io::ioctl_fionbio(&master, true)?;
    let mut termios = rustix::termios::tcgetattr(&slave)?;
    modes.apply(&mut termios);
    rustix::termios::tcsetattr(&slave, OptionalActions::Now, &termios)?;
    resize(&master, size)?;
    Ok(PtyPair { master, slave })
}

/// Opens the slave without a path lookup (kernel ≥ 4.13).
#[cfg(target_os = "linux")]
fn open_slave(master: &OwnedFd, _name: &CStr) -> io::Result<OwnedFd> {
    use rustix::pty::OpenptFlags;
    Ok(rustix::pty::ioctl_tiocgptpeer(
        master,
        OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
    )?)
}

/// Opens the slave by the name `ptsname` returned.
#[cfg(not(target_os = "linux"))]
fn open_slave(_master: &OwnedFd, name: &CStr) -> io::Result<OwnedFd> {
    Ok(rustix::fs::open(
        name,
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(pairs: &[(u8, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(opcode, value) in pairs {
            out.push(opcode);
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }

    #[test]
    fn empty_blob_carries_no_modes() {
        assert_eq!(
            Modes::parse(&[]),
            Ok(Modes {
                values: [None; 160]
            })
        );
    }

    #[test]
    fn end_opcode_and_high_opcodes_stop_parsing() {
        let mut b = blob(&[(53, 0)]);
        b.push(0);
        b.extend_from_slice(&blob(&[(51, 0)]));
        let modes = Modes::parse(&b).expect("parse");
        assert_eq!(modes.get(53), Some(0));
        assert_eq!(modes.get(51), None, "TTY_OP_END ends the stream");

        let mut b = blob(&[(53, 1)]);
        b.push(160);
        b.extend_from_slice(&[0xde, 0xad]);
        let modes = Modes::parse(&b).expect("parse stops at 160");
        assert_eq!(modes.get(53), Some(1));
    }

    #[test]
    fn truncated_argument_is_the_only_error() {
        assert_eq!(Modes::parse(&[53, 0, 0, 1]), Err(TruncatedMode));
        assert_eq!(Modes::parse(&[53]), Err(TruncatedMode));
    }

    #[test]
    fn a_repeated_opcode_keeps_the_last_value() {
        let modes = Modes::parse(&blob(&[(53, 1), (53, 0)])).expect("parse");
        assert_eq!(modes.get(53), Some(0));
    }

    #[test]
    fn cs8_wins_over_cs7_and_zero_never_selects_a_size() {
        let mut t = rustix::termios::tcgetattr(
            allocate(&Modes::parse(&[]).unwrap(), Size::default())
                .unwrap()
                .slave,
        )
        .unwrap();

        t.control_modes.remove(ControlModes::CSIZE);
        t.control_modes.insert(ControlModes::CS7);
        Modes::parse(&blob(&[(90, 1), (91, 1)]))
            .unwrap()
            .apply(&mut t);
        assert_eq!(t.control_modes & ControlModes::CSIZE, ControlModes::CS8);

        Modes::parse(&blob(&[(90, 1), (91, 0)]))
            .unwrap()
            .apply(&mut t);
        assert_eq!(t.control_modes & ControlModes::CSIZE, ControlModes::CS7);

        Modes::parse(&blob(&[(90, 0), (91, 0)]))
            .unwrap()
            .apply(&mut t);
        assert_eq!(
            t.control_modes & ControlModes::CSIZE,
            ControlModes::CS7,
            "zeros keep the current size"
        );
    }

    #[test]
    fn flags_and_special_characters() {
        let mut t = rustix::termios::tcgetattr(
            allocate(&Modes::parse(&[]).unwrap(), Size::default())
                .unwrap()
                .slave,
        )
        .unwrap();
        let modes =
            Modes::parse(&blob(&[(53, 0), (42, 1), (3, 0x7f), (1, 255), (2, 256)])).unwrap();
        let quit = t.special_codes[SpecialCodeIndex::VQUIT];
        modes.apply(&mut t);
        assert!(!t.local_modes.contains(LocalModes::ECHO));
        assert!(t.input_modes.contains(InputModes::IUTF8));
        assert_eq!(t.special_codes[SpecialCodeIndex::VERASE], 0x7f);
        assert_eq!(t.special_codes[SpecialCodeIndex::VINTR], POSIX_VDISABLE);
        assert_eq!(
            t.special_codes[SpecialCodeIndex::VQUIT],
            quit,
            "above 255 is ignored"
        );
    }

    #[test]
    fn term_rule() {
        assert!(valid_term(b""));
        assert!(valid_term(b"xterm-256color"));
        assert!(valid_term(b"screen.xterm-256color"));
        assert!(valid_term(b"rxvt-unicode+x_1"));
        assert!(!valid_term(b"../../etc"));
        assert!(!valid_term(b"xterm 256"));
        assert!(!valid_term(b"xterm\n"));
        assert!(!valid_term("xtérm".as_bytes()));
    }

    #[test]
    fn zero_keeps_a_dimension_and_large_values_clamp() {
        let current = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let applied = Size {
            cols: 0,
            rows: 100_000,
            width_px: 640,
            height_px: 0,
        }
        .apply(current);
        assert_eq!(applied.ws_col, 80);
        assert_eq!(applied.ws_row, u16::MAX);
        assert_eq!(applied.ws_xpixel, 640);
        assert_eq!(applied.ws_ypixel, 0);
    }

    #[test]
    fn allocation_locks_down_the_slave_and_applies_modes_and_size() {
        let modes = Modes::parse(&blob(&[(53, 0)])).unwrap();
        let size = Size {
            cols: 100,
            rows: 40,
            width_px: 0,
            height_px: 0,
        };
        let pair = allocate(&modes, size).expect("allocate");
        let stat = rustix::fs::fstat(&pair.slave).expect("fstat");
        assert_eq!(stat.st_uid, rustix::process::getuid().as_raw());
        assert_eq!(Mode::from_raw_mode(stat.st_mode), Mode::RUSR | Mode::WUSR);
        let t = rustix::termios::tcgetattr(&pair.slave).expect("tcgetattr");
        assert!(!t.local_modes.contains(LocalModes::ECHO));
        let ws = rustix::termios::tcgetwinsize(&pair.master).expect("winsize");
        assert_eq!((ws.ws_col, ws.ws_row), (100, 40));
        let flags = rustix::io::fcntl_getfd(&pair.master).expect("getfd");
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[tokio::test]
    async fn the_master_is_driven_through_asyncfd() {
        let pair = allocate(&Modes::parse(&[]).unwrap(), Size::default()).expect("allocate");
        // ponytail: the deprecated constructor, sound as in
        // `exec::wait_exit`: the master is moved in and never duplicated.
        #[allow(deprecated)]
        let master = tokio::io::unix::AsyncFd::new(pair.master).expect("AsyncFd takes the master");
        rustix::io::write(&pair.slave, b"probe").expect("write to the slave");
        let mut guard = tokio::time::timeout(std::time::Duration::from_secs(5), master.readable())
            .await
            .expect("readable in time")
            .expect("readiness");
        let mut buf = [0u8; 16];
        let n = guard
            .try_io(|fd| rustix::io::read(fd.get_ref(), &mut buf).map_err(io::Error::from))
            .expect("not would-block")
            .expect("read");
        assert_eq!(&buf[..n], b"probe");
    }
}
