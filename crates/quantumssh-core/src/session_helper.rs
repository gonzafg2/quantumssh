//! The session helper of account mode (ADR-0065): a fresh, single-threaded
//! copy of the binary that becomes the account, checks that root cannot
//! be regained, and runs the session.
//!
//! The launcher starts it as root, with [`HELPER_ARG`] first and the
//! arguments of [`HelperArgs::to_args`], and with the session's
//! environment already set (ADR-0065 §3). Run by anyone but root, it
//! fails at the first identity call and exits with 127 (ADR-0065 §5).

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The reserved first argument that selects the session helper.
pub const HELPER_ARG: &str = "--quantumssh-internal-session";

/// The exit status of any failure: "could not execute" (ADR-0038 §5).
pub const HELPER_FAILED: i32 = 127;

/// The highest ID an argument may carry; `(uid_t)-1` means "leave
/// unchanged" to setresuid(2) (ADR-0071 §2).
const MAX_ID: u32 = u32::MAX - 1;

/// What the session runs (ADR-0065 §2, step 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    /// The login shell with `-c` and the client's command.
    Exec(OsString),
    /// The login shell as a login shell.
    Shell,
    /// The SFTP server, in this process.
    Sftp,
}

/// The helper's arguments, all from the launcher's read of the account
/// for this session (ADR-0065 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// What the session runs.
    pub run: Run,
    /// Whether stdin is a PTY slave, which becomes the controlling
    /// terminal. Never with [`Run::Sftp`].
    pub pty: bool,
    /// The account's UID.
    pub uid: u32,
    /// Its primary GID.
    pub gid: u32,
    /// Every group the session gets, the primary GID included: never
    /// empty.
    pub groups: Vec<u32>,
    /// The home directory.
    pub home: PathBuf,
    /// The program: the login shell, absolute.
    pub program: PathBuf,
}

impl HelperArgs {
    /// The arguments after [`HELPER_ARG`], in ADR-0065 §1's order.
    #[must_use]
    pub fn to_args(&self) -> Vec<OsString> {
        let kind = match self.run {
            Run::Exec(_) => "exec",
            Run::Shell => "shell",
            Run::Sftp => "sftp",
        };
        let groups = self
            .groups
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut args: Vec<OsString> = vec![
            kind.into(),
            if self.pty { "pty" } else { "pipes" }.into(),
            self.uid.to_string().into(),
            self.gid.to_string().into(),
            groups.into(),
            self.home.clone().into_os_string(),
            self.program.clone().into_os_string(),
        ];
        if let Run::Exec(command) = &self.run {
            args.push(command.clone());
        }
        args
    }

    /// Parses the arguments after [`HELPER_ARG`]. `None` for any list
    /// that [`HelperArgs::to_args`] could not have written.
    #[must_use]
    pub fn parse(args: &[OsString]) -> Option<Self> {
        let [kind, pty, uid, gid, groups, home, program, rest @ ..] = args else {
            return None;
        };
        let run = match (kind.as_bytes(), rest) {
            (b"exec", [command]) => Run::Exec(command.clone()),
            (b"shell", []) => Run::Shell,
            (b"sftp", []) => Run::Sftp,
            _ => return None,
        };
        let pty = match pty.as_bytes() {
            b"pty" if run != Run::Sftp => true,
            b"pipes" => false,
            _ => return None,
        };
        let groups = groups
            .as_bytes()
            .split(|&b| b == b',')
            .map(id)
            .collect::<Option<Vec<_>>>()?;
        let program = PathBuf::from(program);
        let home = PathBuf::from(home);
        (!groups.is_empty() && program.is_absolute() && home.is_absolute()).then_some(())?;
        Some(Self {
            run,
            pty,
            uid: id(uid.as_bytes())?,
            gid: id(gid.as_bytes())?,
            groups,
            home,
            program,
        })
    }
}

/// A decimal ID of 1 to 10 digits, at most [`MAX_ID`].
fn id(field: &[u8]) -> Option<u32> {
    if field.is_empty() || field.len() > 10 || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(field)
        .ok()?
        .parse::<u32>()
        .ok()
        .filter(|&v| v <= MAX_ID)
}

/// Runs the session helper when the process was started with
/// [`HELPER_ARG`], and never returns in that case (ADR-0065 §1).
///
/// The binary calls this first in `main`, before any other helper mode,
/// CLI parsing, configuration, logging or runtime, so the process is
/// single-threaded throughout.
#[cfg(target_os = "linux")]
pub fn run_if_requested() {
    let mut args = std::env::args_os();
    let _ = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(HELPER_ARG)) {
        return;
    }
    let rest: Vec<OsString> = args.collect();
    let code = HelperArgs::parse(&rest).map_or(HELPER_FAILED, linux::run);
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use rustix::process::{Gid, Uid, getegid, geteuid, getgid, getgroups, getuid};
    use rustix::thread::{capabilities, set_thread_groups, set_thread_res_gid, set_thread_res_uid};

    use super::{HELPER_FAILED, HelperArgs, Run};

    /// ADR-0065 §2's sequence. Returns only on failure, or when the SFTP
    /// server ends, with the exit status.
    pub(super) fn run(args: HelperArgs) -> i32 {
        // 1. Session leader, while still root.
        if rustix::process::setsid().is_err()
            || (args.pty && rustix::process::ioctl_tiocsctty(std::io::stdin()).is_err())
        {
            return HELPER_FAILED;
        }
        // 2-4. Groups, then GID, then UID.
        let uid = Uid::from_raw(args.uid);
        let gid = Gid::from_raw(args.gid);
        let groups: Vec<Gid> = args.groups.iter().map(|&g| Gid::from_raw(g)).collect();
        if set_thread_groups(&groups).is_err()
            || set_thread_res_gid(gid, gid, gid).is_err()
            || set_thread_res_uid(uid, uid, uid).is_err()
        {
            return HELPER_FAILED;
        }
        // 5. The change is checked, not assumed.
        if !dropped(uid, gid, &args.groups) {
            return HELPER_FAILED;
        }
        // 6. Home, or `/`.
        if std::env::set_current_dir(&args.home).is_err() && std::env::set_current_dir("/").is_err()
        {
            return HELPER_FAILED;
        }
        // 7. The session. `exec` returns only on failure.
        let base = base_name(&args.program);
        match args.run {
            Run::Exec(command) => {
                let _ = Command::new(&args.program)
                    .arg0(base)
                    .arg("-c")
                    .arg(command)
                    .exec();
                HELPER_FAILED
            }
            Run::Shell => {
                let mut argv0 = std::ffi::OsString::from("-");
                argv0.push(base);
                let _ = Command::new(&args.program).arg0(argv0).exec();
                HELPER_FAILED
            }
            Run::Sftp => crate::sftp::serve_stdio(),
        }
    }

    /// The base name of `program`, for argv[0].
    pub(super) fn base_name(program: &std::path::Path) -> &std::ffi::OsStr {
        program.file_name().unwrap_or(program.as_os_str())
    }

    /// ADR-0065 §2, step 5: the real and effective IDs, the groups and
    /// every capability set read back as set, and neither root UID nor
    /// root GID can be regained. A failed `setresuid(0, 0, 0)` proves the
    /// saved UID is not 0, because an unprivileged process may set each
    /// ID only to a current real, effective or saved one (setresuid(2)).
    fn dropped(uid: Uid, gid: Gid, groups: &[u32]) -> bool {
        if getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid {
            return false;
        }
        let Ok(actual) = getgroups() else {
            return false;
        };
        let mut actual: Vec<u32> = actual.into_iter().map(Gid::as_raw).collect();
        actual.sort_unstable();
        actual.dedup();
        let mut expected = groups.to_vec();
        expected.sort_unstable();
        expected.dedup();
        if actual != expected {
            return false;
        }
        let Ok(caps) = capabilities(None) else {
            return false;
        };
        if !(caps.permitted.is_empty() && caps.effective.is_empty() && caps.inheritable.is_empty())
        {
            return false;
        }
        if set_thread_res_uid(Uid::ROOT, Uid::ROOT, Uid::ROOT).is_ok() {
            return false;
        }
        gid == Gid::ROOT || set_thread_res_gid(Gid::ROOT, Gid::ROOT, Gid::ROOT).is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(run: Run, pty: bool) -> HelperArgs {
        HelperArgs {
            run,
            pty,
            uid: 1001,
            gid: 1001,
            groups: vec![999, 1001, 2000],
            home: PathBuf::from("/home/alice"),
            program: PathBuf::from("/bin/bash"),
        }
    }

    #[test]
    fn arguments_round_trip() {
        for a in [
            args(Run::Exec("echo hi; id".into()), false),
            args(Run::Exec(OsString::new()), true),
            args(Run::Shell, true),
            args(Run::Shell, false),
            args(Run::Sftp, false),
        ] {
            assert_eq!(HelperArgs::parse(&a.to_args()), Some(a.clone()), "{a:?}");
        }
    }

    #[test]
    fn the_order_is_adr_0065s() {
        let a = args(Run::Exec("uptime".into()), false).to_args();
        let a: Vec<&str> = a.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            a,
            [
                "exec",
                "pipes",
                "1001",
                "1001",
                "999,1001,2000",
                "/home/alice",
                "/bin/bash",
                "uptime"
            ]
        );
    }

    #[test]
    fn lists_to_args_could_not_have_written_are_refused() {
        let good = args(Run::Shell, false).to_args();
        let with = |i: usize, v: &str| {
            let mut a = good.clone();
            a[i] = v.into();
            HelperArgs::parse(&a)
        };
        assert_eq!(with(0, "login"), None);
        assert_eq!(with(1, "tty"), None);
        for bad_id in ["", "-1", "+1", "4294967295", "0x1", "12345678901", "1 "] {
            assert_eq!(with(2, bad_id), None, "uid {bad_id:?}");
            assert_eq!(with(3, bad_id), None, "gid {bad_id:?}");
            assert_eq!(with(4, bad_id), None, "groups {bad_id:?}");
        }
        assert_eq!(with(4, "1,,2"), None);
        assert_eq!(with(5, "home/alice"), None);
        assert_eq!(with(6, "bash"), None);
        // A command on shell, none on exec, a PTY on sftp.
        let mut extra = good.clone();
        extra.push("uptime".into());
        assert_eq!(HelperArgs::parse(&extra), None);
        let mut exec = good.clone();
        exec[0] = "exec".into();
        assert_eq!(HelperArgs::parse(&exec), None);
        let mut sftp = args(Run::Sftp, false).to_args();
        sftp[1] = "pty".into();
        assert_eq!(HelperArgs::parse(&sftp), None);
        assert_eq!(HelperArgs::parse(&good[..6]), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn argv0_is_the_base_name() {
        use super::linux::base_name;
        assert_eq!(base_name(std::path::Path::new("/bin/bash")), "bash");
        assert_eq!(
            base_name(std::path::Path::new("/usr/sbin/nologin")),
            "nologin"
        );
    }
}
