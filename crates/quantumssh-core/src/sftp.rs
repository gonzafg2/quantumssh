//! SFTP version 3 server (RFC-0013, ADR-0041), run in a helper mode of
//! the binary that the channel layer starts as an ordinary pipe child.
//!
//! The helper is single-threaded and synchronous: it reads framed
//! requests from fd 0 and writes each response to fd 1. Every
//! attacker-controlled length is bounded (OpenSSH's 256 KiB packet, the
//! read clamp, the handle cap), malformed input ends the session, and
//! every request gets exactly one response. File operations run as the
//! service account through `std::fs`, plus `rustix::fs::utimensat` for
//! path times; no first-party `unsafe` (ADR-0018).

// `pub(crate)` items are the surface the tests and the channel layer
// use; only the helper entry point is public API.
#![allow(clippy::redundant_pub_crate)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, FileTimes, Metadata, OpenOptions, ReadDir};
use std::io::{self, BufWriter, ErrorKind, Read, Write};
use std::iter::Peekable;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::wire::{Reader, WireError, Writer};

/// The reserved first argument that selects the SFTP helper mode.
pub const HELPER_ARG: &str = "--quantumssh-internal-sftp-server";

/// Packet bound: type plus payload (OpenSSH's `SFTP_MAX_MSG_LENGTH`).
const MAX_PACKET: usize = 256 * 1024;
/// READ and WRITE length bound (OpenSSH's `SFTP_MAX_READ_LENGTH`).
const MAX_DATA: u32 = 256 * 1024 - 1024;
/// Open file and directory handles (ADR-0041 §3).
const MAX_HANDLES: usize = 256;
/// Names per READDIR reply.
const MAX_NAMES: usize = 100;
/// Exit status on a protocol violation or a broken stdin/stdout.
const EXIT_VIOLATION: i32 = 2;

const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_LSTAT: u8 = 7;
const FXP_FSTAT: u8 = 8;
const FXP_SETSTAT: u8 = 9;
const FXP_FSETSTAT: u8 = 10;
const FXP_OPENDIR: u8 = 11;
const FXP_READDIR: u8 = 12;
const FXP_REMOVE: u8 = 13;
const FXP_MKDIR: u8 = 14;
const FXP_RMDIR: u8 = 15;
const FXP_REALPATH: u8 = 16;
const FXP_STAT: u8 = 17;
const FXP_RENAME: u8 = 18;
const FXP_READLINK: u8 = 19;
const FXP_SYMLINK: u8 = 20;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_NAME: u8 = 104;
const FXP_ATTRS: u8 = 105;
const FXP_EXTENDED: u8 = 200;
const FXP_EXTENDED_REPLY: u8 = 201;

const FX_OK: u32 = 0;
const FX_EOF: u32 = 1;
const FX_NO_SUCH_FILE: u32 = 2;
const FX_PERMISSION_DENIED: u32 = 3;
const FX_FAILURE: u32 = 4;
const FX_OP_UNSUPPORTED: u32 = 8;

const ATTR_SIZE: u32 = 0x1;
const ATTR_UIDGID: u32 = 0x2;
const ATTR_PERMISSIONS: u32 = 0x4;
const ATTR_ACMODTIME: u32 = 0x8;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const OPEN_READ: u32 = 0x1;
const OPEN_WRITE: u32 = 0x2;
const OPEN_APPEND: u32 = 0x4;
const OPEN_CREAT: u32 = 0x8;
const OPEN_TRUNC: u32 = 0x10;
const OPEN_EXCL: u32 = 0x20;

/// The extensions advertised in VERSION, each at version "1".
const EXTENSIONS: [&str; 4] = [
    "posix-rename@openssh.com",
    "fsync@openssh.com",
    "limits@openssh.com",
    "expand-path@openssh.com",
];

/// Runs the SFTP helper when the process was started with
/// [`HELPER_ARG`], and never returns in that case (ADR-0041 §2).
///
/// A binary that hosts the `sftp` subsystem calls this first in `main`,
/// before command-line parsing, configuration, logging or the runtime.
pub fn run_server_if_requested() {
    let mut args = std::env::args_os();
    let _ = args.next();
    if args.next().as_deref() != Some(OsStr::new(HELPER_ARG)) {
        return;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    // The session starts in the home directory, as sshd's child does.
    let in_home = home
        .as_deref()
        .is_some_and(|h| std::env::set_current_dir(h).is_ok());
    if !in_home {
        let _ = std::env::set_current_dir("/");
    }
    // `~` and relative REALPATHs resolve against the working directory,
    // as OpenSSH's `getcwd` (ADR-0041 §4).
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let code = serve(io::stdin().lock(), io::stdout().lock(), cwd);
    std::process::exit(code);
}

/// A malformed request: the session ends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation;

impl From<WireError> for Violation {
    fn from(_: WireError) -> Self {
        Self
    }
}

/// Serves one SFTP session until EOF on `input`, resolving `~` and
/// relative REALPATHs against `cwd`. Returns the helper's exit status: 0
/// at EOF, [`EXIT_VIOLATION`] on a protocol violation or when reading or
/// writing fails.
pub(crate) fn serve(mut input: impl Read, output: impl Write, cwd: PathBuf) -> i32 {
    let mut out = BufWriter::new(output);
    let mut server = Server::new(cwd);
    let mut packet = Vec::new();
    let mut first = true;
    loop {
        match read_packet(&mut input, &mut packet) {
            Ok(true) => {}
            Ok(false) => return 0,
            Err(Violation) => return EXIT_VIOLATION,
        }
        let reply = if first {
            first = false;
            // INIT's version is read and ignored; a truncated INIT is a
            // violation like any truncated field (ADR-0041 §3).
            let mut r = Reader::new(&packet);
            if r.byte() != Ok(FXP_INIT) || r.uint32().is_err() {
                return EXIT_VIOLATION;
            }
            version_reply()
        } else {
            match server.handle(&packet) {
                Ok(reply) => reply,
                Err(Violation) => return EXIT_VIOLATION,
            }
        };
        if write_packet(&mut out, &reply).is_err() {
            return EXIT_VIOLATION;
        }
    }
}

/// Reads one framed packet into `packet`. `Ok(false)` at a clean EOF
/// before the length; a length of 0 or over [`MAX_PACKET`], or a stream
/// that ends inside a packet, is a violation.
fn read_packet(input: &mut impl Read, packet: &mut Vec<u8>) -> Result<bool, Violation> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match input.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(Violation),
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(Violation),
        }
    }
    let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| Violation)?;
    if len == 0 || len > MAX_PACKET {
        return Err(Violation);
    }
    packet.clear();
    packet.resize(len, 0);
    input
        .read_exact(packet)
        .map_err(|_| Violation)
        .map(|()| true)
}

fn write_packet(out: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| io::Error::other("oversized reply"))?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(payload)?;
    out.flush()
}

fn version_reply() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(FXP_VERSION);
    w.put_uint32(3);
    for name in EXTENSIONS {
        w.put_string(name.as_bytes());
        w.put_string(b"1");
    }
    w.into_bytes()
}

/// An open handle.
enum Handle {
    File {
        file: File,
        append: bool,
        written: bool,
    },
    Dir {
        entries: Peekable<ReadDir>,
    },
}

/// Attributes a request asks to set.
#[derive(Default)]
struct SetAttrs {
    size: Option<u64>,
    owner: Option<(u32, u32)>,
    perm: Option<u32>,
    times: Option<(u32, u32)>,
}

/// One session's state.
struct Server {
    handles: Vec<Option<Handle>>,
    cwd: PathBuf,
}

impl Server {
    const fn new(cwd: PathBuf) -> Self {
        Self {
            handles: Vec::new(),
            cwd,
        }
    }

    /// Handles one request after INIT. Every request gets exactly one
    /// reply; a malformed one is a [`Violation`].
    fn handle(&mut self, packet: &[u8]) -> Result<Vec<u8>, Violation> {
        let mut r = Reader::new(packet);
        let kind = r.byte()?;
        let id = r.uint32()?;
        let reply = match kind {
            FXP_OPEN => self.open(id, &mut r)?,
            FXP_CLOSE => self.close(id, &mut r)?,
            FXP_READ => self.read(id, &mut r)?,
            FXP_WRITE => self.write(id, &mut r)?,
            FXP_STAT => stat(id, &path_arg(&mut r)?, true),
            FXP_LSTAT => stat(id, &path_arg(&mut r)?, false),
            FXP_FSTAT => self.fstat(id, &mut r)?,
            FXP_SETSTAT => {
                let path = path_arg(&mut r)?;
                let attrs = read_attrs(&mut r)?;
                status_of(id, setstat(&path, &attrs))
            }
            FXP_FSETSTAT => self.fsetstat(id, &mut r)?,
            FXP_OPENDIR => self.opendir(id, &mut r)?,
            FXP_READDIR => self.readdir(id, &mut r)?,
            FXP_REMOVE => status_of(id, fs::remove_file(path_arg(&mut r)?)),
            FXP_MKDIR => {
                let path = path_arg(&mut r)?;
                let attrs = read_attrs(&mut r)?;
                let mode = attrs.perm.map_or(0o777, |p| p & 0o777);
                status_of(id, DirBuilder::new().mode(mode).create(path))
            }
            FXP_RMDIR => status_of(id, fs::remove_dir(path_arg(&mut r)?)),
            FXP_REALPATH => match realpath(&path_arg(&mut r)?, &self.cwd) {
                Ok(path) => name_reply(id, &path),
                Err(e) => status_reply(id, error_code(&e)),
            },
            FXP_RENAME => {
                let old = path_arg(&mut r)?;
                let new = path_arg(&mut r)?;
                status_of(id, rename_no_overwrite(&old, &new))
            }
            FXP_READLINK => match fs::read_link(path_arg(&mut r)?) {
                Ok(target) => name_reply(id, &target),
                Err(e) => status_reply(id, error_code(&e)),
            },
            // OpenSSH's order: the target first, then the link path.
            FXP_SYMLINK => {
                let target = path_arg(&mut r)?;
                let link = path_arg(&mut r)?;
                status_of(id, std::os::unix::fs::symlink(target, link))
            }
            FXP_EXTENDED => self.extended(id, &mut r)?,
            _ => status_reply(id, FX_OP_UNSUPPORTED),
        };
        Ok(reply)
    }

    fn open(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let path = path_arg(r)?;
        let pflags = r.uint32()?;
        let attrs = read_attrs(r)?;
        // `p & 0o777` fits `mode_t` everywhere (u16 on macOS, u32 on Linux).
        let bits = attrs.perm.map_or(0o666, |p| p & 0o777);
        let mode =
            rustix::fs::Mode::from_raw_mode(rustix::fs::RawMode::try_from(bits).unwrap_or(0o666));
        let opened = rustix::fs::open(&path, open_flags(pflags), mode)
            .map(File::from)
            .map_err(io::Error::from);
        Ok(match opened {
            Ok(file) => self.insert(
                id,
                Handle::File {
                    file,
                    append: pflags & OPEN_APPEND != 0,
                    written: false,
                },
            ),
            Err(e) => status_reply(id, error_code(&e)),
        })
    }

    fn opendir(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let path = path_arg(r)?;
        Ok(match fs::read_dir(&path) {
            Ok(entries) => self.insert(
                id,
                Handle::Dir {
                    entries: entries.peekable(),
                },
            ),
            Err(e) => status_reply(id, error_code(&e)),
        })
    }

    /// Stores a handle under the cap and replies HANDLE, or FAILURE when
    /// the cap is reached.
    fn insert(&mut self, id: u32, handle: Handle) -> Vec<u8> {
        let slot = self.handles.iter().position(Option::is_none);
        let index = match slot {
            Some(i) => i,
            None if self.handles.len() < MAX_HANDLES => {
                self.handles.push(None);
                self.handles.len() - 1
            }
            None => return status_reply(id, FX_FAILURE),
        };
        self.handles[index] = Some(handle);
        let mut w = Writer::new();
        w.put_byte(FXP_HANDLE);
        w.put_uint32(id);
        // `index` < MAX_HANDLES, so it fits a u32.
        w.put_string(&u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes());
        w.into_bytes()
    }

    /// The index a handle string names, if it is a 4-byte index of an
    /// open handle.
    fn index(&self, r: &mut Reader<'_>) -> Result<Option<usize>, Violation> {
        let raw = r.string(MAX_PACKET)?;
        let Ok(bytes) = <[u8; 4]>::try_from(raw) else {
            return Ok(None);
        };
        let index = usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| Violation)?;
        Ok((index < self.handles.len() && self.handles[index].is_some()).then_some(index))
    }

    fn file(&mut self, r: &mut Reader<'_>) -> Result<Option<&mut Handle>, Violation> {
        Ok(match self.index(r)? {
            Some(i) => self.handles[i].as_mut(),
            None => None,
        })
    }

    fn close(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let Some(index) = self.index(r)? else {
            return Ok(status_reply(id, FX_FAILURE));
        };
        Ok(match self.handles[index].take() {
            // A written regular file is synced first: the only safe way to
            // see a deferred write error. A FIFO, socket or device is not:
            // `fdatasync` fails there with EINVAL (ADR-0041 §4).
            Some(Handle::File {
                file,
                written: true,
                ..
            }) => status_of(
                id,
                file.metadata().and_then(|m| {
                    if m.is_file() {
                        file.sync_data()
                    } else {
                        Ok(())
                    }
                }),
            ),
            Some(_) => status_reply(id, FX_OK),
            None => status_reply(id, FX_FAILURE),
        })
    }

    fn read(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let handle = self.file(r)?;
        let offset = r.uint64()?;
        let len = r.uint32()?.min(MAX_DATA);
        let Some(Handle::File { file, .. }) = handle else {
            return Ok(status_reply(id, FX_FAILURE));
        };
        let mut buf = vec![0u8; usize::try_from(len).map_err(|_| Violation)?];
        Ok(match file.read_at(&mut buf, offset) {
            Ok(0) => status_reply(id, FX_EOF),
            Ok(n) => {
                let mut w = Writer::new();
                w.put_byte(FXP_DATA);
                w.put_uint32(id);
                w.put_string(&buf[..n]);
                w.into_bytes()
            }
            Err(e) => status_reply(id, error_code(&e)),
        })
    }

    fn write(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let index = self.index(r)?;
        let offset = r.uint64()?;
        let data = r.string(MAX_PACKET)?;
        let Some(Some(Handle::File {
            file,
            append,
            written,
        })) = index.map(|i| self.handles[i].as_mut())
        else {
            return Ok(status_reply(id, FX_FAILURE));
        };
        // APPEND writes sequentially: `pwrite` ignores `O_APPEND` on
        // POSIX systems such as macOS (ADR-0041 §4).
        let result = if *append {
            file.write_all(data)
        } else {
            file.write_all_at(data, offset)
        };
        if result.is_ok() {
            *written = true;
        }
        Ok(status_of(id, result))
    }

    fn fstat(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        Ok(match self.file(r)? {
            Some(Handle::File { file, .. }) => match file.metadata() {
                Ok(m) => attrs_reply(id, &m),
                Err(e) => status_reply(id, error_code(&e)),
            },
            _ => status_reply(id, FX_FAILURE),
        })
    }

    fn fsetstat(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let index = self.index(r)?;
        let attrs = read_attrs(r)?;
        Ok(match index.and_then(|i| self.handles[i].as_mut()) {
            Some(Handle::File { file, .. }) => status_of(id, fsetstat(file, &attrs)),
            _ => status_reply(id, FX_FAILURE),
        })
    }

    fn readdir(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let Some(Some(Handle::Dir { entries })) = self.index(r)?.map(|i| self.handles[i].as_mut())
        else {
            return Ok(status_reply(id, FX_FAILURE));
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let mut names: Vec<(Vec<u8>, Vec<u8>, Metadata)> = Vec::new();
        // Type, id and count, then each entry's encoded size.
        let mut size = 1 + 4 + 4;
        while names.len() < MAX_NAMES {
            let Some(next) = entries.peek() else { break };
            let Ok(entry) = next else {
                entries.next();
                continue;
            };
            // Through the open directory, not a rebuilt path that a rename
            // may have changed; it does not follow symlinks.
            let Ok(meta) = entry.metadata() else {
                entries.next();
                continue;
            };
            let name = entry.file_name().into_vec();
            let long = longname(&name, &meta, now);
            let entry_size = 4 + name.len() + 4 + long.len() + ATTRS_LEN;
            if size + entry_size > MAX_PACKET {
                break;
            }
            size += entry_size;
            names.push((name, long, meta));
            entries.next();
        }
        if names.is_empty() {
            return Ok(status_reply(id, FX_EOF));
        }
        let mut w = Writer::new();
        w.put_byte(FXP_NAME);
        w.put_uint32(id);
        w.put_uint32(u32::try_from(names.len()).unwrap_or(0));
        for (name, long, meta) in &names {
            w.put_string(name);
            w.put_string(long);
            put_attrs(&mut w, meta);
        }
        Ok(w.into_bytes())
    }

    fn extended(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, Violation> {
        let name = r.string(MAX_PACKET)?;
        Ok(match name {
            b"posix-rename@openssh.com" => {
                let old = path_arg(r)?;
                let new = path_arg(r)?;
                status_of(id, fs::rename(old, new))
            }
            b"fsync@openssh.com" => match self.file(r)? {
                Some(Handle::File { file, .. }) => status_of(id, file.sync_all()),
                _ => status_reply(id, FX_FAILURE),
            },
            b"limits@openssh.com" => {
                let mut w = Writer::new();
                w.put_byte(FXP_EXTENDED_REPLY);
                w.put_uint32(id);
                w.put_uint64(MAX_PACKET as u64);
                w.put_uint64(u64::from(MAX_DATA));
                w.put_uint64(u64::from(MAX_DATA));
                w.put_uint64(MAX_HANDLES as u64);
                w.into_bytes()
            }
            b"expand-path@openssh.com" => {
                let path = r.string(MAX_PACKET)?;
                match self.expand(path).and_then(|p| realpath(&p, &self.cwd)) {
                    Ok(path) => name_reply(id, &path),
                    Err(e) => status_reply(id, error_code(&e)),
                }
            }
            _ => status_reply(id, FX_OP_UNSUPPORTED),
        })
    }

    /// `~` and `~/…` relative to the working directory, which is the
    /// service account's home or `/`, as OpenSSH's `getcwd`; `~user` is
    /// not resolved (ADR-0041 §4).
    fn expand(&self, path: &[u8]) -> io::Result<PathBuf> {
        if path == b"~" {
            return Ok(self.cwd.clone());
        }
        if let Some(rest) = path.strip_prefix(b"~/") {
            return Ok(self.cwd.join(OsStr::from_bytes(rest)));
        }
        if path.first() == Some(&b'~') {
            return Err(io::Error::from(ErrorKind::NotFound));
        }
        Ok(PathBuf::from(OsString::from_vec(path.to_vec())))
    }
}

/// A path argument: raw bytes, as SFTP v3 carries them.
fn path_arg(r: &mut Reader<'_>) -> Result<PathBuf, Violation> {
    Ok(PathBuf::from(OsString::from_vec(
        r.string(MAX_PACKET)?.to_vec(),
    )))
}

fn read_attrs(r: &mut Reader<'_>) -> Result<SetAttrs, Violation> {
    let flags = r.uint32()?;
    let mut attrs = SetAttrs::default();
    if flags & ATTR_SIZE != 0 {
        attrs.size = Some(r.uint64()?);
    }
    if flags & ATTR_UIDGID != 0 {
        attrs.owner = Some((r.uint32()?, r.uint32()?));
    }
    if flags & ATTR_PERMISSIONS != 0 {
        attrs.perm = Some(r.uint32()?);
    }
    if flags & ATTR_ACMODTIME != 0 {
        attrs.times = Some((r.uint32()?, r.uint32()?));
    }
    // Extended pairs are read and ignored; a count larger than the packet
    // holds runs out of data and is a violation.
    if flags & ATTR_EXTENDED != 0 {
        for _ in 0..r.uint32()? {
            r.string(MAX_PACKET)?;
            r.string(MAX_PACKET)?;
        }
    }
    Ok(attrs)
}

/// The encoded size of a full ATTRS: flags, size, uid, gid, permissions,
/// atime, mtime.
const ATTRS_LEN: usize = 4 + 8 + 4 + 4 + 4 + 4 + 4;

fn put_attrs(w: &mut Writer, m: &Metadata) {
    w.put_uint32(ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME);
    w.put_uint64(m.len());
    w.put_uint32(m.uid());
    w.put_uint32(m.gid());
    w.put_uint32(m.mode());
    w.put_uint32(clamp_time(m.atime()));
    w.put_uint32(clamp_time(m.mtime()));
}

fn clamp_time(secs: i64) -> u32 {
    u32::try_from(secs.max(0)).unwrap_or(u32::MAX)
}

fn stat(id: u32, path: &Path, follow: bool) -> Vec<u8> {
    let meta = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match meta {
        Ok(m) => attrs_reply(id, &m),
        Err(e) => status_reply(id, error_code(&e)),
    }
}

/// SETSTAT, in ADR-0041 §4's order; the first failure ends it.
fn setstat(path: &Path, attrs: &SetAttrs) -> io::Result<()> {
    if let Some(size) = attrs.size {
        OpenOptions::new().write(true).open(path)?.set_len(size)?;
    }
    if let Some((uid, gid)) = attrs.owner {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    if let Some(perm) = attrs.perm {
        fs::set_permissions(path, fs::Permissions::from_mode(perm & 0o7777))?;
    }
    if let Some((atime, mtime)) = attrs.times {
        let at = |secs: u32| rustix::fs::Timespec {
            tv_sec: i64::from(secs),
            tv_nsec: 0,
        };
        let times = rustix::fs::Timestamps {
            last_access: at(atime),
            last_modification: at(mtime),
        };
        rustix::fs::utimensat(rustix::fs::CWD, path, &times, rustix::fs::AtFlags::empty())?;
    }
    Ok(())
}

fn fsetstat(file: &File, attrs: &SetAttrs) -> io::Result<()> {
    if let Some(size) = attrs.size {
        file.set_len(size)?;
    }
    if let Some((uid, gid)) = attrs.owner {
        fchown(file, Some(uid), Some(gid))?;
    }
    if let Some(perm) = attrs.perm {
        file.set_permissions(fs::Permissions::from_mode(perm & 0o7777))?;
    }
    if let Some((atime, mtime)) = attrs.times {
        let at = |secs: u32| UNIX_EPOCH + Duration::from_secs(u64::from(secs));
        file.set_times(
            FileTimes::new()
                .set_accessed(at(atime))
                .set_modified(at(mtime)),
        )?;
    }
    Ok(())
}

/// OpenSSH's flags for an SFTP OPEN (`flags_from_portable`): READ and
/// WRITE choose the access mode, and APPEND, CREAT, TRUNC and EXCL each
/// add their own flag, so READ|APPEND stays read-only and READ|CREAT is
/// valid — combinations `OpenOptions` cannot express (ADR-0041 §4).
fn open_flags(pflags: u32) -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    let mut flags = match (pflags & OPEN_READ != 0, pflags & OPEN_WRITE != 0) {
        (true, true) => OFlags::RDWR,
        (false, true) => OFlags::WRONLY,
        _ => OFlags::RDONLY,
    } | OFlags::CLOEXEC;
    for (bit, flag) in [
        (OPEN_APPEND, OFlags::APPEND),
        (OPEN_CREAT, OFlags::CREATE),
        (OPEN_TRUNC, OFlags::TRUNC),
        (OPEN_EXCL, OFlags::EXCL),
    ] {
        if pflags & bit != 0 {
            flags |= flag;
        }
    }
    flags
}

/// Symlinks REALPATH follows before it fails (OpenSSH's `SYMLOOP_MAX`).
const SYMLOOP_MAX: u32 = 32;

/// REALPATH by OpenSSH's algorithm (`sftp-realpath.c`): components are
/// resolved left to right, every symlink is followed (the last
/// component's included), and only a missing **last** component is
/// accepted, so a dangling final symlink resolves to its target's path.
/// A relative path starts from `cwd`; an empty path means `.`.
fn realpath(path: &Path, cwd: &Path) -> io::Result<PathBuf> {
    let path = path.as_os_str().as_bytes();
    let (mut resolved, mut left) = match path {
        [] => (cwd.as_os_str().as_bytes().to_vec(), b".".to_vec()),
        [b'/', rest @ ..] => (b"/".to_vec(), rest.to_vec()),
        _ => (cwd.as_os_str().as_bytes().to_vec(), path.to_vec()),
    };
    let mut links = 0;
    while !left.is_empty() {
        let (token, last) = match left.iter().position(|&b| b == b'/') {
            Some(i) => {
                let token = left[..i].to_vec();
                left.drain(..=i);
                (token, false)
            }
            None => (std::mem::take(&mut left), true),
        };
        if resolved.last() != Some(&b'/') {
            resolved.push(b'/');
        }
        match token.as_slice() {
            b"" | b"." => continue,
            b".." => {
                pop_component(&mut resolved);
                continue;
            }
            _ => {}
        }
        resolved.extend_from_slice(&token);
        let meta = match fs::symlink_metadata(OsStr::from_bytes(&resolved)) {
            Err(e) if e.kind() == ErrorKind::NotFound && last => break,
            other => other?,
        };
        if meta.file_type().is_symlink() {
            links += 1;
            if links > SYMLOOP_MAX {
                return Err(rustix::io::Errno::LOOP.into());
            }
            let mut target = fs::read_link(OsStr::from_bytes(&resolved))?
                .into_os_string()
                .into_vec();
            if target.first() == Some(&b'/') {
                resolved.truncate(1);
            } else {
                pop_component(&mut resolved);
            }
            // The link's target, then whatever followed the link.
            if !last {
                if target.last() != Some(&b'/') {
                    target.push(b'/');
                }
                target.extend_from_slice(&left);
            }
            left = target;
        }
    }
    if resolved.len() > 1 && resolved.last() == Some(&b'/') {
        resolved.pop();
    }
    Ok(PathBuf::from(OsString::from_vec(resolved)))
}

/// Drops the last component of `resolved`, keeping the root.
fn pop_component(resolved: &mut Vec<u8>) {
    if resolved.len() <= 1 {
        return;
    }
    let end = if resolved.last() == Some(&b'/') {
        resolved.len() - 1
    } else {
        resolved.len()
    };
    let cut = resolved[..end]
        .iter()
        .rposition(|&b| b == b'/')
        .map_or(1, |i| i + 1);
    resolved.truncate(cut.max(1));
}

/// RENAME with OpenSSH's no-overwrite semantics (`sftp-server.c:1274-1314`).
fn rename_no_overwrite(old: &Path, new: &Path) -> io::Result<()> {
    if fs::symlink_metadata(old)?.is_file() {
        match fs::hard_link(old, new) {
            Ok(()) => {
                if let Err(e) = fs::remove_file(old) {
                    // Do not leave the file under both names.
                    let _ = fs::remove_file(new);
                    return Err(e);
                }
                Ok(())
            }
            // A filesystem without hard links, or another device.
            Err(e) if is_link_unsupported(&e) => rename_if_absent(old, new),
            Err(e) => Err(e),
        }
    } else {
        rename_if_absent(old, new)
    }
}

/// An existence check that does not follow a symlink, so an existing
/// dangling symlink at `new` is never replaced (ADR-0041 §4).
fn rename_if_absent(old: &Path, new: &Path) -> io::Result<()> {
    if fs::symlink_metadata(new).is_ok() {
        return Err(io::Error::from(ErrorKind::AlreadyExists));
    }
    fs::rename(old, new)
}

/// `link()` errors that mean "no hard link here": OpenSSH's list, with
/// Linux's `EPERM` (its `LINK_OPNOTSUPP_ERRNO`, `configure.ac:974`).
fn is_link_unsupported(error: &io::Error) -> bool {
    use rustix::io::Errno;
    let unsupported: &[Errno] = if cfg!(target_os = "linux") {
        &[Errno::OPNOTSUPP, Errno::NOSYS, Errno::XDEV, Errno::PERM]
    } else {
        &[Errno::OPNOTSUPP, Errno::NOSYS, Errno::XDEV]
    };
    error
        .raw_os_error()
        .is_some_and(|code| unsupported.iter().any(|e| e.raw_os_error() == code))
}

fn error_code(error: &io::Error) -> u32 {
    match error.kind() {
        ErrorKind::NotFound => FX_NO_SUCH_FILE,
        ErrorKind::PermissionDenied => FX_PERMISSION_DENIED,
        _ => FX_FAILURE,
    }
}

fn status_of(id: u32, result: io::Result<()>) -> Vec<u8> {
    status_reply(id, result.map_or_else(|e| error_code(&e), |()| FX_OK))
}

/// STATUS with the code's fixed message and an empty language tag: no OS
/// error detail is sent.
fn status_reply(id: u32, code: u32) -> Vec<u8> {
    let message: &[u8] = match code {
        FX_OK => b"Success",
        FX_EOF => b"End of file",
        FX_NO_SUCH_FILE => b"No such file",
        FX_PERMISSION_DENIED => b"Permission denied",
        FX_OP_UNSUPPORTED => b"Operation unsupported",
        _ => b"Failure",
    };
    let mut w = Writer::new();
    w.put_byte(FXP_STATUS);
    w.put_uint32(id);
    w.put_uint32(code);
    w.put_string(message);
    w.put_string(b"");
    w.into_bytes()
}

fn attrs_reply(id: u32, m: &Metadata) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(FXP_ATTRS);
    w.put_uint32(id);
    put_attrs(&mut w, m);
    w.into_bytes()
}

/// A NAME with one entry whose name and longname are both `path`, and no
/// attributes, as OpenSSH replies to REALPATH and READLINK.
fn name_reply(id: u32, path: &Path) -> Vec<u8> {
    let bytes = path.as_os_str().as_bytes();
    let mut w = Writer::new();
    w.put_byte(FXP_NAME);
    w.put_uint32(id);
    w.put_uint32(1);
    w.put_string(bytes);
    w.put_string(bytes);
    w.put_uint32(0);
    w.into_bytes()
}

/// OpenSSH's `ls -l` longname with numeric owner and group and the mtime
/// in UTC (ADR-0041 §5).
fn longname(name: &[u8], m: &Metadata, now: i64) -> Vec<u8> {
    let date = ls_date(m.mtime(), now);
    let mut line = format!(
        "{} {:>3} {:<8} {:<8} {:>8} {date} ",
        mode_string(m.mode()),
        m.nlink(),
        m.uid(),
        m.gid(),
        m.len()
    )
    .into_bytes();
    line.extend_from_slice(name);
    line
}

/// The `ls -l` date in UTC: `%b %e %H:%M` for an mtime in the six months
/// up to now, `%b %e  %Y` otherwise, a future mtime included (OpenSSH's
/// `sftp-common.c:242-246`).
fn ls_date(mtime: i64, now: i64) -> String {
    let (year, month, day) = civil_from_days(mtime.div_euclid(86_400));
    if mtime <= now && now.saturating_sub(mtime) < 365 * 24 * 60 * 60 / 2 {
        let secs = mtime.rem_euclid(86_400);
        format!(
            "{} {day:>2} {:02}:{:02}",
            MONTHS[month],
            secs / 3600,
            secs % 3600 / 60
        )
    } else {
        format!("{} {day:>2}  {year}", MONTHS[month])
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 to (year, month index 0–11, day), the proleptic
/// Gregorian civil date (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, usize, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // `month` is 1–12.
    (year, usize::try_from(month - 1).unwrap_or(0), day)
}

/// The `ls -l` mode string for `st_mode`.
fn mode_string(mode: u32) -> String {
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '-',
    };
    let bit = |mask: u32, c: char| if mode & mask == 0 { '-' } else { c };
    let exec =
        |x: u32, special: u32, on: char, off: char| match (mode & x != 0, mode & special != 0) {
            (true, true) => on,
            (false, true) => off,
            (true, false) => 'x',
            (false, false) => '-',
        };
    [
        kind,
        bit(0o400, 'r'),
        bit(0o200, 'w'),
        exec(0o100, 0o4000, 's', 'S'),
        bit(0o040, 'r'),
        bit(0o020, 'w'),
        exec(0o010, 0o2000, 's', 'S'),
        bit(0o004, 'r'),
        bit(0o002, 'w'),
        exec(0o001, 0o1000, 't', 'T'),
    ]
    .iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh directory under the system temp dir.
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("quantumssh-sftp-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        fs::canonicalize(dir).expect("canonical temp dir")
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn init() -> Vec<u8> {
        frame(&[FXP_INIT, 0, 0, 0, 3])
    }

    fn request(kind: u8, id: u32, build: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_byte(kind);
        w.put_uint32(id);
        build(&mut w);
        frame(&w.into_bytes())
    }

    fn path(p: &Path) -> &[u8] {
        p.as_os_str().as_bytes()
    }

    /// Runs a session over `input` and returns the exit status and the
    /// reply payloads.
    fn run(input: &[u8]) -> (i32, Vec<Vec<u8>>) {
        let mut out = Vec::new();
        let code = serve(Cursor::new(input.to_vec()), &mut out, PathBuf::from("/"));
        let mut replies = Vec::new();
        let mut rest = &out[..];
        while rest.len() >= 4 {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            replies.push(rest[4..4 + len].to_vec());
            rest = &rest[4 + len..];
        }
        (code, replies)
    }

    fn status_code(reply: &[u8]) -> u32 {
        let mut r = Reader::new(reply);
        assert_eq!(r.byte().unwrap(), FXP_STATUS, "a STATUS reply: {reply:?}");
        let _ = r.uint32().unwrap();
        r.uint32().unwrap()
    }

    fn handle_of(reply: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(reply);
        assert_eq!(r.byte().unwrap(), FXP_HANDLE);
        let _ = r.uint32().unwrap();
        r.string(64).unwrap().to_vec()
    }

    #[test]
    fn version_advertises_three_and_the_four_extensions() {
        let (code, replies) = run(&init());
        assert_eq!(code, 0);
        let mut r = Reader::new(&replies[0]);
        assert_eq!(r.byte().unwrap(), FXP_VERSION);
        assert_eq!(r.uint32().unwrap(), 3);
        for name in EXTENSIONS {
            assert_eq!(r.string(64).unwrap(), name.as_bytes());
            assert_eq!(r.string(64).unwrap(), b"1");
        }
        r.finish().unwrap();
    }

    #[test]
    fn malformed_input_ends_the_session() {
        // Not INIT first.
        assert_eq!(run(&request(FXP_REALPATH, 1, |w| w.put_string(b"."))).0, 2);
        // Oversized length.
        let mut big = init();
        big.extend_from_slice(&u32::try_from(MAX_PACKET + 1).unwrap().to_be_bytes());
        assert_eq!(run(&big).0, 2);
        // A truncated field: REALPATH without its path.
        let mut short = init();
        short.extend_from_slice(&frame(&[FXP_REALPATH, 0, 0, 0, 1]));
        assert_eq!(run(&short).0, 2);
        // A stream that ends inside a packet.
        let mut cut = init();
        cut.extend_from_slice(&[0, 0, 0, 9, FXP_REALPATH]);
        assert_eq!(run(&cut).0, 2);
    }

    #[test]
    fn unknown_requests_get_op_unsupported() {
        let mut input = init();
        input.extend_from_slice(&request(99, 5, |_| {}));
        input.extend_from_slice(&request(FXP_EXTENDED, 6, |w| {
            w.put_string(b"nope@example.com");
        }));
        let (code, replies) = run(&input);
        assert_eq!(code, 0);
        assert_eq!(status_code(&replies[1]), FX_OP_UNSUPPORTED);
        assert_eq!(status_code(&replies[2]), FX_OP_UNSUPPORTED);
    }

    #[test]
    fn write_then_read_back_and_close() {
        let dir = temp_dir();
        let file = dir.join("f");
        let mut input = init();
        input.extend_from_slice(&request(FXP_OPEN, 1, |w| {
            w.put_string(path(&file));
            w.put_uint32(OPEN_WRITE | OPEN_CREAT | OPEN_TRUNC);
            w.put_uint32(0);
        }));
        let (_, replies) = run(&input);
        let handle = handle_of(&replies[1]);

        let mut input = init();
        input.extend_from_slice(&request(FXP_OPEN, 1, |w| {
            w.put_string(path(&file));
            w.put_uint32(OPEN_WRITE | OPEN_CREAT | OPEN_TRUNC);
            w.put_uint32(0);
        }));
        input.extend_from_slice(&request(FXP_WRITE, 2, |w| {
            w.put_string(&handle);
            w.put_uint64(0);
            w.put_string(b"hello world");
        }));
        input.extend_from_slice(&request(FXP_CLOSE, 3, |w| w.put_string(&handle)));
        let (code, replies) = run(&input);
        assert_eq!(code, 0);
        assert_eq!(status_code(&replies[2]), FX_OK);
        assert_eq!(status_code(&replies[3]), FX_OK);
        assert_eq!(fs::read(&file).unwrap(), b"hello world");

        let mut input = init();
        input.extend_from_slice(&request(FXP_OPEN, 1, |w| {
            w.put_string(path(&file));
            w.put_uint32(OPEN_READ);
            w.put_uint32(0);
        }));
        input.extend_from_slice(&request(FXP_READ, 2, |w| {
            w.put_string(&handle);
            w.put_uint64(6);
            w.put_uint32(u32::MAX);
        }));
        input.extend_from_slice(&request(FXP_READ, 3, |w| {
            w.put_string(&handle);
            w.put_uint64(11);
            w.put_uint32(10);
        }));
        let (_, replies) = run(&input);
        let mut r = Reader::new(&replies[2]);
        assert_eq!(r.byte().unwrap(), FXP_DATA);
        let _ = r.uint32().unwrap();
        assert_eq!(r.string(MAX_PACKET).unwrap(), b"world");
        assert_eq!(status_code(&replies[3]), FX_EOF);
    }

    #[test]
    fn append_writes_ignore_the_offset() {
        let dir = temp_dir();
        let file = dir.join("log");
        fs::write(&file, b"abc").unwrap();
        let mut input = init();
        input.extend_from_slice(&request(FXP_OPEN, 1, |w| {
            w.put_string(path(&file));
            w.put_uint32(OPEN_WRITE | OPEN_APPEND);
            w.put_uint32(0);
        }));
        input.extend_from_slice(&request(FXP_WRITE, 2, |w| {
            w.put_string(&0u32.to_be_bytes());
            w.put_uint64(0);
            w.put_string(b"def");
        }));
        let (_, replies) = run(&input);
        assert_eq!(status_code(&replies[2]), FX_OK);
        assert_eq!(fs::read(&file).unwrap(), b"abcdef");
    }

    #[test]
    fn invalid_handles_get_failure_and_the_cap_holds() {
        let dir = temp_dir();
        let mut input = init();
        input.extend_from_slice(&request(FXP_CLOSE, 1, |w| w.put_string(b"xyz")));
        input.extend_from_slice(&request(FXP_CLOSE, 2, |w| {
            w.put_string(&7u32.to_be_bytes());
        }));
        for i in 0..=MAX_HANDLES {
            input.extend_from_slice(&request(FXP_OPENDIR, 10 + u32::try_from(i).unwrap(), |w| {
                w.put_string(path(&dir));
            }));
        }
        let (code, replies) = run(&input);
        assert_eq!(code, 0);
        assert_eq!(status_code(&replies[1]), FX_FAILURE);
        assert_eq!(status_code(&replies[2]), FX_FAILURE);
        assert_eq!(handle_of(&replies[3 + MAX_HANDLES - 1]).len(), 4);
        assert_eq!(status_code(&replies[3 + MAX_HANDLES]), FX_FAILURE);
    }

    #[test]
    fn readdir_lists_entries_then_eof() {
        let dir = temp_dir();
        fs::write(dir.join("a"), b"1").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        let mut input = init();
        input.extend_from_slice(&request(FXP_OPENDIR, 1, |w| w.put_string(path(&dir))));
        input.extend_from_slice(&request(FXP_READDIR, 2, |w| {
            w.put_string(&0u32.to_be_bytes());
        }));
        input.extend_from_slice(&request(FXP_READDIR, 3, |w| {
            w.put_string(&0u32.to_be_bytes());
        }));
        let (_, replies) = run(&input);
        let mut r = Reader::new(&replies[2]);
        assert_eq!(r.byte().unwrap(), FXP_NAME);
        let _ = r.uint32().unwrap();
        let count = r.uint32().unwrap();
        let mut names = Vec::new();
        for _ in 0..count {
            names.push(r.string(MAX_PACKET).unwrap().to_vec());
            let long = r.string(MAX_PACKET).unwrap();
            assert!(long.ends_with(names.last().unwrap()));
            let flags = r.uint32().unwrap();
            assert_eq!(
                flags,
                ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME
            );
            let _ = r.bytes(ATTRS_LEN - 4).unwrap();
        }
        names.sort();
        assert_eq!(names, vec![b"a".to_vec(), b"sub".to_vec()]);
        assert_eq!(status_code(&replies[3]), FX_EOF);
    }

    #[test]
    fn realpath_resolves_a_missing_last_component() {
        let dir = temp_dir();
        let root = Path::new("/");
        let resolved = realpath(&dir.join("missing"), root).unwrap();
        assert_eq!(resolved, dir.join("missing"));
        assert!(realpath(&dir.join("no/such"), root).is_err());
        // Relative paths and an empty path start from the working directory.
        assert_eq!(realpath(Path::new("x"), &dir).unwrap(), dir.join("x"));
        assert_eq!(realpath(Path::new(""), &dir).unwrap(), dir);
        assert_eq!(
            realpath(&dir.join("a/../b/./c"), root).unwrap_err().kind(),
            ErrorKind::NotFound,
            "`a` is missing and not last"
        );
        fs::create_dir(dir.join("a")).unwrap();
        assert_eq!(realpath(&dir.join("a/../b"), root).unwrap(), dir.join("b"));
    }

    /// OpenSSH follows the final symlink too: a dangling one resolves to
    /// its missing target, not to the link's own path (`sftp-realpath.c`).
    #[test]
    fn realpath_follows_symlinks_the_final_one_included() {
        let dir = temp_dir();
        let root = Path::new("/");
        std::os::unix::fs::symlink("gone", dir.join("dangling")).unwrap();
        assert_eq!(
            realpath(&dir.join("dangling"), root).unwrap(),
            dir.join("gone")
        );
        fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("abs")).unwrap();
        assert_eq!(
            realpath(&dir.join("abs/f"), root).unwrap(),
            dir.join("real/f")
        );
        std::os::unix::fs::symlink("loop", dir.join("loop")).unwrap();
        assert!(realpath(&dir.join("loop"), root).is_err());
    }

    #[test]
    fn rename_refuses_to_overwrite_and_posix_rename_does() {
        let dir = temp_dir();
        let (a, b) = (dir.join("a"), dir.join("b"));
        fs::write(&a, b"A").unwrap();
        fs::write(&b, b"B").unwrap();
        assert!(rename_no_overwrite(&a, &b).is_err());
        assert_eq!(fs::read(&b).unwrap(), b"B");
        assert!(a.exists(), "a refused rename leaves the source in place");

        let c = dir.join("c");
        rename_no_overwrite(&a, &c).unwrap();
        assert!(!a.exists());
        assert_eq!(fs::read(&c).unwrap(), b"A");

        let mut input = init();
        input.extend_from_slice(&request(FXP_EXTENDED, 1, |w| {
            w.put_string(b"posix-rename@openssh.com");
            w.put_string(path(&c));
            w.put_string(path(&b));
        }));
        let (_, replies) = run(&input);
        assert_eq!(status_code(&replies[1]), FX_OK);
        assert_eq!(fs::read(&b).unwrap(), b"A");
    }

    #[test]
    fn rename_cleans_the_spare_link_when_the_source_cannot_be_removed() {
        let dir = temp_dir();
        let locked = dir.join("locked");
        fs::create_dir(&locked).unwrap();
        let old = locked.join("f");
        fs::write(&old, b"x").unwrap();
        let new = dir.join("g");
        // Read and search only: the link can be made from it, but the
        // source cannot be unlinked.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
        let result = rename_no_overwrite(&old, &new);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        if rustix::process::geteuid().is_root() {
            // Root ignores the directory's permissions.
            return;
        }
        assert!(result.is_err());
        assert!(old.exists(), "the source stays");
        assert!(!new.exists(), "the spare link is removed");
    }

    /// `~` is the working directory, as OpenSSH's `getcwd`: the home, or
    /// `/` when the home was unusable.
    #[test]
    fn expand_path_handles_tilde_forms() {
        let cwd = temp_dir();
        let server = Server::new(cwd.clone());
        assert_eq!(server.expand(b"~").unwrap(), cwd);
        assert_eq!(server.expand(b"~/x").unwrap(), cwd.join("x"));
        assert_eq!(
            server.expand(b"~root/x").unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(server.expand(b"/etc").unwrap(), PathBuf::from("/etc"));
    }

    #[test]
    fn limits_report_the_bounds() {
        let mut input = init();
        input.extend_from_slice(&request(FXP_EXTENDED, 1, |w| {
            w.put_string(b"limits@openssh.com");
        }));
        let (_, replies) = run(&input);
        let mut r = Reader::new(&replies[1]);
        assert_eq!(r.byte().unwrap(), FXP_EXTENDED_REPLY);
        let _ = r.uint32().unwrap();
        assert_eq!(r.uint64().unwrap(), 262_144);
        assert_eq!(r.uint64().unwrap(), 261_120);
        assert_eq!(r.uint64().unwrap(), 261_120);
        assert_eq!(r.uint64().unwrap(), 256);
    }

    #[test]
    fn status_messages_are_fixed_and_carry_an_empty_language_tag() {
        let reply = status_reply(9, FX_NO_SUCH_FILE);
        let mut r = Reader::new(&reply);
        assert_eq!(r.byte().unwrap(), FXP_STATUS);
        assert_eq!(r.uint32().unwrap(), 9);
        assert_eq!(r.uint32().unwrap(), FX_NO_SUCH_FILE);
        assert_eq!(r.string(64).unwrap(), b"No such file");
        assert_eq!(r.string(64).unwrap(), b"");
        r.finish().unwrap();
        assert_eq!(
            error_code(&io::Error::from(ErrorKind::PermissionDenied)),
            FX_PERMISSION_DENIED
        );
        assert_eq!(
            error_code(&io::Error::from(ErrorKind::AlreadyExists)),
            FX_FAILURE
        );
    }

    /// INIT's version must be there: a truncated INIT ends the session.
    #[test]
    fn init_without_a_version_ends_the_session() {
        assert_eq!(run(&frame(&[FXP_INIT])).0, 2);
        assert_eq!(run(&frame(&[FXP_INIT, 0, 0])).0, 2);
        assert_eq!(run(&init()).0, 0);
    }

    /// OpenSSH's flag mapping: READ|CREAT creates a file and opens it
    /// read-only; READ|APPEND does not grant write access. Handles are the
    /// 4-byte indices 0 and 1.
    #[test]
    fn open_maps_flags_independently() {
        let dir = temp_dir();
        let created = dir.join("created");
        let appended = dir.join("appended");
        fs::write(&appended, b"x").unwrap();
        let mut input = init();
        for (id, file, flags) in [
            (1, &created, OPEN_READ | OPEN_CREAT),
            (2, &appended, OPEN_READ | OPEN_APPEND),
        ] {
            input.extend_from_slice(&request(FXP_OPEN, id, |w| {
                w.put_string(path(file));
                w.put_uint32(flags);
                w.put_uint32(0);
            }));
        }
        for (id, index) in [(3, 0u32), (4, 1)] {
            input.extend_from_slice(&request(FXP_WRITE, id, |w| {
                w.put_string(&index.to_be_bytes());
                w.put_uint64(0);
                w.put_string(b"y");
            }));
        }
        let (_, replies) = run(&input);
        assert_eq!(handle_of(&replies[1]), 0u32.to_be_bytes());
        assert_eq!(handle_of(&replies[2]), 1u32.to_be_bytes());
        assert!(created.is_file(), "READ|CREAT created the file");
        assert_eq!(
            status_code(&replies[3]),
            FX_FAILURE,
            "READ|CREAT is read-only"
        );
        assert_eq!(
            status_code(&replies[4]),
            FX_FAILURE,
            "READ|APPEND is read-only"
        );
        assert_eq!(fs::read(&appended).unwrap(), b"x");
    }

    /// CLOSE syncs written regular files only: writing to a device and
    /// closing it succeeds, as under OpenSSH.
    #[test]
    fn close_of_a_written_device_succeeds() {
        let handle = 0u32.to_be_bytes();
        let mut input = init();
        input.extend_from_slice(&request(FXP_OPEN, 1, |w| {
            w.put_string(b"/dev/null");
            w.put_uint32(OPEN_WRITE);
            w.put_uint32(0);
        }));
        input.extend_from_slice(&request(FXP_WRITE, 2, |w| {
            w.put_string(&handle);
            w.put_uint64(0);
            w.put_string(b"data");
        }));
        input.extend_from_slice(&request(FXP_CLOSE, 3, |w| w.put_string(&handle)));
        let (_, replies) = run(&input);
        assert_eq!(handle_of(&replies[1]), handle);
        assert_eq!(status_code(&replies[2]), FX_OK);
        assert_eq!(status_code(&replies[3]), FX_OK);
    }

    /// An existing dangling symlink at the destination counts as existing:
    /// RENAME never replaces it.
    #[test]
    fn rename_does_not_replace_a_dangling_symlink() {
        let dir = temp_dir();
        let (src, dst) = (dir.join("dir"), dir.join("link"));
        fs::create_dir(&src).unwrap();
        std::os::unix::fs::symlink("gone", &dst).unwrap();
        assert_eq!(
            rename_no_overwrite(&src, &dst).unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert!(src.is_dir());
        assert!(fs::symlink_metadata(&dst).unwrap().file_type().is_symlink());
    }

    /// The time form only for an mtime in the six months up to now; a
    /// future mtime gets the year (OpenSSH's rule).
    #[test]
    fn ls_dates_follow_openssh() {
        // 2026-10-12 12:34 UTC.
        let now = 20_738 * 86_400 + 12 * 3600 + 34 * 60;
        assert_eq!(ls_date(now - 3600, now), "Oct 12 11:34");
        assert_eq!(ls_date(now - 200 * 86_400, now), "Mar 26  2026");
        assert_eq!(ls_date(now + 60, now), "Oct 12  2026");
        assert_eq!(ls_date(now + 10 * 365 * 86_400, now), "Oct  9  2036");
    }

    #[test]
    fn civil_dates_and_mode_strings() {
        assert_eq!(civil_from_days(0), (1970, 0, 1));
        // 2026-10-12 is day 20 738.
        assert_eq!(civil_from_days(20_738), (2026, 9, 12));
        assert_eq!(civil_from_days(-1), (1969, 11, 31));
        assert_eq!(mode_string(0o100_644), "-rw-r--r--");
        assert_eq!(mode_string(0o040_755), "drwxr-xr-x");
        assert_eq!(mode_string(0o104_755), "-rwsr-xr-x");
        assert_eq!(mode_string(0o041_777), "drwxrwxrwt");
        assert_eq!(mode_string(0o120_777), "lrwxrwxrwx");
    }
}
