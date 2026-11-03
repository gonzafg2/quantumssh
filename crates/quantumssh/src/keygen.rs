//! `quantumssh keygen <PATH>` (RFC-0018, ADR-0058 §3): writes a new
//! `ssh-mldsa44-ed25519` host key and its `.pub` file. Both are created
//! relative to a descriptor of the checked parent directory, never through
//! a path-based `open`.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use quantumssh_core::host_key::{GeneratedHostKey, RngError, generate_host_key};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::config::{ancestor_violation, mode_of};

/// Runs the subcommand: on success, prints the two paths with their modes
/// and the fingerprint.
pub fn main(path: &Path) -> ExitCode {
    match run(path, generate_host_key) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// One of the two files: its name in the directory and its full path.
struct Target {
    leaf: OsString,
    path: PathBuf,
}

/// Why a run failed, and whether private-key bytes may have reached the
/// disk (RFC-0018 §3).
struct Failure {
    message: String,
    key_written: bool,
}

/// Writes the pair at `path` with the key `generate` returns. Production
/// passes [`generate_host_key`]; only this module's tests pass anything
/// else (ADR-0058 §3).
fn run(
    path: &Path,
    generate: impl FnOnce() -> Result<GeneratedHostKey, RngError>,
) -> Result<String, String> {
    let (parent, leaf) = split(path)?;
    let parent = std::fs::canonicalize(&parent)
        .map_err(|e| format!("{}: cannot resolve the directory: {e}", parent.display()))?;
    let dir = rustix::fs::open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: cannot open the directory: {e}", parent.display()))?;
    check_directory(&dir, &parent)?;

    let mut public_leaf = leaf.clone();
    public_leaf.push(".pub");
    let private = Target {
        path: parent.join(&leaf),
        leaf,
    };
    let public = Target {
        path: parent.join(&public_leaf),
        leaf: public_leaf,
    };
    let mut created = Vec::new();
    write_pair(&dir, &private, &public, &mut created, generate)
        .map_err(|failure| remove_created(&dir, &created, failure))
}

/// `<PATH>` as its parent directory and a leaf that must be a file name
/// (ADR-0058 §3 step 1). A bare file name's parent is `.`.
fn split(path: &Path) -> Result<(PathBuf, OsString), String> {
    let bytes = path.as_os_str().as_bytes();
    let (parent, leaf): (&[u8], &[u8]) = match bytes.iter().rposition(|&b| b == b'/') {
        None => (b".", bytes),
        Some(0) => (b"/", &bytes[1..]),
        Some(i) => (&bytes[..i], &bytes[i + 1..]),
    };
    if matches!(leaf, b"" | b"." | b"..") {
        return Err(format!(
            "{}: the path must end in a file name",
            path.display()
        ));
    }
    Ok((
        PathBuf::from(OsStr::from_bytes(parent)),
        OsStr::from_bytes(leaf).to_owned(),
    ))
}

/// ADR-0029's ancestor rule, on the directory the files go into (through
/// its descriptor) and on every directory above it (ADR-0058 §3 step 3).
/// A key the server would refuse to read is refused now.
fn check_directory(dir: &OwnedFd, canonical: &Path) -> Result<(), String> {
    let refused = |at: &Path, violation: String| {
        format!(
            "{}: {violation}; the server would refuse a key there (ADR-0029)",
            at.display()
        )
    };
    let st =
        rustix::fs::fstat(dir).map_err(|e| format!("{}: cannot stat: {e}", canonical.display()))?;
    if let Some(violation) = ancestor_violation(mode_of(&st)) {
        return Err(refused(canonical, violation));
    }
    for ancestor in canonical.ancestors().skip(1) {
        let st = rustix::fs::stat(ancestor)
            .map_err(|e| format!("{}: cannot stat: {e}", ancestor.display()))?;
        if let Some(violation) = ancestor_violation(mode_of(&st)) {
            return Err(refused(ancestor, violation));
        }
    }
    Ok(())
}

/// Steps 4 to 9 of ADR-0058 §3. Each file this run creates is recorded in
/// `created` before anything else can fail.
fn write_pair<'a>(
    dir: &OwnedFd,
    private: &'a Target,
    public: &'a Target,
    created: &mut Vec<&'a Target>,
    generate: impl FnOnce() -> Result<GeneratedHostKey, RngError>,
) -> Result<String, Failure> {
    let private_mode = Mode::RUSR | Mode::WUSR;
    let public_mode = private_mode | Mode::RGRP | Mode::ROTH;
    // The private file is never wider than 0600, from the moment it
    // exists: the mode is set in the open itself (RFC-0018 §3).
    let mut private_file = create(dir, private, private_mode, created)?;
    let mut public_file = create(dir, public, public_mode, created)?;
    // Undo whatever the umask removed: a umask of 077 would leave the
    // public file at 0600.
    for (file, target, mode) in [
        (&private_file, private, private_mode),
        (&public_file, public, public_mode),
    ] {
        rustix::fs::fchmod(file, mode).map_err(|e| Failure {
            message: format!("{}: cannot set its mode: {e}", target.path.display()),
            key_written: false,
        })?;
    }

    let key = generate().map_err(|e| Failure {
        message: format!("{e}; no key was written"),
        key_written: false,
    })?;
    write_synced(&mut private_file, private, key.private_pem.as_bytes())?;
    write_synced(
        &mut public_file,
        public,
        format!("{}\n", key.public_line).as_bytes(),
    )?;

    let observed = |file: &File, target: &Target| {
        rustix::fs::fstat(file)
            .map(|st| mode_of(&st) & 0o7777)
            .map_err(|e| Failure {
                message: format!("{}: cannot stat: {e}", target.path.display()),
                key_written: true,
            })
    };
    let private_observed = observed(&private_file, private)?;
    let public_observed = observed(&public_file, public)?;
    Ok(format!(
        "wrote {} (private, {private_observed:04o})\nwrote {} (public, {public_observed:04o})\n{}\n",
        private.path.display(),
        public.path.display(),
        key.fingerprint
    ))
}

/// Creates `target` empty with `mode`, refusing an existing file or a
/// symlink (ADR-0058 §3 steps 4 and 5).
fn create<'a>(
    dir: &OwnedFd,
    target: &'a Target,
    mode: Mode,
    created: &mut Vec<&'a Target>,
) -> Result<File, Failure> {
    let flags = OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::WRONLY | OFlags::CLOEXEC;
    match rustix::fs::openat(dir, target.leaf.as_os_str(), flags, mode) {
        Ok(fd) => {
            created.push(target);
            Ok(File::from(fd))
        }
        Err(e) => {
            let why = if e == Errno::EXIST {
                "already exists; keygen never replaces a file".to_owned()
            } else {
                format!("cannot create: {e}")
            };
            Err(Failure {
                message: format!("{}: {why}", target.path.display()),
                key_written: false,
            })
        }
    }
}

/// Writes `bytes` to `file` and `fsync`s it (ADR-0058 §3 step 8).
fn write_synced(file: &mut File, target: &Target, bytes: &[u8]) -> Result<(), Failure> {
    file.write_all(bytes)
        .and_then(|()| rustix::fs::fsync(&*file).map_err(Into::into))
        .map_err(|e| Failure {
            message: format!("{}: cannot write: {e}", target.path.display()),
            key_written: true,
        })
}

/// Removes exactly the files this run created, through the directory
/// descriptor, and returns the error to print. A file that cannot be
/// removed is its own error, naming the path left behind.
fn remove_created(dir: &OwnedFd, created: &[&Target], failure: Failure) -> String {
    let mut message = failure.message;
    if failure.key_written {
        message.push_str(
            "; part of the private key may have reached the disk: treat that key as never used",
        );
    }
    for target in created {
        if let Err(e) = rustix::fs::unlinkat(dir, target.leaf.as_os_str(), AtFlags::empty()) {
            let _ = write!(
                message,
                "\nerror: cannot remove {} after that failure: {e}; remove it before running keygen again",
                target.path.display()
            );
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A private directory under `target/`. The ancestor rule refuses a
    /// directory below a group- or world-writable one, such as `/tmp` or a
    /// `target/` created under `umask 002`, so the directories this
    /// repository owns on the way lose their group and world write bits,
    /// as the interop script does for `target/`.
    fn tree(name: &str) -> PathBuf {
        let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        let base = target.join("keygen-unit-tests");
        std::fs::create_dir_all(&base).expect("create test base");
        for dir in [&target, &base] {
            let mode = std::fs::metadata(dir).expect("stat").permissions().mode();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & !0o022))
                .expect("chmod");
        }
        let root = base.join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test tree");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        root
    }

    #[test]
    fn split_takes_the_last_component_as_the_file_name() {
        let ok = |p: &str| {
            let (parent, leaf) = split(Path::new(p)).expect(p);
            (parent.display().to_string(), leaf.into_string().unwrap())
        };
        assert_eq!(ok("hk"), (".".into(), "hk".into()));
        assert_eq!(ok("/hk"), ("/".into(), "hk".into()));
        assert_eq!(ok("a/b/hk"), ("a/b".into(), "hk".into()));
        for bad in ["", ".", "..", "a/", "a/.", "a/..", "/"] {
            assert!(split(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    /// RFC-0018 §2: an RNG failure aborts the run, removes both empty
    /// files and says no key was written.
    #[test]
    fn a_failing_rng_leaves_no_file() {
        let dir = tree("rng");
        let err = run(&dir.join("hk"), || Err(RngError)).unwrap_err();
        assert!(err.contains("no key was written"), "{err}");
        assert!(!err.contains("cannot remove"), "{err}");
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
    }
}
