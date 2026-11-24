//! Account records from `/etc/passwd` and `/etc/group` (RFC-0019 §4,
//! ADR-0071), and the account-name rule (ADR-0070 §2).
//!
//! Pure functions over the files' bytes: no I/O, no NSS, no `unsafe`.
//! The callers read the files, after RFC-0019 §8's check, and decide what
//! a record may do: UID 0, for one, is theirs to refuse.

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The largest `/etc/passwd` or `/etc/group` a caller may read (ADR-0071
/// §1). Over it, the file is unusable: the caller's read fails.
pub const MAX_FILE: usize = 16 * 1024 * 1024;

/// The longest line that can be an entry (ADR-0071 §1).
pub const MAX_LINE: usize = 1024 * 1024;

/// The most groups an account may hold, its primary GID included:
/// Linux's `NGROUPS_MAX` (ADR-0071 §1).
pub const MAX_GROUPS: usize = 65_536;

/// The longest account name (ADR-0070 §2): the user-name bound the
/// server already applies.
pub const MAX_NAME: usize = crate::auth::USER_NAME_BOUND;

/// The shell an empty login-shell field stands for (passwd(5)).
const DEFAULT_SHELL: &str = "/bin/sh";

/// The highest ID a record may carry. `(uid_t)-1`, one above it, means
/// "leave unchanged" to setresuid(2) and setresgid(2) (ADR-0071 §2).
const MAX_ID: u32 = u32::MAX - 1;

/// The files an account's record comes from (RFC-0019 §4).
pub const PASSWD: &str = "/etc/passwd";
/// See [`PASSWD`].
pub const GROUP: &str = "/etc/group";

/// Group- or world-writable bits.
const WRITE_OTHERS: u32 = 0o022;

/// Why a file that grants access to an account cannot be used
/// (RFC-0019 §8). The two kinds map onto ADR-0070 §3's classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileCheck {
    /// The check could not run, or the file could not be read:
    /// `file_unavailable`.
    Unavailable(String),
    /// The check ran and the file fails it: `insecure_permissions`.
    Insecure(String),
}

impl std::fmt::Display for FileCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(d) | Self::Insecure(d) => f.write_str(d),
        }
    }
}

/// RFC-0019 §8's account-mode check of a file that grants access to an
/// account.
///
/// `path` must already be its canonical path, absolute with no symlink in
/// any component. It must be owned by root and not group- or
/// world-writable, and so must every ancestor directory up to `/`.
///
/// Stat-based and best-effort against a race with the read that follows,
/// as ADR-0029's check is. Every directory on the way is root's, so only
/// root could change the file in between.
///
/// # Errors
///
/// [`FileCheck::Unavailable`] when the path cannot be canonicalised or a
/// component cannot be stat'ed; [`FileCheck::Insecure`] naming the path
/// and the predicate it fails.
pub fn check_root_file(path: &Path) -> Result<(), FileCheck> {
    let canon = std::fs::canonicalize(path).map_err(|e| {
        FileCheck::Unavailable(format!("{}: cannot canonicalise: {e}", path.display()))
    })?;
    // Byte for byte: `Path` equality skips `.` components.
    if canon.as_os_str() != path.as_os_str() {
        return Err(FileCheck::Insecure(format!(
            "{}: not a canonical path, resolves to {} (account mode)",
            path.display(),
            canon.display()
        )));
    }
    let st = stat(path)?;
    if st.st_uid != 0 {
        return Err(FileCheck::Insecure(format!(
            "{}: not owned by root (account mode)",
            path.display()
        )));
    }
    if mode_of(&st) & WRITE_OTHERS != 0 {
        return Err(FileCheck::Insecure(format!(
            "{}: group/world-writable (mode {:04o})",
            path.display(),
            mode_of(&st) & 0o7777
        )));
    }
    for dir in path.ancestors().skip(1) {
        let st = stat(dir)?;
        if st.st_uid != 0 {
            return Err(FileCheck::Insecure(format!(
                "{}: ancestor directory {} not owned by root (account mode)",
                path.display(),
                dir.display()
            )));
        }
        if mode_of(&st) & WRITE_OTHERS != 0 {
            return Err(FileCheck::Insecure(format!(
                "{}: group/world-writable ancestor directory (mode {:04o}) at {}",
                path.display(),
                mode_of(&st) & 0o7777,
                dir.display()
            )));
        }
    }
    Ok(())
}

fn stat(path: &Path) -> Result<rustix::fs::Stat, FileCheck> {
    rustix::fs::stat(path)
        .map_err(|e| FileCheck::Unavailable(format!("{}: cannot stat: {e}", path.display())))
}

/// A `stat` mode as `u32`: `st_mode` is `u16` on the libc (macOS)
/// backend and `u32` on `linux_raw`.
#[must_use]
pub fn mode_of(st: &rustix::fs::Stat) -> u32 {
    #[allow(clippy::useless_conversion)]
    u32::from(st.st_mode)
}

/// Checks `path` with [`check_root_file`], then reads it whole, refusing
/// one over [`MAX_FILE`] (ADR-0071 §1).
///
/// # Errors
///
/// The check's [`FileCheck`], or [`FileCheck::Unavailable`] when the read
/// fails or the file is over its bound.
pub fn read_root_file(path: &Path) -> Result<Vec<u8>, FileCheck> {
    check_root_file(path)?;
    let unavailable =
        |e: std::io::Error| FileCheck::Unavailable(format!("{}: cannot read: {e}", path.display()));
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(unavailable)?
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() > MAX_FILE {
        return Err(FileCheck::Unavailable(format!(
            "{}: over its bound of {MAX_FILE} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Why an account could not be resolved from the files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A file failed its check or its read.
    File(FileCheck),
    /// The files hold no usable record for the account.
    Unresolved(Unresolved),
}

/// Resolves `name` from the system's files, [`PASSWD`] and [`GROUP`].
///
/// Both pass RFC-0019 §8's check, are read within ADR-0071 §1's bound,
/// and are looked up as ADR-0071 says. This is the read RFC-0019 §4 and
/// ADR-0064 §2 make, at authentication and at each session start.
///
/// # Errors
///
/// [`ResolveError`].
pub fn resolve(name: &str) -> Result<AccountRecord, ResolveError> {
    resolve_from(Path::new(PASSWD), Path::new(GROUP), name)
}

/// [`resolve`] over the given paths.
fn resolve_from(
    passwd: &Path,
    group: &Path,
    name: &str,
) -> Result<AccountRecord, ResolveError> {
    let passwd = read_root_file(passwd).map_err(ResolveError::File)?;
    let group = read_root_file(group).map_err(ResolveError::File)?;
    lookup(&passwd, &group, name).map_err(ResolveError::Unresolved)
}

/// What a session runs as (RFC-0019 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// The account's name, as listed.
    pub name: String,
    /// The UID, which may be 0: refusing it is the caller's job.
    pub uid: u32,
    /// The primary GID.
    pub gid: u32,
    /// The home directory, an absolute path.
    pub home: PathBuf,
    /// The login shell, an absolute path; `/bin/sh` for an empty field.
    pub shell: PathBuf,
    /// Every group the session gets: the `/etc/group` memberships and the
    /// primary GID, sorted and without duplicates, as initgroups(3)
    /// builds the list (ADR-0065 §2).
    pub groups: Vec<u32>,
}

/// Why a lookup found no usable record (ADR-0070 §4's reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    /// `/etc/passwd` has no line for the name.
    NoEntry,
    /// The account's `/etc/passwd` line, or an `/etc/group` line that
    /// names it, is malformed (ADR-0071 §3).
    Malformed,
    /// The account's groups, primary GID included, exceed [`MAX_GROUPS`].
    TooManyGroups,
}

impl Unresolved {
    /// The `reason` value of ADR-0070 §4's diagnostic record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEntry => "no_passwd_entry",
            Self::Malformed => "malformed_entry",
            Self::TooManyGroups => "too_many_groups",
        }
    }
}

/// ADR-0070 §2: 1 to [`MAX_NAME`] bytes of ASCII letters, digits, `_` and
/// `-`, with an optional final `$`; not starting with `-`; not all digits.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    !body.is_empty()
        && name.len() <= MAX_NAME
        && !body.starts_with('-')
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && !body.bytes().all(|b| b.is_ascii_digit())
}

/// Looks `name` up in the bytes of `/etc/passwd` and `/etc/group`
/// (ADR-0071).
///
/// The first `/etc/passwd` line for the name decides: if it is
/// malformed, the account does not resolve. A malformed `/etc/group` line
/// that names the account fails the lookup too. Every other malformed
/// line is skipped.
///
/// # Errors
///
/// The [`Unresolved`] reason when no usable record exists. A name outside
/// [`valid_name`] has no entry.
pub fn lookup(passwd: &[u8], group: &[u8], name: &str) -> Result<AccountRecord, Unresolved> {
    if !valid_name(name) {
        return Err(Unresolved::NoEntry);
    }
    let line = entries(passwd)
        .find(|line| first_field(line) == name.as_bytes())
        .ok_or(Unresolved::NoEntry)?;
    let (uid, gid, home, shell) = parse_passwd_line(line).ok_or(Unresolved::Malformed)?;
    let mut groups = vec![gid];
    for line in entries(group) {
        if !names(line, name.as_bytes()) {
            continue;
        }
        let (gid, members) = parse_group_line(line).ok_or(Unresolved::Malformed)?;
        if members
            .split(|&b| b == b',')
            .any(|member| list_item(member) == name.as_bytes())
        {
            groups.push(gid);
        }
    }
    groups.sort_unstable();
    groups.dedup();
    if groups.len() > MAX_GROUPS {
        return Err(Unresolved::TooManyGroups);
    }
    Ok(AccountRecord {
        name: name.to_owned(),
        uid,
        gid,
        home,
        shell,
        groups,
    })
}

/// The lines that can be entries (ADR-0071 §2): leading ASCII whitespace
/// is skipped, as glibc's reader does, and so are empty lines and those
/// that then start with `#`, `+` or `-` (comments and NIS entries).
fn entries(file: &[u8]) -> impl Iterator<Item = &[u8]> {
    file.split(|&b| b == b'\n')
        .map(|line| {
            let start = line
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t' | 0x0b | 0x0c | b'\r'))
                .unwrap_or(line.len());
            &line[start..]
        })
        .filter(|line| !matches!(line.first(), None | Some(b'#' | b'+' | b'-')))
}

/// The bytes before the first `:`, or the whole line.
fn first_field(line: &[u8]) -> &[u8] {
    line.split(|&b| b == b':').next().unwrap_or(line)
}

/// Whether `name` is some field of `line`, or some comma-separated item of
/// a field: the test for an `/etc/group` line that could concern the
/// account (ADR-0071 §3).
fn names(line: &[u8], name: &[u8]) -> bool {
    line.split(|&b| b == b':')
        .flat_map(|field| field.split(|&b| b == b','))
        .any(|item| until_nul(list_item(item)) == name)
}

/// The bytes before the first NUL: what a C-string reader such as glibc's
/// sees. A line that names the account only up to a NUL still counts as
/// naming it, so the NUL makes it malformed rather than skipped
/// (ADR-0071 §2, §3).
fn until_nul(item: &[u8]) -> &[u8] {
    item.split(|&b| b == 0).next().unwrap_or(item)
}

/// A comma-separated item without its leading ASCII whitespace, as
/// glibc's `parse_list` reads a group's members ("Skip leading white
/// space", `nss/nss_files/files-parse.c`), so `bob, alice` lists `alice`.
fn list_item(item: &[u8]) -> &[u8] {
    let start = item
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .unwrap_or(item.len());
    &item[start..]
}

/// A line within [`MAX_LINE`], with no NUL byte, split into exactly `n`
/// fields.
fn fields<const N: usize>(line: &[u8]) -> Option<[&[u8]; N]> {
    if line.len() > MAX_LINE || line.contains(&0) {
        return None;
    }
    let mut out = [&line[..0]; N];
    let mut parts = line.split(|&b| b == b':');
    for slot in &mut out {
        *slot = parts.next()?;
    }
    parts.next().is_none().then_some(out)
}

/// `name:password:UID:GID:GECOS:directory:shell` (passwd(5)), under
/// ADR-0071 §2's field rules.
fn parse_passwd_line(line: &[u8]) -> Option<(u32, u32, PathBuf, PathBuf)> {
    let [_, _, uid, gid, _, home, shell] = fields::<7>(line)?;
    let home = absolute(home)?;
    let shell = if shell.is_empty() {
        PathBuf::from(DEFAULT_SHELL)
    } else {
        absolute(shell)?
    };
    Some((id(uid)?, id(gid)?, home, shell))
}

/// `group_name:password:GID:user_list` (group(5)).
fn parse_group_line(line: &[u8]) -> Option<(u32, &[u8])> {
    let [_, _, gid, members] = fields::<4>(line)?;
    Some((id(gid)?, members))
}

/// A decimal ID of 1 to 10 digits, with no sign or space, at most
/// [`MAX_ID`].
fn id(field: &[u8]) -> Option<u32> {
    if field.is_empty() || field.len() > 10 || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = field
        .iter()
        .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0'));
    u32::try_from(value).ok().filter(|&v| v <= MAX_ID)
}

/// A non-empty path that starts with `/`.
fn absolute(field: &[u8]) -> Option<PathBuf> {
    (field.first() == Some(&b'/')).then(|| PathBuf::from(OsStr::from_bytes(field)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
alice:x:1001:1001:Alice:/home/alice:/bin/bash\n\
deploy:x:1002:1002::/srv/deploy:\n";

    const GROUP: &[u8] = b"root:x:0:\n\
alice:x:1001:\n\
team:x:2000:alice,deploy\n\
docker:x:999:alice\n";

    fn ok(passwd: &[u8], group: &[u8], name: &str) -> AccountRecord {
        lookup(passwd, group, name).expect("resolves")
    }

    #[test]
    fn a_well_formed_account_resolves_with_its_groups() {
        let r = ok(PASSWD, GROUP, "alice");
        assert_eq!(r.name, "alice");
        assert_eq!((r.uid, r.gid), (1001, 1001));
        assert_eq!(r.home, PathBuf::from("/home/alice"));
        assert_eq!(r.shell, PathBuf::from("/bin/bash"));
        assert_eq!(r.groups, vec![999, 1001, 2000]);
    }

    #[test]
    fn an_empty_shell_is_bin_sh_and_the_primary_gid_is_a_group() {
        let r = ok(PASSWD, GROUP, "deploy");
        assert_eq!(r.shell, PathBuf::from("/bin/sh"));
        assert_eq!(r.groups, vec![1002, 2000]);
    }

    #[test]
    fn uid_0_resolves_for_the_caller_to_refuse() {
        assert_eq!(ok(PASSWD, GROUP, "root").uid, 0);
    }

    #[test]
    fn a_missing_name_has_no_entry() {
        assert_eq!(lookup(PASSWD, GROUP, "bob"), Err(Unresolved::NoEntry));
    }

    #[test]
    fn the_first_line_for_the_name_decides() {
        let passwd = b"alice:x:1001:1001::/home/alice:/bin/bash\nalice:x:0:0::/root:/bin/sh\n";
        assert_eq!(ok(passwd, b"", "alice").uid, 1001);
    }

    #[test]
    fn a_malformed_first_line_is_not_skipped_for_a_later_one() {
        let passwd =
            b"alice:x:oops:1001::/home/alice:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/sh\n";
        assert_eq!(lookup(passwd, b"", "alice"), Err(Unresolved::Malformed));
    }

    #[test]
    fn malformed_lines_of_other_accounts_are_skipped() {
        let passwd = b"broken line\nbob:x:nope\nalice:x:1001:1001::/home/alice:/bin/bash\n";
        assert_eq!(ok(passwd, b"also:broken\n", "alice").uid, 1001);
    }

    #[test]
    fn field_counts_other_than_seven_are_malformed() {
        for passwd in [
            &b"alice:x:1001:1001:/home/alice:/bin/bash\n"[..],
            b"alice:x:1001:1001::/home/alice:/bin/bash:extra\n",
        ] {
            assert_eq!(lookup(passwd, b"", "alice"), Err(Unresolved::Malformed));
        }
    }

    #[test]
    fn ids_take_digits_only_and_never_the_leave_unchanged_value() {
        for bad in [
            "",
            "+1",
            "-1",
            " 1",
            "1 ",
            "0x10",
            "12345678901",
            "4294967295",
        ] {
            let passwd = format!("alice:x:{bad}:1001::/home/alice:/bin/bash\n");
            assert_eq!(
                lookup(passwd.as_bytes(), b"", "alice"),
                Err(Unresolved::Malformed),
                "{bad:?} in the third field"
            );
            let passwd = format!("alice:x:1001:{bad}::/home/alice:/bin/bash\n");
            assert_eq!(
                lookup(passwd.as_bytes(), b"", "alice"),
                Err(Unresolved::Malformed),
                "{bad:?} in the fourth field"
            );
        }
        let passwd = b"alice:x:4294967294:0000001001::/home/alice:/bin/bash\n";
        let r = ok(passwd, b"", "alice");
        assert_eq!((r.uid, r.gid), (4_294_967_294, 1001));
    }

    #[test]
    fn a_relative_or_empty_home_is_malformed() {
        for home in ["", "home/alice", "tmp"] {
            let passwd = format!("alice:x:1001:1001::{home}:/bin/bash\n");
            assert_eq!(
                lookup(passwd.as_bytes(), b"", "alice"),
                Err(Unresolved::Malformed),
                "home {home:?}"
            );
        }
    }

    #[test]
    fn a_relative_shell_is_malformed() {
        let passwd = b"alice:x:1001:1001::/home/alice:bash\n";
        assert_eq!(lookup(passwd, b"", "alice"), Err(Unresolved::Malformed));
    }

    #[test]
    fn a_nul_byte_or_an_overlong_line_is_malformed() {
        let passwd = b"alice:x:1001:1001::/home/al\0ice:/bin/bash\n";
        assert_eq!(lookup(passwd, b"", "alice"), Err(Unresolved::Malformed));
        let mut long = b"alice:x:1001:1001:".to_vec();
        long.resize(MAX_LINE, b'g');
        long.extend_from_slice(b":/home/alice:/bin/bash\n");
        assert_eq!(lookup(&long, b"", "alice"), Err(Unresolved::Malformed));
    }

    #[test]
    fn comments_nis_entries_and_leading_whitespace() {
        let passwd = b"#alice:x:0:0::/root:/bin/sh\n+alice\n-alice\n\n \t alice:x:1001:1001::/home/alice:/bin/bash\n";
        assert_eq!(ok(passwd, b"", "alice").uid, 1001);
        // A commented-out group line, plain or indented, gives no group.
        let group = b"#wheel:x:10:alice\n\t#wheel:x:10:alice\n+wheel\n";
        assert_eq!(ok(PASSWD, group, "alice").groups, vec![1001]);
    }

    #[test]
    fn a_malformed_group_line_that_names_the_account_fails_the_lookup() {
        for group in [
            &b"wheel:x:ten:alice\n"[..],
            b"wheel:x:10\n:alice",
            b"alice:x:10\n",
            b"wheel:x:10:bob,alice:extra\n",
        ] {
            assert_eq!(
                lookup(PASSWD, group, "alice"),
                Err(Unresolved::Malformed),
                "{:?}",
                String::from_utf8_lossy(group)
            );
        }
    }

    #[test]
    fn a_malformed_group_line_that_does_not_name_the_account_is_skipped() {
        let group = b"wheel:x:ten:bob\nteam:x:2000:alice\n";
        assert_eq!(ok(PASSWD, group, "alice").groups, vec![1001, 2000]);
    }

    #[test]
    fn a_member_after_a_comma_and_whitespace_counts() {
        // glibc skips leading whitespace in a member list; so does the parser.
        let group = b"team:x:2000:bob, alice\nops:x:3000:\talice\n";
        assert_eq!(ok(PASSWD, group, "alice").groups, vec![1001, 2000, 3000]);
        // Trailing whitespace stays part of the item, as in glibc.
        assert_eq!(
            ok(PASSWD, b"team:x:2000:alice \n", "alice").groups,
            vec![1001]
        );
        // A NUL ends the item for a C-string reader: the line names the
        // account, and the NUL makes it malformed.
        assert_eq!(
            lookup(PASSWD, b"wheel:x:10:alice\0carol\n", "alice"),
            Err(Unresolved::Malformed)
        );
        // A malformed line that lists the account after whitespace still
        // fails the lookup.
        assert_eq!(
            lookup(PASSWD, b"wheel:x:ten:bob, alice\n", "alice"),
            Err(Unresolved::Malformed)
        );
    }

    #[test]
    fn a_group_named_like_the_account_is_not_membership() {
        let group = b"alice:x:3000:bob\n";
        assert_eq!(ok(PASSWD, group, "alice").groups, vec![1001]);
    }

    #[test]
    fn the_group_bound_counts_the_primary_gid() {
        let mut group = Vec::new();
        for gid in 0..u32::try_from(MAX_GROUPS).unwrap() {
            if gid != 1001 {
                group.extend_from_slice(format!("g{gid}:x:{gid}:alice\n").as_bytes());
            }
        }
        // MAX_GROUPS - 1 memberships plus the primary GID: at the bound.
        assert_eq!(ok(PASSWD, &group, "alice").groups.len(), MAX_GROUPS);
        group.extend_from_slice(b"extra:x:70000:alice\n");
        assert_eq!(
            lookup(PASSWD, &group, "alice"),
            Err(Unresolved::TooManyGroups)
        );
    }

    /// A directory under the workspace's `target/`: owned by the user
    /// running the tests, so never root's.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/account-tests")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    #[test]
    fn a_file_owned_by_another_user_fails_the_root_check() {
        if rustix::process::geteuid().is_root() {
            return; // Root owns what it creates.
        }
        let file = scratch("owner").join("keys");
        std::fs::write(&file, b"").unwrap();
        let err = check_root_file(&file).unwrap_err();
        assert!(
            matches!(&err, FileCheck::Insecure(d) if d.ends_with("not owned by root (account mode)")),
            "{err}"
        );
    }

    #[test]
    fn a_path_that_is_not_canonical_fails_the_root_check() {
        let dir = scratch("canonical");
        std::fs::write(dir.join("keys"), b"").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(dir.join("keys"), &link).unwrap();
        for path in [
            link,
            dir.join(".").join("keys"),
            PathBuf::from("relative/keys"),
        ] {
            let err = check_root_file(&path).unwrap_err();
            assert!(
                matches!(&err, FileCheck::Insecure(d) if d.contains("not a canonical path"))
                    || matches!(&err, FileCheck::Unavailable(_)),
                "{}: {err}",
                path.display()
            );
        }
        let err = check_root_file(&dir.join("link")).unwrap_err();
        assert!(matches!(err, FileCheck::Insecure(d) if d.contains("not a canonical path")));
    }

    #[test]
    fn a_missing_file_is_unavailable() {
        let err = check_root_file(Path::new("/nonexistent/quantumssh/keys")).unwrap_err();
        assert!(matches!(err, FileCheck::Unavailable(_)), "{err}");
    }

    #[test]
    fn a_root_owned_file_in_root_owned_directories_passes() {
        // Root-owned on Linux and macOS, with root-owned, unwritable
        // ancestors. Canonicalised first: some distributions make
        // /usr/bin/true a symlink, to gnutrue for one.
        let path = std::fs::canonicalize("/usr/bin/true").expect("true exists");
        assert_eq!(check_root_file(&path), Ok(()));
        assert!(read_root_file(&path).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_resolves_from_the_systems_files() {
        let root = resolve("root").expect("root resolves on Linux");
        assert_eq!(root.uid, 0);
        assert!(root.groups.contains(&root.gid));
    }

    #[test]
    fn the_name_rule() {
        for good in ["alice", "a", "svc$", "_x", "a-b", "Alice", "a1"] {
            assert!(valid_name(good), "{good}");
        }
        let too_long = "a".repeat(MAX_NAME + 1);
        for bad in [
            "", "$", "-a", "123", "123$", "a.b", ".", "..", "a b", "a$b", "é", &too_long,
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_name(&"a".repeat(MAX_NAME)));
        // A name outside the rule has no entry, even if a line matches it.
        assert_eq!(
            lookup(b"a.b:x:1:1::/h:/bin/sh\n", b"", "a.b"),
            Err(Unresolved::NoEntry)
        );
    }
}
