//! Account records from `/etc/passwd` and `/etc/group` (RFC-0019 §4,
//! ADR-0071), and the account-name rule (ADR-0070 §2).
//!
//! Pure functions over the files' bytes: no I/O, no NSS, no `unsafe`.
//! The callers read the files, after RFC-0019 §8's check, and decide what
//! a record may do: UID 0, for one, is theirs to refuse.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

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
            .any(|member| member == name.as_bytes())
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
        .any(|item| item == name)
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
        for uid in [
            "",
            "+1",
            "-1",
            " 1",
            "1 ",
            "0x10",
            "12345678901",
            "4294967295",
        ] {
            let passwd = format!("alice:x:{uid}:1001::/home/alice:/bin/bash\n");
            assert_eq!(
                lookup(passwd.as_bytes(), b"", "alice"),
                Err(Unresolved::Malformed),
                "uid {uid:?}"
            );
            let passwd = format!("alice:x:1001:{uid}::/home/alice:/bin/bash\n");
            assert_eq!(
                lookup(passwd.as_bytes(), b"", "alice"),
                Err(Unresolved::Malformed),
                "gid {uid:?}"
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
