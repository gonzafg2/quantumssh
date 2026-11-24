# ADR 0071: The `/etc/passwd` and `/etc/group` parser: bounds, and what a malformed line does

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §4. It is the second item of RFC-0019 §9: "the parser's bounds, and how it treats a malformed line it does not need".
  - Its records feed:
    - the startup checks of [ADR-0070](0070-account-sections-grammar-and-startup-errors.md);
    - the server's read at authentication (RFC-0019 §4);
    - the launcher's read for each session ([ADR-0064](0064-sessions-in-the-launcher-identifiers-pty-allocation-ending-and-reaping.md) §2), which passes the record to the helper of [ADR-0065](0065-session-helper-identity-change-checks-and-environment.md).
  - Constrained by [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (no `unsafe`).

## Context

RFC-0019 §4 decides that account mode reads its accounts from
`/etc/passwd` and `/etc/group`, through the server's own parser, with no
NSS. Every read first passes RFC-0019 §8's check, so both files are
owned by root, with root-owned ancestors and no symlink. The parser is
"bounded in file size, line length and field count, and has no
`unsafe`".

The record holds:

- from `/etc/passwd`: the name, UID, primary GID, home and login shell;
- from `/etc/group`: the supplementary groups, every group that lists the
  name as a member.

"The first entry with the name counts, as with `getpwnam`" (§3).

The formats:

- **passwd(5):** one entry per line, seven colon-separated fields,
  `name:password:UID:GID:GECOS:directory:shell`. "If empty, use
  `/bin/sh`" for the shell.
- **group(5):** four fields, `group_name:password:GID:user_list`. The
  user list is "a list of the usernames that are members of this group,
  separated by commas".

What one libc does with a line it cannot split: musl's `getpwent_a.c`
skips it and goes on to the next line (each `strchr(s, ':')` that fails
is a `continue`).

The values reach privileged calls: `setresuid`, `setresgid`,
`setgroups`, `chdir` and `execve`. One value needs care in particular.
`(uid_t)-1`, 4294967295, means "leave this ID unchanged" to
setresuid(2). A record carrying it must never reach the helper.

## Decision

### 1. What is read, and how much

- **Two fixed paths.** `/etc/passwd` and `/etc/group`, with no
  configuration key to change them.
- **Each read takes the whole file at once,** after RFC-0019 §8's check
  on it.

| Bound | Value | Over the bound |
|---|---|---|
| File size | 16 MiB | the file is unusable: at startup a `file_unavailable` error names it; at authentication and at a session start, the read fails as RFC-0019 §4 and ADR-0064 §2 prescribe |
| Line length | 1 MiB | the line is malformed (§3) |
| Fields per line | exactly 7 in `/etc/passwd`, exactly 4 in `/etc/group` | the line is malformed |
| Groups per account | 65,536, Linux's `NGROUPS_MAX`, counted on the final list that `setgroups` gets: the `/etc/group` memberships plus the primary GID, without duplicates (ADR-0065 §2) | the account does not resolve |

The 1 MiB line bound leaves room for a group that lists every account
of a large host. The file bound leaves room for many such lines.

### 2. Field rules

**`/etc/passwd`:**

- **name:** the line's own bytes, compared byte for byte with the
  account's name. Nothing is normalized.
- **UID and GID:** decimal digits only, at most 10 of them, with no sign
  or space. The value must be at most 4294967294. 4294967295 is
  malformed, because setresuid(2) and setresgid(2) read it as "leave
  unchanged".
- **home:** an absolute path. An empty or relative home is malformed.
  `chdir` would resolve a relative one against the helper's working
  directory, and `HOME` would carry it into the session. A home that
  does not exist is not malformed: `chdir` fails, and the helper falls
  back to `/` (ADR-0065 §2).
- **shell:** empty, or an absolute path. An empty shell becomes
  `/bin/sh`, as passwd(5) says. A relative shell is malformed.
  `execve(2)` itself does not search `PATH`, but `std::process::Command`
  does, as `execvp(3)` does, for a name with no `/`. The shell run would
  then depend on the session's environment.
- **The password and GECOS fields** are not read.

**`/etc/group`:**

- **GID:** the passwd rule above.
- **user list:** split on `,`, with empty items ignored. Each item is
  compared byte for byte with the account's name.
- **The group name and password** are not read.

**Both files:**

- **Leading ASCII whitespace is skipped first:** space, `\t`, `\v`,
  `\f` and `\r`. glibc's reader does the same before it looks for a
  comment (`nss/nss_readline.c:68-70` at `04e750e75b73`). A line that is
  empty after that is skipped.
- **Comment and NIS lines are then skipped, before any other rule.** A
  line whose first byte, after the whitespace, is `#`, `+` or `-` is
  never read as an entry, a membership or a malformed line. In `/etc/group` this matters: a
  commented-out `#wheel:x:10:alice` splits into four valid fields. Read
  as an entry, it would give `alice` the GID 10 that the operator took
  away. There is therefore no NIS either.
- A NUL byte anywhere in a line makes the line malformed.

### 3. Malformed lines

The rule is that a malformed line counts only when it could concern the
account being looked up. Then the lookup fails closed. Otherwise it is
skipped, as musl skips it.

**In `/etc/passwd`:**

- **The account's line** is the first line whose first field, the bytes
  before the first `:`, equals the name.
- **If that line is malformed, the account does not resolve.** The
  parser does not move on to a later line with the same name. That
  would let a later line override the one `getpwnam` reads first.
- **Every other line is ignored,** malformed or not. Comment and NIS
  lines never reach this rule (§2).

**In `/etc/group`:**

- **A well-formed line** makes its GID a supplementary group of every
  name in its user list.
- **A malformed line that names the account fails the lookup.** "Names
  the account" means that the name equals some field, or some
  comma-separated item of a field.
  - Dropping such a line would drop a group. That gives fewer
    privileges, but group permissions can also deny access: a file with
    mode `0604` denies its group what it grants everyone else. A
    dropped group could then grant more than the operator set.
- **A malformed line that does not name the account is ignored.**

**What the caller sees.** A lookup that fails this way, or that finds
more groups than §1 allows, is an account that does not resolve:

- at startup, the diagnostic record of ADR-0070 §4, with the reason
  `malformed_entry` or `too_many_groups`;
- at authentication, a failure as a wrong key, with a diagnostic record
  (RFC-0019 §4);
- at a session start, `refused` with reason 2 (ADR-0064 §2).

### 4. Where it lives, and how it is tested

- **The code.** A module, `account`, in `quantumssh-core`. It is pure,
  so it builds and is tested on every platform the crate builds on.
  Account mode itself stays Linux only (ADR-0070 §3).
- **One pure function, `lookup`,** over the bytes of both files and a
  name. It does no I/O, and allocates only the record it returns.
- **What sits outside it, in the callers:** the reads, their bound of
  §1, and RFC-0019 §8's check.
- **ADR-0070 §2's name rule** lives beside it, as `valid_name`.
- **Unit tests** cover:
  - each bound;
  - each field rule;
  - 4294967295 as UID and as GID;
  - a relative shell;
  - an earlier malformed line with the account's name;
  - a malformed group line that names the account, and one that does
    not;
  - NIS-style lines, and a `#`-prefixed group line that lists the
    account, plain and indented with `\t`, which must not give it that
    GID;
  - a name that appears only as a group name, which is not membership.
- **No fuzz target.** Both files are owned by root, and RFC-0019 §8
  checks that before every read. ADR-0060 §9's rule covers parsers of
  peer-supplied bytes, and a root-owned file is not one.

## Consequences

### Positive

- **What the parser reads is bounded,** and every value that reaches a
  privileged call is checked: no "leave unchanged" ID, and no shell
  looked up in `PATH`.
- **A corrupt line about an account shuts out that account alone.** It
  does not grant anything, and it does not stop the server.
- **It matches what `getpwnam` returns for a well-formed file,** first
  entry included.

### Negative

- **Stricter than libc in three places.** A relative shell, an empty or
  relative home, or a malformed group line that names the account makes
  the account unreachable where `login` would still let it in. The
  startup record says why.
- **No NSS, no NIS, no `nscd`.** RFC-0019's Drawbacks accept this.

### Neutral

- **Service-account mode never reads either file.**

## Alternatives considered

### Alternative 1: skip every malformed line, as musl does

Rejected for the lines that concern the account. A malformed first line
for the name would hand the lookup to a later line, and a dropped group
line could remove a group that denies access. Skipping is kept for every
other line.

### Alternative 2: fail every lookup if any line is malformed

Rejected. One stray line, about an account that is not listed, would
shut out every account.

### Alternative 3: `getpwnam_r` and `getgrouplist` from libc

Rejected by RFC-0019 §4. These calls need `unsafe`, and the static musl
builds would add `nscd` lookups, not directory services.

## Links

- [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §3, §4, §8, §9, Drawbacks.
- passwd(5), group(5), setresuid(2): Linux man-pages 6.19.
- musl `src/passwd/getpwent_a.c` (git.musl-libc.org, read 2026-11-24): a line that cannot be split is skipped.
- glibc `nss/nss_readline.c:68-70` at `04e750e75b73`: leading whitespace, empty lines and `#` lines are skipped.
- [ADR-0060](0060-continuous-fuzzing-cargo-fuzz-on-the-pinned-stable-toolchain.md) §9.
