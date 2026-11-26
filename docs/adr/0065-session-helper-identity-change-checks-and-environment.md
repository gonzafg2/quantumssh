# ADR 0065: The session helper: the identity change, its checks, and the session's environment

- **Status:** Accepted; §4's keyring bullet is superseded by [ADR-0074](0074-each-account-mode-session-joins-its-own-session-keyring.md), which adds step 5a to §2
- **Date:** 2026-11-25 (accepted with the implementing PRs [#304](https://github.com/gonzafg2/quantumssh/pull/304) and [#306](https://github.com/gonzafg2/quantumssh/pull/306); drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §4 and §5. It is the third item of RFC-0020 §12: "the helper's exact sequence and checks, and the default `PATH`".
  - Started by the launcher as [ADR-0064](0064-sessions-in-the-launcher-identifiers-pty-allocation-ending-and-reaping.md) §2 describes.
  - Extends the re-exec helper of [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §5, and runs the SFTP server of [ADR-0041](0041-sftp-v3-server-in-a-re-exec-helper.md) §2 in-process.
  - Account mode replaces [ADR-0016](0016-phase-1-service-account-uid-model.md)'s environment allowlist and fixed shell (RFC-0020 §10).
  - Constrained by [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md).

## Context

RFC-0020 §4 lists what the helper does, in order:

1. it becomes a session leader, and takes the PTY as its controlling
   terminal when it has one;
2. it sets the supplementary groups, then the GID, then the UID;
3. it checks that the change is permanent;
4. it changes to the account's home directory;
5. it runs the session.

§5 sets the session's environment from the account's record, with a
fixed default `PATH` that this ADR names.

The helper starts as root. It is single-threaded because `main` checks
its reserved argument before anything else, as ADR-0038 §5's helper
does. On Linux the credential calls change the calling thread only,
which here is the whole process. rustix 1.1.6 makes each of them as a
safe function:

| Call | rustix 1.1.6 | Feature |
|---|---|---|
| `setgroups` | `thread::set_thread_groups`, `src/thread/id.rs:192` | `thread` |
| `setresgid` | `thread::set_thread_res_gid`, `:162` | `thread` |
| `setresuid` | `thread::set_thread_res_uid`, `:108` | `thread` |
| `capget` | `thread::capabilities`, `src/thread/libcap.rs:123` | `thread` |
| `getuid`, `geteuid`, `getgid`, `getegid`, `getgroups` | `process`, `src/process/id.rs:33`, `:53`, `:73`, `:93`, `:252` | `process` |

rustix has no `getresuid` or `getresgid`, so the saved IDs cannot be read
directly. The kernel's rules are enough to check them:

- **setresuid(2):** "An unprivileged process may change its real UID,
  effective UID, and saved set-user-ID, each to one of: the current real
  UID, the current effective UID, or the current saved set-user-ID."
- **capabilities(7):** when one of the real, effective or saved UIDs
  was 0 and all of them become nonzero, "all capabilities are cleared
  from the permitted, effective, and ambient capability sets".
- **Unless a securebit says otherwise.** `SECBIT_NO_SETUID_FIXUP` stops
  that adjustment (capabilities(7)).

OpenSSH's `permanently_set_uid` (`uidswap.c`) checks that the old IDs
cannot be restored, and stops with "was able to restore old [e]uid"
when they can.

## Decision

### 1. Entry and arguments

- **Reserved argument.** The first argument is
  `--quantumssh-internal-session`. `main` checks it first: before the
  other helper modes, CLI parsing, configuration, logging or any
  runtime. The mode exists on Linux only.
- **Its arguments, in order:**
  1. the kind: `exec`, `shell` or `sftp`;
  2. `pty` or `pipes`;
  3. the UID, in decimal;
  4. the primary GID, in decimal;
  5. the supplementary groups: decimal GIDs separated by commas. The
     list is never empty, because it always holds the primary GID
     (§2, step 2);
  6. the home directory;
  7. the program to run: the record's login shell, or `/bin/sh` when the
     field is empty, as passwd(5) says ("if empty, use `/bin/sh`");
  8. for `exec` only, the command.
- **Where the arguments come from.** The launcher writes them, from the
  record it read for this session (ADR-0064 §2). The command is the one
  argument that comes from the server, as RFC-0020 §2 allows. `TERM` is
  the one variable that does (§3).
- **A malformed argument list** exits 127, like every other failure (§2).

### 2. The sequence

Each step must succeed before the next one starts. Any failure exits
with status 127 and prints nothing, because stderr may be the user's
terminal (ADR-0038 §5).

1. **Become the session leader, as root.**
   - `rustix::process::setsid()`.
   - With a PTY, also `ioctl_tiocsctty` on stdin, which is the slave.
2. **Set the groups:** `set_thread_groups` with the launcher's list.
   - That list holds every group in `/etc/group` that names the account,
     plus its primary GID.
   - It is sorted and has no duplicates.
   - It is the list initgroups(3) builds: "The additional group group is
     also added to the list."
3. **Set the GID:** `set_thread_res_gid(g, g, g)`.
4. **Set the UID:** `set_thread_res_uid(u, u, u)`.
5. **Check, and exit with 127 if any check fails:**
   - **Real and effective IDs:** `getuid` and `geteuid` return `u`, and
     `getgid` and `getegid` return `g`.
   - **Groups:** `getgroups`, as a set, equals the list of step 2.
   - **Capabilities:** `capabilities(None)` returns empty permitted,
     effective and inheritable sets.
     - The kernel empties the permitted and effective sets at step 4.
       If they are not empty, a securebit or the launcher's environment
       kept them.
     - The inheritable set matters at `execve`, through capabilities(7)'s
       "P'(permitted) = (P(inheritable) & F(inheritable)) | …". So it
       must be empty too.
   - **Root cannot be regained:** `set_thread_res_uid(0, 0, 0)` must
     fail.
     - By setresuid(2)'s rule, it succeeds only when one of the real,
       effective or saved UIDs is still 0, or when the process holds
       `CAP_SETUID`.
     - Its failure therefore proves the saved UID is not 0. That replaces
       reading it back, which rustix cannot do.
     - If the call succeeds, the helper exits at once.
   - **The root group cannot be regained:** when `g` is not 0,
     `set_thread_res_gid(0, 0, 0)` must fail, by the same rule.
     RFC-0019 forbids UID 0 only, so a primary GID of 0 is allowed, and
     then there is nothing to check.

   RFC-0020 §4 says the real, effective and saved IDs "read back as `u`
   and `g`". This step reads back the real and effective IDs. It proves
   the saved IDs by the failed calls, as OpenSSH's `permanently_set_uid`
   does.
6. **Change to the home directory.** `chdir` to the home directory, or to
   `/` if that fails. `HOME` stays the record's value.
7. **Run the session.**
   - **`exec`:** run the program with argv[0] set to its base name, then
     `-c` and the command, through `Command::exec()`. That is OpenSSH's
     `do_child` form.
   - **`shell`:** run the program as a login shell, with argv[0] `-` plus
     its base name.
   - **`sftp`:** run ADR-0041's SFTP server in this process, on stdin and
     stdout, as ADR-0041 §2's helper does. Nothing is executed.

   `Command::exec()` returns only on failure, which exits 127.

### 3. The session's environment

**Who sets it.** The launcher starts the helper with a cleared
environment, then adds exactly these variables. The helper changes
nothing. Every step of §2 runs under this environment, and the program
the helper runs inherits it as it is.

| Variable | Value |
|---|---|
| `HOME`, `USER`, `LOGNAME` | from the record |
| `SHELL` | the program of §1, item 7 |
| `PATH` | `/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin` |
| `TERM` | with a PTY and a non-empty `TERM` only, under ADR-0038 §2's rule |
| `LANG`, `LC_*` | copied from the launcher's own environment, as ADR-0016's allowlist copies them from the server's today |

**The default `PATH`.**

- It is OpenSSH portable's default user `PATH` for a build with the
  default prefix. `configure.ac` starts from
  `/usr/bin:/bin:/usr/sbin:/sbin` and appends `$bindir` "so scp will
  work" (`configure.ac:5426-5446` at `d1b85c672314`).
- With the default prefix, `$bindir` is `/usr/local/bin`. The operator
  guide installs QuantumSSH there too.
- A login shell usually sets its own `PATH` from `/etc/profile`. This
  value matters most for `exec`, which runs the shell with `-c` and no
  login profile.

**From the server,** only `TERM` arrives, bounded and checked, as the
`pty-req` field it is. ADR-0016's rule therefore still holds: no client
`env` request reaches a session (ADR-0023). Today's sessions get no
`SSH_CONNECTION`, `SSH_CLIENT`, `SSH_TTY` or `MAIL`, and neither do
these.

### 4. What the helper does not do

- **It does not set `no_new_privs`.** A session may use `sudo` or other
  set-user-ID programs (RFC-0020 §8).
- **It applies no resource limits.** The unit's limits apply to every
  session (RFC-0020, unresolved question 2).
- **It writes no login records** (question 1), and uses no PAM
  (RFC-0019).
- **It gives the session no kernel session keyring of its own.**
  - **Why every process shares one.** Under systemd, `KeyringMode=`
    defaults to `private` for system services: one session keyring is
    allocated when a service process is invoked (systemd.exec(5)). Every
    process of the unit inherits it: every session of every listed
    account, and the network server. A key that one of them links into
    that keyring is within reach of the others.
  - **How OpenSSH avoids it.** It gives each session a fresh keyring
    through `pam_keyinit`, and account mode has no PAM (RFC-0019).
  - **Why the helper does not create one.** Joining a new session
    keyring takes `keyctl(KEYCTL_JOIN_SESSION_KEYRING)`. rustix 1.1.6
    has no such call, and a crate for it would contradict RFC-0020 §11.
  - ADR-0069 states the residual. Closing it is follow-up work.
- **It does not set a umask.** The launcher's umask applies: 0022 under
  systemd, which is `UMask=`'s default for system units
  (systemd.exec(5)).

### 5. The contract

- **The reserved argument is internal.** It is an internal contract of
  one binary with itself, as ADR-0038 §5's is, and `--help` does not list
  it.
- **Run by hand, it grants nothing.**
  - A caller who is not root fails at step 2 with `EPERM` and exits 127.
  - Root can already do everything the helper does.
- **The network server cannot use it either.** It can execute the
  binary, but it runs as the service account, so step 2 fails.
- **The binary must not be writable by anyone but root,** because every
  session runs its first steps as root. ADR-0066 §1 checks this at
  startup.

### 6. Verification

The implementing PR adds:

- **unit tests** for the argument parser;
- **an integration test that runs as root** in the gate image
  (ADR-0059), in a disposable container: `tests/privsep/`, run by CI's
  `build (ubuntu-latest)`. It starts the helper as a test
  account, and the session reads its own `/proc/self/status`. It checks:
  - all four values of `Uid:` and `Gid:`, and `Groups:`;
  - `CapPrm`, `CapEff` and `CapInh` are zero;
  - `NoNewPrivs` is 0.
- the conformance cases of [ADR-0068](0068-account-mode-conformance-cases-run-as-root-in-the-gate-image.md),
  which cover what a client sees.

## Consequences

### Positive

- **The identity change is checked, not assumed.** It covers the IDs,
  the groups and every capability set, so an operator setting that keeps
  capabilities makes sessions fail rather than run with them.
- **No new crate and no `unsafe`.** The `rustix` pin gains the `thread`
  feature, as RFC-0020 §11 states.
- **The session gets the account's login shell.** An account whose shell
  is `nologin` gets what `nologin` does, and can still use SFTP
  (RFC-0020 §5).

### Negative

- **A session runs its first steps as root.** That is why the binary's
  integrity is now a startup check (ADR-0066 §1).
- **The saved IDs are proved, not read.** A reviewer must follow the
  setresuid(2) rule to see why the check holds.

### Neutral

- **Service-account mode keeps ADR-0016's environment** and ADR-0038
  §5's helper unchanged.

## Alternatives considered

### Alternative 1: read the saved IDs from `/proc/self/status`

The `Uid:` and `Gid:` lines list the real, effective, saved and
filesystem IDs. Rejected. It needs a second parser in a root process,
for a fact that the failed calls of step 5 already prove. It would also
depend on `/proc` being mounted.

### Alternative 2: pass the parameters over a pipe, not as arguments

Rejected. The arguments come from root and need no second encoding.
`ps` shows them only until the helper executes the program. That is as
long as today's `sh -c` already shows a command.

### Alternative 3: take `PATH` from the launcher's environment

The launcher's environment holds systemd's `PATH` for services. Rejected.
Sessions would then depend on the service manager's default. RFC-0020 §5
fixes a default for this ADR to name.

### Alternative 4: leave the primary GID out of the supplementary list

Rejected. initgroups(3) adds it, so the account's groups would differ
from other logins. `id -G` would print a different list.

## Links

- [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §4, §5, §8, §11, §12.
- [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §2, §5; [ADR-0041](0041-sftp-v3-server-in-a-re-exec-helper.md) §2; [ADR-0016](0016-phase-1-service-account-uid-model.md).
- setresuid(2), capabilities(7), passwd(5), initgroups(3): Linux man-pages 6.19. systemd.exec(5), `UMask=`.
- openssh-portable `configure.ac:5426-5446` at `d1b85c672314` (`user_path`); `uidswap.c`, `permanently_set_uid`; `session.c`, `do_child`.
- rustix 1.1.6: `src/thread/id.rs:108`, `:162`, `:192`; `src/thread/libcap.rs:123`; `src/process/id.rs:33`, `:53`, `:73`, `:93`, `:252`.
