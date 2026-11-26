# ADR 0074: Each account-mode session joins its own session keyring

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-26)
- **Deciders:** Project lead
- **Related:**
  - Tracked in [#299](https://github.com/gonzafg2/quantumssh/issues/299), which the implementation PR, [#312](https://github.com/gonzafg2/quantumssh/pull/312), closes.
  - Supersedes in part [ADR-0065](0065-session-helper-identity-change-checks-and-environment.md) §4, whose bullet "It gives the session no kernel session keyring of its own" records the gap. It adds a step to ADR-0065 §2's sequence.
  - Implements [RFC-0021](../rfcs/0021-a-keyring-crate-for-the-session-helper.md) (Accepted 2026-11-26), which makes one exception to [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §11's "No new crate" for this crate and this purpose.
  - Narrows the residual that [ADR-0069](0069-threat-model-text-for-account-mode.md) §4 adds to threat model §7, "One kernel session keyring for every account-mode session".

## Context

**Every account-mode session shares one kernel session keyring.**

- **Where it comes from.** systemd's `KeyringMode=` "Defaults to
  `private` for services of the system service manager": one session
  keyring is allocated when the service is invoked (systemd.exec(5)).
- **Who inherits it.** Every process of the unit does: the launcher, the
  network server, and every session of every listed account.
- **What follows.** Possessing a keyring grants the possessor's
  permissions on what is linked into it. A key that one session links
  into `@s` is therefore within reach of every other session, and of the
  network server.

**How OpenSSH avoids it.** `pam_keyinit` gives each session a fresh
keyring, and links the account's user keyring `@u` into it. Account mode
has no PAM (RFC-0019).

**The fix is one system call** in the session helper, after the identity
change: `keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL)`. With a NULL name the
kernel creates an anonymous keyring and installs it as the calling
process's session keyring, in place of the inherited one
(keyctl_join_session_keyring(3)). It is created with the caller's UID,
and only possessors and that UID have permissions on it.

**What can make that call without first-party `unsafe` (ADR-0018):**

| Candidate | Licence | What it offers | Crates it adds |
|---|---|---|---|
| rustix 1.1.6 | Apache-2.0 / MIT | no `keyctl` at all | — |
| linux-keyutils 0.2.5 | Apache-2.0 OR MIT | the opcode in a private enum, and no public call that joins a session keyring | — (it cannot do it) |
| keyutils 0.4.0 | BSD-3-Clause | a high-level wrapper over the next row | five: itself, `bitflags` 1, and the next row's three |
| keyutils-raw 0.4.0 | BSD-3-Clause | `keyctl_join_session_keyring(Option<&str>)`, through `libc::syscall(SYS_keyctl, …)`, with no C library | three: `keyutils-raw`, `log`, `uninit` (`errno` and `libc` are already in the tree) |

These were read from each crate's published source, at the versions
listed.

**Containers block the call.** Docker's documentation lists `add_key`,
`keyctl` and `request_key` among the calls its default seccomp profile
blocks, because keyrings are not namespaced. Measured in the gate image
on arm64:

- without privileges, `keyctl(JOIN_SESSION_KEYRING, NULL)` fails with
  `EPERM`;
- with `--privileged`, it returns a new keyring.

The `openssh-interop` job runs in such a container (ADR-0068).

## Decision

### 1. The helper joins a fresh session keyring

ADR-0065 §2 gains a step between step 5 (the checks) and step 6 (the
home directory):

> **5a. Join a session keyring of its own.**
> `keyutils_raw::keyctl_join_session_keyring(None)`.

- **Why after step 5.** The helper is then the account, so the keyring
  belongs to the account's UID, and counts against its key quota.
- **Who possesses it.** The session's own process tree. The launcher,
  the network server and the sessions of other accounts never join it,
  and have no permission on it, because their UIDs differ.
- **What other sessions of the same account keep.** They share the UID,
  so they keep its permissions on the keyring: view, read and link. They
  could link it by its serial and possess it. That crosses no boundary,
  because processes of one UID can already reach each other, through
  `ptrace` for example.
- **Every kind of session joins:** `exec`, `shell`, on a PTY or on pipes,
  and SFTP, which runs in the helper itself.

### 2. When the call fails

- **`EPERM` or `ENOSYS`: the helper probes, then decides.** `EPERM`
  with a NULL name comes from a seccomp filter or an LSM, as in a
  default Docker container. `ENOSYS` comes from a kernel without
  keyrings, or from a seccomp filter that answers with it. Neither alone
  says whether the inherited keyring is still reachable. The helper
  therefore asks for its session keyring's ID without creating one:
  `keyctl_get_keyring_id(KEY_SPEC_SESSION_KEYRING, false)`.
  - **If the probe also fails with `EPERM` or `ENOSYS`,** `keyctl` is
    unavailable as a whole: no keyrings in the kernel, or a filter on
    every call, as Docker's default profile is. That binds the session's
    processes too, so the helper goes on.
  - **If the probe succeeds,** only the join was denied, for example by
    a filter on that one operation or by an LSM. The inherited keyring
    is reachable, so the session fails.
  - **Any other probe error** also fails the session.
- **Any other error of the join fails the session** with status 127, as
  a failed check of ADR-0065 §2 does. Examples are `EDQUOT`, when the
  account's key quota is full, and `ENOMEM`.
- **No record.** The helper's stderr is already the session's, and no
  step of the sequence writes there.

**Residual:** a filter could deny the join and the probe but allow some
other keyring call: another `keyctl` operation, `add_key` or
`request_key`. A session could then still reach the inherited keyring
through that call. Docker's default profile denies all three system
calls. The threat model's §7 entry is narrowed to this case.

### 3. The dependency

- **The crate:** `keyutils-raw = "=0.4.0"`, a workspace dependency, and
  in `quantumssh-core` a Linux-only target dependency (RFC-0019 §4). It
  is pinned to the release whose source was read, so a bump is a
  reviewed change.
- **Its use:** only the session helper calls it, and only the join and
  the probe of §2.
- **What it adds to the tree:**
  - `keyutils-raw` 0.4.0 (BSD-3-Clause);
  - `log` 0.4.35 (MIT OR Apache-2.0);
  - `uninit` 0.3.0 (MIT).

  All three licences are in `deny.toml`'s list, and RustSec lists no
  advisory for any of them when this ADR was drafted. The implementing
  PR passes `cargo deny`.
- **ponytail: the crate's last release is from August 2023.** It wraps a
  system call whose ABI does not change. The upgrade path is whichever
  lands first: `keyctl` in rustix, or a public join in linux-keyutils.
  The replacement then drops the three crates.

### 4. Tests

- **The systemd gate** (ADR-0067 §5) runs with `--privileged`, so the
  call succeeds there. Its account-mode run gains a check:
  1. A session of `qssh-alice` adds a `user` key to `@s`, and stays
     open.
  2. A session of `qssh-bob` searches its `@s` for that key, and does not
     find it.
  3. Read by its serial, the key cannot be read by `qssh-bob` or by the
     service account. The service account's read runs outside the unit,
     through `setpriv`, so it checks permission only. The network server
     has no possession path either, because it never joins a session's
     keyring.

  The gate image has no `keyctl` tool, so the check makes the system
  calls from `perl`, with the architecture's numbers.
- **A unit test of §2's rule** covers each row as a pure function, the
  fail-closed rows included: a probe that succeeds, a probe with another
  error, and `EDQUOT`. It needs no privileges.
- **A unit test of the helper's call** runs where keyrings are
  available. After the call, the process's `@s` is a new keyring.
- **The conformance case `account_own_keyring`** (ADR-0062 §8) asserts
  both ways, so it never skips on a Linux leg:
  - where sessions can use keyrings, the isolation check above;
  - where `keyctl` is blocked as a whole, as in the unprivileged
    `openssh-interop` container, that the session runs on, and that
    `keyctl` is blocked in another session too.

  The other account cases show that sessions still work there.

### 5. Documents

The implementing PR also changes three documents:

- **ADR-0065** gains a Status note: §4's keyring bullet is superseded by
  ADR-0074, which also adds step 5a to §2.
- **ADR-0069** gains a Status note: the §7 keyring entry of its §4 is
  narrowed by ADR-0074 §2.
- **Threat model §7.** The entry becomes the filter case of §2, and
  `docs/deployment.md`'s keyring paragraph says the same.

## Consequences

### Positive

- **A key linked into a session's `@s` is out of reach** of other
  accounts' sessions and of the network server (§1).
- **No PAM, and no change to the unit.**
- **The fix is one call,** at one place in the sequence ADR-0065 already
  checks.

### Negative

- **Three crates join the tree,** one of them with `unsafe` system calls,
  and its last release is from 2023 (§3).
- **Under a filter that denies the join and the probe but not every
  keyring call,** the shared keyring stays reachable (§2).

### Neutral

- **Service-account mode is unchanged.** Its sessions run as the service
  account, which already owns the keyring they share.
- **The account's user keyring `@u` is not linked in,** unlike under
  `pam_keyinit`. A program that relies on `request_key` reaching `@u`
  through `@s` does not find its key in a session. That keeps `@u`'s
  contents away from anything that possesses the session keyring.
  Linking it is in RFC-0021's "Future possibilities".

## Alternatives considered

### Alternative 1: `KeyringMode=inherit` in the account-mode unit

The sessions would inherit PID 1's session keyring, or none. Rejected.

- **The result depends on PID 1,** not on QuantumSSH.
- **In containers it is worse.** There runc gives PID 1 a keyring, and
  `inherit` would share PID 1's keyring with every session.
- **The gate cannot check a real host's PID 1.**

### Alternative 2: add the call to linux-keyutils first

The crate already defines the opcode. A public join would add only one
crate, because `bitflags` and `libc` are already in the tree. Rejected
for now:

- the fix would wait on an upstream release;
- asking for that change is outside this repository.

§3's upgrade path keeps this option open.

### Alternative 3: run the session through `keyctl session`

keyutils' `keyctl session - <program>` joins an anonymous keyring and
then runs the program. Rejected. It makes every session depend on a
host binary, run as the account through `PATH`, and it changes the
argv that ADR-0065 §2 fixes.

### Alternative 4: fail the session when the call fails with `EPERM`

Rejected. Account mode would then fail in every default Docker
container, the conformance job's among them. §2's probe tells a filter
that blocks `keyctl` as a whole, which binds the session too, from one
that denies only the join.

## Links

- [#299](https://github.com/gonzafg2/quantumssh/issues/299); [RFC-0021](../rfcs/0021-a-keyring-crate-for-the-session-helper.md); [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §11; [ADR-0065](0065-session-helper-identity-change-checks-and-environment.md) §2, §4; [ADR-0067](0067-account-mode-systemd-unit.md) §5; [ADR-0069](0069-threat-model-text-for-account-mode.md) §4.
- keyctl_join_session_keyring(3), keyrings(7), systemd.exec(5) `KeyringMode=`.
- keyutils-raw 0.4.0, `src/functions.rs`: `keyctl_join_session_keyring`.
