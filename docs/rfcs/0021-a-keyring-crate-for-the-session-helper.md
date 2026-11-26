# RFC 0021: A keyring crate for the session helper

- **Status:** Accepted (2026-11-26). The project lead shortened the 14-day comment period on [#311](https://github.com/gonzafg2/quantumssh/pull/311), with the reason stated there (`docs/rfcs/README.md`, step 5).
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-11-26
- **Roadmap issue:** [#248](https://github.com/gonzafg2/quantumssh/issues/248) (Phase 3); tracked in [#299](https://github.com/gonzafg2/quantumssh/issues/299)
- **Implementation PR:** [#312](https://github.com/gonzafg2/quantumssh/pull/312); the implementing ADR is ADR-0074, in [#310](https://github.com/gonzafg2/quantumssh/pull/310)

## Summary

[RFC-0020](0020-privilege-separation-root-launcher-and-session-helper.md)
§11 says of account mode: "No new crate." This RFC makes one exception.
The session helper may use the crate `keyutils-raw` for one purpose: to
give each account-mode session a kernel session keyring of its own. That
closes the residual that threat model §7 records as "One kernel session
keyring for every account-mode session".

The rest of RFC-0020 §11 stands. The exception is for this crate and this
purpose only, and it ends when a crate already in the tree can make the
same call. The call itself, its failure handling and its tests are the
implementing ADR's: ADR-0074, Proposed in
[#310](https://github.com/gonzafg2/quantumssh/pull/310).

## Motivation

**Every account-mode session shares one kernel session keyring.**

- **Why.** systemd gives each system service one session keyring
  (`KeyringMode=private`, the default; systemd.exec(5)). Every process of
  the unit inherits it: the launcher, the network server, and every
  session of every listed account.
- **What that exposes.** Possessing a keyring grants the possessor's
  permissions on what is linked into it. A key that one account's session
  links into `@s` is within reach of another account's sessions, and of
  a compromised network server.
- **A measurement.** In the systemd gate, a session of `qssh-alice`
  added a `user` key to `@s`. A session of `qssh-bob` then found it with
  `KEYCTL_SEARCH`.

**OpenSSH closes this with `pam_keyinit`,** which gives each session a
fresh keyring. Account mode has no PAM (RFC-0019).

**The fix is one system call,** `keyctl(KEYCTL_JOIN_SESSION_KEYRING,
NULL)`, made by the helper once it is the account. No crate already in
the tree offers it:

- **rustix 1.1.6** has no `keyctl`.
- **linux-keyutils 0.2.5** has the opcode only in a private enum, with no
  public call that joins a session keyring.

**First-party code cannot make the call either.** It would need
`unsafe`, and ADR-0018 forbids that.

**Without this RFC, the residual stays.** Operators are told to keep no
secret in an account-mode session's keyring. Nothing enforces that.

## Guide-level explanation

In account mode, each session starts with a session keyring of its own.

- **What a session's `@s` holds.** Keys that the session's processes put
  there.
- **Who else can reach them:**
  - other sessions of the same account, which share its UID, and so the
    UID's permissions on the keyring;
  - no other account's session, and not the network server.

  Root, the launcher included, can reach every key, as it can reach
  everything else. It is outside this model.

**Where keyrings are unavailable,** sessions run as before, with no
keyring of their own:

- **a kernel without keyrings;**
- **a container whose seccomp profile blocks every keyring call,** as
  Docker's default profile does.

An operator changes nothing: no setting, no unit directive, no package.

## Reference-level explanation

### The exception to RFC-0020 §11

- **The crate.** `quantumssh-core` may depend on `keyutils-raw`, as a
  Linux-only dependency.
- **The pin.** `keyutils-raw` is pinned to an exact, reviewed version,
  which the implementing ADR names. A version bump is a reviewed change,
  like any other pin.
- **Its use.** Only the session helper calls it, and only the calls that
  give the session its own keyring. The implementing ADR names them. A
  reviewer checks the confinement by searching the workspace's Rust
  source files for the crate's name: it must occur only in the session
  helper's module.
- **Where the call runs.** After the identity change of ADR-0065 §2, as
  the account, never as root. That rule covers the calls only.
- **Where the code is.** The crate is linked into the one binary, so its
  code is present in every process the binary runs as, the root
  launcher included. The launcher never calls it. This RFC accepts that,
  with the exact pin and `cargo deny` as the controls. At the versions
  of the evidence below, none of the three crates has a build script or
  code that runs at process start. A reviewer checks that against each
  crate's published source: no `build.rs`, and no `#[ctor]`,
  `link_section` or `.init_array`.
- **What it brings.** The crate and its dependencies must pass
  `cargo deny` with the repository's `deny.toml`.

  The evidence at drafting, for `keyutils-raw` 0.4.0, shows the tree
  gaining exactly three crates. The table records that evidence; the
  decision is the policy above, and the implementing ADR keeps the
  versions current:

  | Crate | Version | Licence |
  |---|---|---|
  | `keyutils-raw` | 0.4.0 | BSD-3-Clause |
  | `log` | 0.4.35 | MIT OR Apache-2.0 |
  | `uninit` | 0.3.0 | MIT |

  `errno` and `libc` are already in the tree. The crate makes its calls
  through `libc::syscall(SYS_keyctl, …)`, and links no C library.
- **When the exception ends.** As soon as a crate already in the tree
  offers the call without `unsafe` in first-party code, the dependency is
  removed. That would be `keyctl` in rustix, or a public join in
  linux-keyutils. The removal needs no new RFC.

### What falls back, and what fails

Only an error that means the session cannot reach any keyring either may
let the session go on without one of its own: a kernel without
keyrings, or `keyctl` blocked as a whole. Every other failure, such as
`ENOMEM` or a join denied while other keyring calls still work, fails
the session. The implementing ADR fixes the exact errors and how the
helper tells them apart.

### What the implementing ADR decides

ADR-0074 decides:

- **The call and its place** in ADR-0065 §2's sequence.
- **Failures:**
  - which errors mean keyrings are unavailable to the session too, so it
    goes on;
  - which errors fail the session.
- **Tests:** the gate check that one account's session cannot find or
  read another account's key, and that the service account cannot read
  it either.
- **The documents:** threat model §7, `docs/deployment.md`, and the
  Status notes.

## Drawbacks

- **More third-party `unsafe`.** `keyutils-raw` wraps system calls in
  `unsafe` blocks. That is the audited-dependency layer that ADR-0018
  allows, but it is more of it, and it runs in every session.
- **An old release.** `keyutils-raw` 0.4.0 was released in August 2023.
  It wraps a system call whose ABI does not change. A RustSec
  unmaintained advisory against it would fail `cargo deny`, and then the
  exception's end condition decides what replaces it.
- **Three crates for one call.** `log` and `uninit` come with it.
- **The code is in the root launcher too.** It is linked into the one
  binary, so it is present in the root process, which never calls it
  (see the reference-level explanation).
- **RFC-0020 §11 no longer holds absolutely.** A reader of RFC-0020 has
  to know this RFC exists.

## Rationale and alternatives

- **Wait for rustix or linux-keyutils.** It needs no new crate.
  Rejected for now: the fix would wait on outside releases, and asking
  for the change is outside this repository. It stays as this RFC's end
  condition.
- **`KeyringMode=inherit` in the account-mode unit.** Rejected:
  - the result depends on the keyring PID 1 holds;
  - in containers, runc gives PID 1 a keyring, and `inherit` would share
    it with every session;
  - the gate cannot check a real host's PID 1.
- **Run each session through `keyctl session`,** the keyutils tool.
  Rejected. Every session would depend on a host binary resolved
  through `PATH`, and it changes the argv that ADR-0065 §2 fixes.
- **First-party `unsafe` for one call.** Rejected by ADR-0018, which
  allows no exception.
- **The `keyutils` crate,** the high-level wrapper over `keyutils-raw`.
  Rejected. It adds two more crates, `bitflags` 1 among them, for no
  call that this purpose needs.
- **Not doing this.** The residual stays, enforced only by advice to
  operators.

## Prior art

- **`pam_keyinit`** (Linux-PAM). Each PAM session joins a fresh session
  keyring. OpenSSH sessions get one through it, when PAM is configured
  with it.
- **systemd's `KeyringMode=`** gives each service one keyring, not each
  process the service starts.
- **keyutils' `keyctl session`** joins a fresh keyring, then runs a
  program.

## Unresolved questions

None for this RFC. The implementing ADR settles the call, its failure
handling and its tests.

## Future possibilities

- **Removing the crate** once rustix or linux-keyutils offers the call.
  The exception's end condition makes that a plain dependency change.
- **Linking the account's user keyring `@u` into the new session
  keyring,** as `pam_keyinit` does. Programs that rely on `request_key`
  reaching `@u` through `@s` would then find their keys. The
  implementing ADR records whether the helper does this.
