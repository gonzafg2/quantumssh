# RFC 0020: Privilege separation — a root launcher, an unprivileged server, and a helper that becomes the account

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-11-23
- **Roadmap issue:** [#248](https://github.com/gonzafg2/quantumssh/issues/248) (Phase 3); tracked in [#43](https://github.com/gonzafg2/quantumssh/issues/43)
- **Implementation PR:** TBD

## Summary

[RFC-0019](0019-identity-model-ssh-user-name-to-os-account.md) decided
which operating-system account a connection logs in to. This RFC decides
how a session comes to run as that account. It is the follow-up RFC that
threat model §8.12 names as its closure condition.

In account mode, QuantumSSH runs as two processes:

- **A launcher, started as root.** It is small and single-threaded, and
  never touches the network. It checks the configuration, then starts
  the network server as the service account. Afterwards it starts each
  session process on the server's request.
- **The network server, which holds no privilege.** It is today's
  server: listener, key exchange, authentication, channels, audit log.
  It runs as the service account, with no supplementary groups, no
  capabilities and `no_new_privs`.

The launcher starts each session through a helper: a fresh,
single-threaded copy of the binary that becomes the account and then
runs the session. Becoming the account takes `setgroups`, `setresgid`
and `setresuid`, then a check that root cannot be regained. The account
runs one of three things:

- `exec`: its login shell, given the command;
- `shell`: its login shell;
- SFTP: the binary's own SFTP server.

No first-party `unsafe` is needed. rustix has safe calls for every step,
and std starts the network server with `Command::uid` and `gid`.

Service-account mode does not change. It stays one process, as
ADR-0016 describes.

## Motivation

### What §8.12 asks for

Threat model §8.12 states that "QuantumSSH executes the authenticated
user's command under the operating system identity of the QuantumSSH
service account". Its closure condition is "Phase 3 privilege-separation
being implemented and a follow-up RFC superseding this entry". §2.5
calls per-user execution "the Phase-3 target".

RFC-0019 settled the first half: the user name names an operator-listed
account, whose record comes from `/etc/passwd` and `/etc/group`. What
remains is how to get from the server to a process running as that
account.

### The constraint every design has to meet

The scoping note
[`docs/plans/phase3-privsep-scoping.md`](../plans/phase3-privsep-scoping.md)
records one finding as settled. QuantumSSH is a multi-threaded Tokio
runtime (ADR-0022) and forbids first-party `unsafe` (ADR-0018).
Together, these "push the privileged→unprivileged transition out of the
async process entirely".

- **Linux changes credentials per thread.** The kernel's `setuid` and
  `setgroups` change only the calling thread. glibc hides that with a
  signal to every thread; the raw calls rustix makes do not. In a live
  Tokio worker pool, a transition from inside the server would leave
  other threads with the old identity.
- **Between `fork` and `exec` there is nowhere to put code.**
  `CommandExt::pre_exec` is `unsafe`, so the server cannot run
  `setgroups` in a child before it executes.
- **std covers only part of it.** `CommandExt::uid` and `gid` are
  stable. `CommandExt::groups` is not: it is nightly-only (rust-lang/rust
  #90747). Without it, std calls `setgroups(0, NULL)` before `setuid`, so
  a session started that way would lose the account's supplementary
  groups.

So the change of identity has to happen in a single-threaded process
that QuantumSSH starts fresh. The binary already has one: the re-exec
helper that ADR-0038 §5 uses to make a PTY session leader, and that
ADR-0041 uses for SFTP.

### What happens without it

Every key in `authorized_keys` stays "operationally equivalent to a key
for the service account" (ADR-0016). Multi-user deployment stays out of
scope, and the README's "not hardened for production" stays true.

## Guide-level explanation

### What an operator does

Account mode is chosen by listing accounts (RFC-0019). With this RFC it
also needs the server to start as root:

- **The unit has no `User=`.** systemd starts `quantumssh` as root, and
  the binary itself starts the network server as the service account
  `quantumssh`.
- **Started as anything but root with `[[account]]` entries, the server
  refuses to start.** It names the reason.
- **Service-account mode keeps today's unit,** with `User=quantumssh`.

The process tree of an account-mode server with two sessions:

```text
quantumssh            root        launcher: no network, single-threaded
├─ quantumssh         quantumssh  the network server
├─ -bash              alice       a shell session
└─ sh -c 'uptime'     deploy      an exec session
```

### What a user sees

- `ssh alice@host id` prints Alice's UID, primary group and
  supplementary groups.
- Her session starts in her home directory, with `HOME`, `USER`,
  `LOGNAME` and `SHELL` set from her account.
- Files she creates, over the shell or over SFTP, are hers.
- `sudo` works as it does on the host. The account-mode unit does not
  set `NoNewPrivileges=`, which would also bind her session (§8).

### What the audit log shows

`exec.started` and `exec.finished` carry the account's UID in
`executing_uid`, and its name in RFC-0019's `account` field. The field
§8.12 made first-class "precisely so this gap is visible" now shows the
gap closed.

## Reference-level explanation

### 1. The two processes

In account mode the binary, started as root, becomes the launcher. It
does these things in order:

1. **It reads and checks the configuration and every file RFC-0019 §8
   names, as root.** These are the configuration, the CA file, the
   account key files, `/etc/passwd` and `/etc/group`. It keeps its own
   copy of the account list.
2. **It binds the listening socket,** so port 22 needs no capability in
   the server.
3. **It creates a Unix socket pair,** the channel to the server.
4. **It starts the network server.** That is `std::process::Command` on
   its own executable, with a reserved argument, `.uid()` and `.gid()`
   of the service account, a cleared environment, and the server's end
   of the socket pair as its stdin.
   - std calls `setgroups(0, NULL)` before `setuid`, so the server has
     no supplementary groups.
   - As root changes every UID to a non-zero one, the kernel clears the
     capability sets.
5. **It passes the listening socket to the server** over the socket
   pair, with `SCM_RIGHTS`.
6. **It serves the server's requests until the server exits,** then
   exits too.

The network server sets `no_new_privs` on itself before it starts any
thread, so every thread inherits it. It then runs as today. The
exception is sessions: it asks the launcher to start each one, instead
of spawning it.

In service-account mode none of this happens. The binary is the server,
as now.

### 2. The launcher's interface

The server and the launcher speak a small binary protocol over the
socket pair.

- **Server to launcher:**
  - *start a session*: the account's name, the kind (`exec` and its
    command, `shell`, or `sftp`), and, for a PTY, the `pty-req` fields:
    the terminal modes blob and the window size;
  - *signal a session*: kill its process group, by the identifier the
    launcher gave it.
- **Launcher to server:**
  - *started*: the session's identifier, the UID it runs under, and the
    server's ends of the session's stdio, attached by `SCM_RIGHTS`;
  - *refused*;
  - *exited*: the exit status, or the signal.

**No descriptor flows from the server to the launcher.** The launcher
creates every descriptor a session uses: the three pipes of a session
without a PTY, or the PTY pair. It keeps the session's ends and passes
the server its own: the pipes' other ends, or the PTY master. It does
the same with the listening socket at startup (§1). So the root
process never runs a privileged call on a descriptor that a
compromised server chose, such as `/dev/ptmx` in place of a slave.

The launcher treats every byte as hostile, because it must hold if the
server is compromised.

- **Bounded.** Every field has a bound, and a malformed message ends
  the launcher's service, which stops the server too.
- **Fuzzed.** It is a parser at a privilege boundary, so it gets a fuzz
  target and seeds in the implementing PR (ADR-0060's rule).
- **No paths from the server.** The launcher accepts no path, no
  program name and no environment variable from it. The command string
  of `exec` is the one exception: it is the user's own request, and
  only the account's shell interprets it.
- **The modes blob goes through the parser the server already uses,**
  `pty::Modes::parse`, which has its own fuzz target (`pty_modes`). It
  is bounded to 1024 bytes, as ADR-0038 §2 bounds it.
- **Session identifiers are never reused.** The launcher signals a
  session's process group only while it still holds the group's leader
  unreaped. It watches for the exit with `WNOWAIT`, as `exec.rs` does
  today. A request for a session whose leader it has already reaped is
  refused. Once a leader is reaped, its process group ID could belong to
  an unrelated process, and root would signal it.

### 3. What the launcher checks, and what it does not

Before it starts a session for account `A`, the launcher checks:

1. `A` is in the list it read at startup.
2. `A` resolves now, in `/etc/passwd` and `/etc/group`, both read for
   this session, with a UID that is not 0. This is the record the
   session runs with, supplementary groups included: an account removed
   from a group loses it on its next session, without a restart.
   RFC-0019 §4's read in the server stays the gate for authentication,
   but it no longer decides the session's identity, because the
   launcher cannot trust it.

It does not check that the connection authenticated as `A`. A
compromised server can therefore ask for a session as any listed
account. It cannot get one with UID 0, as an unlisted account, or
running a program the launcher did not choose. But a session as a
listed account can do whatever that account can, its own ways to
become root included: `sudo`, a group such as `docker` or `disk`, a
set-user-ID program it can reach. Drawbacks and Alternative 3 weigh
this against a launcher that verifies authentication itself.

### 4. The session helper

The launcher starts the helper with `std::process::Command` on its own
executable, with a reserved argument, the session's ends of the
descriptors it created as stdin, stdout and stderr, and a cleared
environment. The helper's `main`
checks the reserved argument before anything else, as ADR-0038 §5's
does, so it is single-threaded throughout.

What the helper does, in order:

1. **Session leader, while still root.** `setsid`, and on a PTY
   `ioctl_tiocsctty` on the slave. The launcher allocated that pair
   itself, as root, before it started the helper, with the sequence
   `pty::allocate` uses today (ADR-0038 §4):
   - open `/dev/ptmx`, then `grantpt`;
   - while the pair is still locked, give the slave to the account and
     set its mode to `0600`;
   - `unlockpt`, then open the slave through `ioctl_tiocgptpeer`;
   - apply the modes and the window size.

   That keeps ADR-0038 §10's Phase-2 mode, which leaves out OpenSSH's
   `tty` group write bit so that `write` and `wall` cannot reach a
   session. ADR-0038 §10 named two ways for Phase 3 to give the slave
   to the user, and this is the first: the privileged side allocates
   the pair and gives the slave away before the drop.
2. **Groups.** `set_thread_groups` to the account's supplementary
   groups, from the launcher's read for this session (§3).
3. **GID.** `set_thread_res_gid(g, g, g)`.
4. **UID.** `set_thread_res_uid(u, u, u)`. Root changing every UID to a
   non-zero one also clears the capability sets.
5. **Check that the change is permanent.** The real, effective and
   saved UIDs and GIDs read back as `u` and `g`. The groups read back
   as set. Setting the UID or GID back to 0 fails. OpenSSH's
   `permanently_set_uid` makes the same check and stops with "was able
   to restore old [e]uid".
6. **Working directory.** `chdir` to the account's home, or to `/` if
   that fails.
7. **Run the session:**
   - `exec` runs the login shell with `-c` and the command;
   - `shell` runs the login shell as a login shell, with argv[0] `-` and
     its name;
   - `sftp` runs the SFTP server in the same process, as ADR-0041's
     helper does.

On any failure the helper exits with 127 and prints nothing, as
ADR-0038 §5's does, because its stderr may be the user's terminal.

Every call above is safe in rustix 1.1:

- `rustix::thread::set_thread_groups`, `set_thread_res_gid` and
  `set_thread_res_uid`, which change the calling thread only, which is
  the whole helper;
- `rustix::process::setsid` and `ioctl_tiocsctty`, which ADR-0038 already
  uses;
- in the launcher, the calls `pty::allocate` already makes:
  `rustix::fs::open`, `rustix::pty::grantpt`, `ptsname`, `unlockpt` and
  `ioctl_tiocgptpeer`, with `rustix::fs::chown` for the owner;
- `std::io::pipe` for the three pipes.

### 5. The session's environment

The helper sets the environment from the account's record, not from the
server:

- `HOME`, `USER`, `LOGNAME` and `SHELL` from the record;
- `PATH`, a fixed default that the implementing ADR names;
- `TERM` on a PTY, from the request, under ADR-0038 §2's rule;
- `LANG` and `LC_*`, from the launcher's own environment, as ADR-0016's
  allowlist does today.

The login shell is the record's. An account whose shell is
`/usr/sbin/nologin` gets what `nologin` does for `exec` and `shell`.
SFTP still works for it, because SFTP runs the binary's server, not the
shell. That answers the shell question RFC-0019 left to this RFC.

### 6. Reaping and signals

- **The launcher waits on every session** and reports its exit to the
  server. The server relays it to the channel as `exit-status` or
  `exit-signal`, as now.
- **Killing a session needs the launcher.** The server cannot signal a
  process of another UID, so it sends a request and the launcher kills
  the session's process group. ADR-0023's kill on an early close works
  that way.
- **The PTY master is the server's,** which relays its bytes and
  applies `window-change` to it as now. The launcher keeps the slave,
  and only the helper gets it.

### 7. Platform

Account mode exists on Linux only (RFC-0019 §4), and so does this design.
`set_thread_groups` and the per-thread credential calls are Linux's.

### 8. The account-mode unit

- **No `User=`,** so systemd starts the launcher as root.
- **No `NoNewPrivileges=`.** It would bind every session, and a real
  account's session may rely on `sudo` or other set-user-ID programs.
  The network server sets `no_new_privs` on itself instead (§1).
- **What that means for the list.** Every way a listed account has to
  become root is within reach of a compromised server (§3). An operator
  should list only accounts whose whole privilege, escalation paths
  included, they accept exposing that way. An operator who wants no
  session to gain privilege can still set `NoNewPrivileges=yes`, at the
  cost of `sudo` in every session.
- **The launcher is the main process** for `Type=notify` and
  `NotifyAccess=main`. How readiness passes from the server to it is
  the implementing ADR's.

ADR-0043's unit stays the service-account-mode unit.

### 9. Proposed threat-model changes

When this RFC is implemented, the implementing PR changes the threat
model:

- **§8.12 is closed for account mode.** It stays as the description of
  service-account mode, which still runs every session as the service
  account.
- **§2.5's "Phase-bounded reality"** names service-account mode, and
  says that account mode runs each session as its account.
- **§4.2 gains the launcher boundary,** between the network server and
  the launcher:
  - what the launcher trusts from the server (nothing);
  - what it checks (§3);
  - what a compromised server can reach: every listed account, never
    UID 0 directly, never an unlisted account, and through a listed
    account whatever that account can reach, root included if it has a
    way there (§8).
- **§3.2.1's and §3.2.4's residuals** say the same about a remote
  compromise of the network server.

### 10. Changes to accepted decisions

- **ADR-0016:** superseded for account mode. Service-account mode keeps
  it.
- **RFC-0002 §8.12:** this RFC is the follow-up that its closure
  condition names, effective when implemented.
- **RFC-0019 §4:** refined. The record a session runs with is the one
  the launcher reads when it starts the session (§3). The server's read
  stays the authentication gate.
- **ADR-0038 §5 and ADR-0041:** their helpers start from the launcher,
  not the server, and the identity change of §4 runs first.
- **ADR-0038 §4 and §10:** in account mode the launcher, not the server,
  allocates the PTY pair. Of the two ways §10 named for Phase 3, this is
  the first. The slave keeps §10's mode `0600`, now owned by the
  account.
- **ADR-0043:** its unit becomes the service-account-mode unit (§8).

### 11. Dependencies

No new crate. The existing `rustix` pin gains the `thread` and `net`
features. They hold the credential calls (§4), `socketpair`, and the
`SCM_RIGHTS` buffers, all as safe functions. That is the same kind of
change ADR-0029 made when it added `fs`.

### 12. What the implementing ADRs decide

- the launcher protocol's encoding and bounds, and its fuzz target;
- the session identifier's lifecycle: when the launcher allocates a
  PTY, when it releases one that was never started, and how it refuses
  a request for a session it has reaped (§2);
- the helper's exact sequence and checks, and the default `PATH`;
- how the launcher starts and stops with the server, and how readiness
  and `SIGTERM` pass between them;
- the account-mode unit;
- the conformance cases (ADR-0062 §8): the session's UID, groups, home
  and shell; file ownership over SFTP; and the refusals of RFC-0019;
- the final text of the threat-model changes (§9).

## Drawbacks

- **A compromised network server reaches every listed account.** It can
  ask the launcher for a session as any of them (§3). It cannot get UID
  0 directly, or an unlisted account. But through a listed account it
  reaches whatever that account can, root included if the account has
  a way there, such as `sudo` (§8). In service-account mode the same
  compromise reaches the service account, which every session already
  runs as. OpenSSH's monitor does better here, because it verifies
  authentication itself (Alternative 3).
- **One server for every connection.** OpenSSH runs each connection's
  pre-authentication code in its own unprivileged process. Here, one
  network server holds every connection, so its compromise reaches all
  of them. That is the same as today.
- **The host key stays in the network server,** as today. A compromise
  exposes it. OpenSSH's monitor holds it instead.
- **A process runs as root.** The launcher's code and its parser are
  now privileged surface, which today has none.
- **More moving parts.** Descriptor passing, a second process to start
  and stop, and exit statuses relayed across processes.
- **No PAM, no utmp.** No `pam_limits`, no `pam_systemd` session, and no
  login records: `last` and `who` do not show QuantumSSH sessions.
  RFC-0019 already ruled out PAM.
- **No `NoNewPrivileges=` for sessions in account mode.** Service-account
  mode keeps it.

## Rationale and alternatives

### Alternative 1: one root process

The server runs as root and spawns the helper itself. Rejected. The
network-facing, multi-threaded process would hold root, so a remote
compromise would be a root compromise. Today it is a service-account
compromise. The launcher exists to keep root out of the process that
reads the network.

### Alternative 2: the server keeps `CAP_SETUID` and `CAP_SETGID`

The server runs as the service account, with only these capabilities.
Rejected. `CAP_SETUID` lets a process become any user, root included,
so it is root in effect. And a capability set held by a non-root
process survives `setuid` unless it is cleared by hand.

### Alternative 3: a launcher that verifies authentication (OpenSSH's monitor)

The server forwards each userauth request and signature, and the
launcher verifies them against the account's keys and the session
identifier before it starts a session. Not chosen for this RFC.

- **It would narrow the compromise.** A compromised server could not
  reach an account whose user does not connect during the compromise.
- **It would move a large parser into the privileged process:** keys,
  certificates, the composite CA signature, and the session state
  needed to reject replayed signatures.
- **It would only hold if the launcher also took part in the key
  exchange,** so that it knows each connection's session identifier.
  That means holding the host key and signing, which is OpenSSH's
  design and most of its size.

It stays the natural next step, and the protocol of §2 leaves room for
it: a start request can carry authentication evidence later.

### Alternative 4: `Command::uid` and `gid` straight from the launcher

The launcher spawns the session with std's stable calls and no helper.
Rejected. `CommandExt::groups` is unstable, so the session would lose
the account's supplementary groups (std calls `setgroups(0, NULL)`). It
would also leave no place for `setsid`, the controlling terminal, or
the check of §4.5.

### Alternative 5: `pre_exec`

Rejected. It is `unsafe`, and ADR-0018 forbids first-party `unsafe`.

### Alternative 6: a resident worker per user

The scoping note's option D. Rejected for now. It adds a population of
long-lived processes and their lifecycle, for a gain in start-up time
that nothing has measured as needed.

### Alternative 7: systemd transient units or PAM sessions

Each session becomes a unit, through D-Bus, or PAM sets up the user.
Rejected. It ties account mode to systemd and D-Bus, or to PAM, which
RFC-0019 rules out.

## Prior art

- **OpenSSH.** `README.privsep`: "sshd-session initially acts as the
  privileged monitor process for a connection before it completes
  authentication", and "sshd-auth is the network-facing process that
  implements the initial key agreement and authentication phase".
  `permanently_set_uid` in `uidswap.c` calls `setresgid`, then
  `setresuid`. It then stops with "was able to restore old [e]gid" or
  "was able to restore old [e]uid" if the old IDs can be restored.
  Read on 2026-11-23 at `openssh-portable` `master`.
- **std** (Rust 1.100.0). `CommandExt::uid` and `gid` are stable, and
  `groups` is unstable (rust-lang/rust#90747). With a UID set and no
  groups, `library/std/src/sys/process/unix/unix.rs` calls `setgid`,
  then `setgroups(0, NULL)`, then `setuid`.
- **rustix 1.1.6.**
  - `thread::set_thread_groups`, `set_thread_res_gid` and
    `set_thread_res_uid` change the calling thread only, with the
    kernel's semantics, as their documentation says.
  - `net::socketpair`, `net::sendmsg` and `net::recvmsg`, with
    `SendAncillaryBuffer` and `RecvAncillaryBuffer`, carry
    `SCM_RIGHTS`. Only `RecvAncillaryBuffer::parse` is `unsafe`, and the
    design does not need it.
- **RFC-0002's "Phase 3 trajectory"** sketched "a privilege-separation
  monitor process" and "`setuid` + `setgid` + `initgroups` invocation
  before `execve`, with the post-condition that `getuid() != 0` is
  asserted". This RFC keeps the identity change and the check. It
  replaces the monitor with a launcher, for the reasons of
  Alternative 3.

## Unresolved questions

1. **Login records.** Should account mode write utmp, wtmp and lastlog?
   Proposed answer: not in this RFC. Writing them is a further root-only
   step with its own formats.
2. **Resource limits.** Should the launcher apply per-account
   `setrlimit`? Proposed answer: no. The unit's limits apply to every
   session, and per-account limits wait for a need.
3. **The launcher's capability bounding set.** systemd could restrict
   it, but sessions inherit the bounding set, which would limit `sudo`
   in them. Proposed answer: the implementing ADR decides, and says
   what it costs sessions.
4. **`permit-pty`.** The launcher cannot see a certificate's
   extensions, so it trusts the server's request for a PTY. Proposed
   answer: accept that. Within a listed account, a compromised server
   can already run anything that account can.

## Future possibilities

- **A launcher that verifies authentication** (Alternative 3).
- **A launcher that holds the host key and signs** the key exchange.
- **One unprivileged network process per connection,** as OpenSSH does.
- **Per-user key files read as the user** (RFC-0019's future
  possibilities), which this design makes possible.
- **Confining the SFTP handlers** (#270). They now run as the account,
  which is the confinement a fuzzer of them would also need, from a
  throwaway account.
