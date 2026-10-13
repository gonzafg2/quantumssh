# ADR 0043: Run under systemd as a `Type=notify` service, with a first-party readiness protocol and a reference unit

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-13)
- **Deciders:** Project lead
- **Related:** The systemd workstream of the Phase-2 milestone ([#109](https://github.com/gonzafg2/quantumssh/issues/109); [`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md), "Likely lane: ADR (operational)"). Consumes, without redefining, the graceful shutdown of [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md), which names "the systemd ADR" as its consumer. Deploys the service-account posture of [ADR-0016](0016-phase-1-service-account-uid-model.md) and writes the operator guidance its Consequences leave open. Picks up the cgroup containment that [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §7 ("What 'no orphan' covers") defers "to the systemd ADR or to Phase 3". Constrained by [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`), [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md) (thin binary), [ADR-0024](0024-phase-1-log-event-schema.md) (logging to stderr) and [RFC-0010](../rfcs/0010-configuration-file.md) (reload is restart-only in Phase 2). Threat model §8.8 (host-level hardening is the operator's).

## Context

`0.1.0` must be "runnable under systemd" (#109, acceptance criteria).
Two questions follow. How does the server tell systemd it has started
and is stopping? And what unit does the project ship?

**Readiness.** A `Type=notify` service sends `READY=1` when startup is
finished, and systemd starts follow-up units only after that
(systemd.service(5), `Type=`). The message is one datagram to the
socket named in `$NOTIFY_SOCKET`. A value starting with `/` is an
`AF_UNIX` path, `@` a Linux abstract-namespace name, and `vsock:` an
`AF_VSOCK` address (sd_notify(3), Notes). systemd documents the
protocol as reimplementable "without external dependencies"
(sd_notify(3), "Standalone Implementations"), and its example states
the protocol "is guaranteed to be stable" (`man/notify-selfcontained-example.py`
at systemd `v262`).

Linking `libsystemd` for this is how the `xz-utils` backdoor reached
`sshd` (CVE-2024-3094, RFC-0001's reference list): distributions
patched `sshd` to call `sd_notify`, which pulled `liblzma` in through
`libsystemd`. OpenSSH's answer was a standalone implementation, "that
does not depend on libsystemd" (openssh-portable commit `08f5792`,
2024-04-03, first released in 9.8p1). At `V_10_6_P1` it is about fifty
lines (`openbsd-compat/port-linux.c:133-188`): path or abstract
addresses only, and an error is logged, not fatal.

**Stopping.** ADR-0028 drains on SIGTERM: accepting stops,
connections in the channel phase run until the drain deadline
(default 30 s, `[server] drain_timeout`, no upper bound), and the
remainder is aborted 2 s later. systemd's default stop path does not
fit that:

- The default `KillMode=control-group` sends SIGTERM to every process
  in the unit at once (systemd.kill(5)). Under QuantumSSH that
  includes every session's processes, so they get the signal at the
  moment the drain starts.
- `TimeoutStopSec=` defaults to `DefaultTimeoutStopSec=`, a build-time
  value that is 90 s upstream (`meson_options.txt`, `default-timeout-sec`,
  at `v262`). A drain configured longer than that is cut by SIGKILL.
  The process dies before it writes `connection.closed` and
  `exec.finished`, which ADR-0028 and ADR-0038 promise on every path.

**The unit.** A unit decides more than how to start a binary. Under
ADR-0016 every session runs as the service account, as a child of the
server. Sessions are therefore processes of the same unit, and every
sandboxing directive in the unit applies to them too.

## Decision

We will implement the readiness protocol in the binary with the
standard library. The server sends `READY=1` once it is listening and
`STOPPING=1` when it starts draining, and the project ships a minimal
reference unit with an operator guide.

### 1. The notification sender

- **Where it lives.** `crates/quantumssh/src/notify.rs`, in the
  binary. systemd is a deployment concern, like the log sink
  (ADR-0024), and the library stays unaware of it (ADR-0017).
- **How it sends.** When `$NOTIFY_SOCKET` is set and non-empty, each
  notification is one `AF_UNIX` `SOCK_DGRAM` datagram, sent with
  `std::os::unix::net::UnixDatagram`. There is no `libsystemd`, no
  crate and no `unsafe`.
- **Addresses.**
  - A `/` value is a path.
  - An `@` value is a Linux abstract name, through
    `std::os::linux::net::SocketAddrExt::from_abstract_name`. It is
    Linux-only, like the namespace itself.
  - Any other value, `vsock:` included, is unsupported: the server
    logs a warning and sends nothing.
- **Failures.** A failed send logs a warning, and the server keeps
  serving, as OpenSSH does. Under `Type=notify` a missing `READY=1`
  still surfaces, because systemd fails the start at
  `TimeoutStartSec=`.
- **Unset variable.** With `$NOTIFY_SOCKET` unset or empty, nothing
  is sent and nothing is logged. Behaviour outside systemd is
  unchanged.
- **Children.** `$NOTIFY_SOCKET` never reaches a channel child. The
  ADR-0016 environment allowlist (`PATH HOME USER SHELL LANG LC_*`)
  already drops it.

### 2. What is sent, and when

- **`READY=1`, once.** It is sent after the listener is bound
  (`server.started`) and after the SIGTERM and SIGINT handlers are
  installed. "Started" then means the port accepts connections and a
  stop request will drain them. A configuration, StrictModes, key or
  bind failure happens before it, so the start fails and
  `systemctl start` reports the failure.
- **`STOPPING=1` and `EXTEND_TIMEOUT_USEC=`, in one datagram.** At the
  first SIGTERM or SIGINT, before the drain begins, the server sends
  `EXTEND_TIMEOUT_USEC=` set to the drain deadline plus 5 s. The 5 s
  covers ADR-0028's 2 s abort grace and the exit.
  - **Order.** systemd processes the state assignments first
    (`src/core/service.c:5516` at `v262`) and the extension after
    (`:5746`), so one datagram is enough.
  - **Effect.** The extension moves the stop timer to at least now
    plus the value and never shortens it (`:436`). A drain longer
    than `TimeoutStopSec=` therefore completes under systemd, and a
    shorter one changes nothing.
- **Nothing else.** The server sends no `WATCHDOG=`, `STATUS=`,
  `RELOADING=`, `MAINPID=` or `FDSTORE=`.

### 3. The reference unit, `contrib/systemd/quantumssh.service`

```ini
[Unit]
Description=QuantumSSH server
Documentation=https://github.com/gonzafg2/quantumssh/blob/main/docs/deployment.md
After=network.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/quantumssh --config /etc/quantumssh/config.toml
User=quantumssh
Group=quantumssh
KillMode=mixed
Restart=on-failure
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

Each directive is here for one reason:

- **`Type=notify`.** The start completes at `READY=1` (§2).
- **`NotifyAccess=main`.** systemd forces this value for `Type=notify`
  when it is unset (systemd.service(5)). It is written out because it
  is load-bearing: sessions are processes of the unit, and with `all`
  any session could send `STOPPING=1`, `MAINPID=` or
  `EXTEND_TIMEOUT_USEC=` and drive the service manager.
- **`User=` and `Group=quantumssh`.** These give ADR-0016's dedicated
  account, never root. `DynamicUser=` is rejected (Alternative 5).
- **`KillMode=mixed`.** SIGTERM goes to the server alone, which runs
  ADR-0028's drain unchanged. When the server exits, systemd sends
  SIGKILL to everything left in the unit's cgroup (systemd.kill(5)).
  What is left are the processes that outlived their channel, such
  as a `nohup` job, or that left its process group, such as a
  `setsid` command. These are the gaps ADR-0038 §7 names, now closed
  at service stop.
- **`Restart=on-failure`.** systemd restarts the server after a crash
  or a failed accept loop, and not after a clean stop. systemd's start
  rate limit ends a restart loop caused by a configuration error.
- **`NoNewPrivileges=yes`.** Neither the server nor any session can
  gain privileges through `execve` (setuid, setgid or file
  capabilities; systemd.exec(5)). ADR-0016's posture needs none: the
  account has no sudoers entry, and nothing it runs is meant to
  elevate. ADR-0016 already names this directive as compatible.
- **No `ExecReload=`.** Reload is restart-only (RFC-0010), so
  `systemctl reload` is refused. `systemctl restart` drains and then
  ends every session, because one process serves every connection.
  There is no hand-over between an old and a new process.
- **No `TimeoutStopSec=`.** The extension in §2 sizes the stop timeout
  from the configured drain.

### 4. What the unit leaves out, and why

- **No capability for port 22.**
  - The unit grants no capability, and the operator guide's example
    configuration listens on port 2222.
  - The recommended way to serve on port 22 is a firewall redirect to
    the configured port (for example nftables `redirect`), which
    keeps the client's source address.
  - `AmbientCapabilities=CAP_NET_BIND_SERVICE` also works, but the
    ambient set survives `execve` of an unprivileged program
    (capabilities(7)). Every session would inherit it, so any
    authorized key could bind privileged ports. The operator guide
    states this cost, and the reference unit does not take it.
  - Socket activation is rejected (Alternative 4).
- **No sandboxing beyond `NoNewPrivileges=`.** `ProtectSystem=`,
  `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`,
  `RestrictAddressFamilies=`, `SystemCallFilter=` and
  `MemoryDenyWriteExecute=` would confine every session along with
  the server. For example:
  - `ProtectHome=` would hide `/home`, `/root` and `/run/user` from
    every session.
  - `ProtectSystem=strict` would make SFTP uploads fail outside
    `ReadWritePaths=`.
  - `RestrictAddressFamilies=` would cut network access from every
    session.

  Choosing these directives means choosing what an authenticated user
  may do, which is Phase-3 confinement ([#43](https://github.com/gonzafg2/quantumssh/issues/43)).
  Until then it is the operator's call, through a drop-in (threat
  model §8.8). The operator guide lists the directives and what each
  one does to sessions.

### 5. Logging

The logging is unchanged. Under systemd, stderr goes to the journal,
and ADR-0024's detection already picks JSON when stderr is not a
terminal. The unit adds no logging directive.

### 6. Operator guide, `docs/deployment.md`

The guide covers:

- **The service account.** It is created with the ADR-0016 posture:
  a system account, the `/usr/sbin/nologin` login shell, and a home
  directory with mode `0750` or stricter.
- **A file layout that StrictModes accepts** (ADR-0029). The
  configuration and `authorized_keys` are not group- or
  world-writable, and neither is any ancestor directory. The host key
  is owned by `quantumssh` with mode `0600`: StrictModes requires root
  or the process UID as owner, and a root-owned `0600` key is
  unreadable by the account.
- **The configuration file** and installing the unit.
- **Port 22**, with the options and costs of §4.
- **Reading the logs** from the journal.
- **Stop and restart behaviour.**
- **The Phase-2 warning** that every authorized key carries the
  account's full authority (threat model §8.12).

### 7. Verification

- **Unit tests** for the sender: datagram content, path addresses,
  unsupported prefixes, and the unset variable.
- **An integration test** that starts the real binary with
  `$NOTIFY_SOCKET` set. It checks that `READY=1` arrives once the
  port accepts, and that SIGTERM produces `STOPPING=1` with the
  extension before a clean exit.
- **A CI step in the existing `build (ubuntu-latest)` job.** The
  runner's own OpenSSH (9.6 on `ubuntu-24.04`) predates the hybrid key
  exchange. The step therefore runs systemd and the client in a
  disposable container (`tests/systemd/`), built from the interop
  gate's pinned Debian image and snapshot (ADR-0034), with systemd as
  PID 1. Inside it, the step installs the server as the operator guide
  describes and checks four things:
  - `systemctl start` leaves the unit active, and a session runs as
    the account;
  - `NoNewPrivs` is set in a session;
  - `systemctl reload` is refused;
  - a stop under `TimeoutStopSec=2`, shorter than a 4 s drain, ends
    with `Result=success` after the drain. The stop runs while a
    session is running and a `setsid` process has escaped. Afterwards
    no process of the account is left, and the journal holds as many
    `exec.finished` records as `exec.started`.

  The required-check set of ADR-0031 does not change.

## Consequences

### Positive

- `systemctl start` reports configuration, key and bind failures as
  start failures, and units ordered after the server start only once
  its port accepts connections.
- ADR-0028's drain runs unchanged under systemd. systemd neither
  signals sessions directly nor kills the server mid-drain, so
  `connection.closed` and `exec.finished` are written on the stop
  path.
- Processes that escaped their channel are killed at service stop.
  This closes the gap ADR-0038 §7 left to this ADR, for the service's
  lifetime.
- There is no new dependency, no FFI and no `unsafe`. The protocol is
  one datagram per message, in a few dozen lines on the standard
  library.
- The operator guidance ADR-0016 left open gets written.

### Negative

- Restarting the service drops every session after the drain. One
  process serves every connection, so there is no OpenSSH-style
  hand-over.
- Port 22 needs a firewall redirect, or a capability that every
  session inherits.
- Within the service's lifetime, an escaped process lives until the
  unit stops. Per-channel containment stays Phase 3.
- The reference unit applies almost no sandboxing. That is
  deliberate, because sandboxing confines sessions too, but an
  operator who expects a hardened unit out of the box gets a short
  one.
- Every log line lands at the journal's default priority, because the
  server writes no `<N>` priority prefixes, so `journalctl -p` cannot
  filter by level. A journald-native sink remains a later binary
  concern (ADR-0024).
- The project maintains its own copy of a small, stable protocol.

### Neutral

- Outside systemd, with no `$NOTIFY_SOCKET`, nothing changes.
- A systemd older than 236 predates `EXTEND_TIMEOUT_USEC=`
  (sd_notify(3)). The stop timeout then falls back to
  `TimeoutStopSec=`.
- `vsock:` notification addresses, used to report a VM guest's
  readiness to its host, are not supported.

## Alternatives considered

### Alternative 1: link `libsystemd` and call `sd_notify(3)`

The FFI needs `unsafe` or a `-sys` crate, which puts a C library on
the trust path. That library pulled `liblzma` into `sshd` in the
`xz-utils` attack. OpenSSH removed exactly this link in 9.8p1.
Rejected.

### Alternative 2: a Rust crate (`sd-notify`, `libsystemd`)

Either crate is a new dependency for a few dozen lines that the
standard library already covers. That conflicts with commitment #4
and with the reuse order of preferring std. Rejected.

### Alternative 3: `Type=exec` or `Type=simple`, no notification

`systemctl start` would succeed before the configuration is read, a
bad key or a taken port would show up later as a crash, and dependent
units would start before the port listens. Without `STOPPING=1` and
the extension, a drain longer than the stop timeout would be cut by
SIGKILL. Rejected.

### Alternative 4: socket activation (`ListenStream=`, `$LISTEN_FDS`)

With socket activation, systemd would bind port 22 for the
unprivileged service, which solves the capability problem. But taking
ownership of an inherited descriptor needs `FromRawFd::from_raw_fd`,
which is `unsafe` and forbidden in first-party code (ADR-0018). A
crate such as `listenfd` would have to do it, on the listener, the
pre-authentication boundary. `Accept=yes` (one process per
connection) would also bypass ADR-0028's admission control. Deferred:
if a privileged port without a redirect becomes a requirement, it
gets its own ADR.

### Alternative 5: `DynamicUser=yes`

In Phase 2 the account is the login identity. Its `authorized_keys`,
its `$HOME` and every file a session creates belong to it. A UID that
can change between restarts breaks that ownership. It also breaks the
host key's: StrictModes accepts only root or the process UID as owner.
`LoadCredential=` could carry the key, but not the home. Rejected.

### Alternative 6: watchdog (`WatchdogSec=`, `WATCHDOG=1`)

A timer task that pings systemd proves that the runtime ticks, not
that the accept loop serves. Deferred until a hang is observed.

### Alternative 7: `KillMode=process`, as OpenSSH's units use

`sshd` forks a process per connection, so sessions survive a restart
of the listener. QuantumSSH serves every connection in one process,
so its sessions end with it anyway. `process` would leave session
leftovers running after stop, outside systemd's lifecycle, which
systemd.kill(5) recommends against. Rejected.

### Alternative 8: `KillMode=control-group` (the default)

systemd would send SIGTERM to every session process at the start of
the drain, so ADR-0028's promise that a session runs until the
deadline would not hold. Rejected.

## Links

- **Implementation:**
  - `crates/quantumssh/src/notify.rs` and `crates/quantumssh/src/main.rs`
    (TBD);
  - `contrib/systemd/quantumssh.service` (TBD);
  - `docs/deployment.md` (TBD).
- **systemd sources, at `v262`:**
  - `man/sd_notify.xml`: Notes, "Standalone Implementations", and the
    `READY=1`, `STOPPING=1` and `EXTEND_TIMEOUT_USEC=` entries;
  - `man/notify-selfcontained-example.py`;
  - `man/systemd.kill.xml` (`KillMode=`);
  - `man/systemd.service.xml` (`Type=notify`, `TimeoutStopSec=`);
  - `man/systemd.exec.xml` (`NoNewPrivileges=`,
    `AmbientCapabilities=`);
  - `src/core/service.c:436`, `:5516` and `:5746`;
  - `meson_options.txt` (`default-timeout-sec`).
- **OpenSSH:**
  - openssh-portable `openbsd-compat/port-linux.c:133-188` at
    `V_10_6_P1`;
  - commit `08f5792` ("notify systemd on listen and reload").
- **Related decisions:**
  - ADR-0016, the service account;
  - ADR-0028, graceful shutdown;
  - ADR-0038 §7, "no orphan";
  - ADR-0024, logging;
  - RFC-0010, restart-only reload;
  - RFC-0001, the `xz-utils` reference.
