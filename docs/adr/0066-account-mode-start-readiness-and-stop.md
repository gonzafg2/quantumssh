# ADR 0066: Account-mode start, readiness and stop: the launcher starts the network server, relays readiness, and forwards the stop

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §1 and §8. It is the fourth item of RFC-0020 §12: "how the launcher starts and stops with the server, and how readiness and `SIGTERM` pass between them".
  - Uses the `listener` and `ready` messages of [ADR-0063](0063-launcher-protocol-seqpacket-socket-pair-ssh-wire-encoding.md), and ends sessions as [ADR-0064](0064-sessions-in-the-launcher-identifiers-pty-allocation-ending-and-reaping.md) §5 describes.
  - Keeps the readiness protocol of [ADR-0043](0043-systemd-notify-service-and-reference-unit.md) and the drain of [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md). The unit is [ADR-0067](0067-account-mode-systemd-unit.md).
  - Selects the mode as [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §1 defines it, and runs its §8 checks as root.

## Context

RFC-0020 §1 gives the launcher's steps:

1. check the configuration as root;
2. bind the listening socket;
3. create the socket pair;
4. start the network server as the service account;
5. pass it the listening socket;
6. serve its requests until it exits.

RFC-0020 §8 makes the launcher the unit's main process. Under
`Type=notify` and `NotifyAccess=main`, only the launcher can talk to
systemd. How readiness and the stop pass between the two processes is
left to this ADR.

Today the server does both jobs itself (ADR-0043 §2):

- **`READY=1`** goes out once the listener is bound and the
  `SIGTERM`/`SIGINT` handlers are installed.
- **At the first `SIGTERM` or `SIGINT`**, `STOPPING=1` goes out with
  `EXTEND_TIMEOUT_USEC=` set to the drain deadline plus 5 s.
- **The drain** stops accepting and lets connections run until the
  deadline (ADR-0028). A second signal skips what remains of the drain.

The launcher must wait for three things at once: a signal from systemd,
a message on the socket, and a session's exit. Neither std nor rustix
1.1.6 handles signals without `unsafe`: std has no signal API, and
rustix has no `signalfd` (it lists it in `src/not_implemented.rs`). The
server already receives signals through tokio's signal streams, and
`exec.rs` already waits for exits through tokio.

## Decision

### 1. Which process the binary becomes

After it reads its configuration, the binary picks one of three paths:

| Configuration | Real and effective UID | The binary becomes |
|---|---|---|
| no `[[account]]` | any | the server, in service-account mode, exactly as today |
| `[[account]]` | 0 | the launcher |
| `[[account]]` | not 0 | nothing: it refuses to start, and says account mode needs it to start as root |

**`--require-account-mode`.** The account-mode unit passes this flag
(ADR-0067 §1).

- **With it,** a configuration that lists no account is refused at
  startup, whatever the UID, and the error names the flag.
- **It selects nothing.** `[[account]]` still selects the mode (RFC-0019
  §1), and account mode without the flag works as the table says.
- **Why it exists.** Without it, a service-account configuration under
  the account-mode unit would start as root, and the process that reads
  the network would hold root. That is the outcome RFC-0020's
  Alternative 1 rejects.

**The launcher's startup checks.** It runs them as root, before anything
else. Each failure stops the start.

1. **RFC-0019's configuration rules and its §8 file checks:** the
   configuration file, the CA file, every account key file,
   `/etc/passwd` and `/etc/group`.
2. **The service account.**
   - The account named `quantumssh` must resolve in `/etc/passwd`, with
     a UID and a primary GID that are not 0.
   - The launcher records that UID.
   - No listed account may have that UID, whatever its name. ADR-0064 §2
     repeats the check at every session start, because `/etc/passwd` is
     read again then.
   - Why: a session running as the server's UID could signal the server,
     read the host key it owns (ADR-0067 §4), and read its memory
     wherever the kernel's ptrace policy allows it.
3. **The launcher's own executable.** The path that `/proc/self/exe`
   resolves to must pass RFC-0019 §8's check: owned by root, not group- or
   world-writable, and every ancestor directory owned by root and not
   group- or world-writable. Every session runs its first steps as root
   from this file (ADR-0065 §5), and the launcher re-executes it as root.

**The service account's name is fixed.** It is `quantumssh`, the account
the operator guide already creates (ADR-0043 §6). A configuration key
would change the grammar (RFC-0016), and nothing needs that yet.

### 2. Starting the server

1. **Bind** `server.listen` as root. A port below 1024 then needs no
   capability in the server.
2. **Create the socket pair** of ADR-0063 §1.
3. **Spawn the server** with `std::process::Command` on `/proc/self/exe`:
   - **Arguments:** first `--quantumssh-internal-network-server`, then
     the launcher's own arguments, which came from root's command line.
   - **Identity:** `.uid()` and `.gid()` of the service account.
     - std calls `setgroups(0, NULL)` before `setuid` (RFC-0020's Prior
       art), so the server has no supplementary groups.
     - Changing every UID from 0 to nonzero empties its capability sets
       (capabilities(7)).
   - **Environment:** cleared.
   - **stdin:** the server's end of the socket pair.
   - **stdout and stderr:** inherited, which under systemd is the
     journal.
   - **Process group:** its own, through `process_group(0)`. A Ctrl-C at
     a terminal then reaches the launcher alone, and the launcher
     forwards it once (§4).
4. **Send `listener`** with the listening socket, then close the
   launcher's copy.

**What the server does with the reserved argument:**

1. **`rustix::thread::set_no_new_privs(true)` first,** before any thread
   exists (RFC-0020 §1; rustix 1.1.6, `src/thread/prctl.rs:631`).
2. **It checks its own privileges, and exits with failure if a check
   fails.**
   - Its real and effective UIDs and GIDs are not 0.
   - `getgroups` is empty.
   - `capabilities(None)` returns empty permitted, effective and
     inheritable sets.
   - `set_thread_res_uid(0, 0, 0)` and `set_thread_res_gid(0, 0, 0)`
     both fail. By setresuid(2)'s rule, that proves the saved IDs are
     not 0, as ADR-0065 §2 proves them for the helper.

   The kernel empties the capability sets when every UID leaves 0, but
   a securebit such as `SECBIT_NO_SETUID_FIXUP` stops that
   (capabilities(7)). `no_new_privs` does not clear sets already held.
   The server checks this as ADR-0065 §2 checks the session helper.
3. **It reads `listener` from stdin** before it starts its runtime. That
   descriptor is its listener, and it binds nothing itself.
4. **It reads its configuration and keys** as the service account, with
   the same checks as today. The launcher's checks do not replace them.
5. **It serves as today.** The exception is sessions, which it starts
   and ends through the launcher (ADR-0064).

**Run by hand, the reserved argument grants nothing.** The process runs
as its caller. Its stdin is not the launcher's socket, so reading
`listener` fails or brings no listener, and it exits with failure.

### 3. Readiness

- **The server sends `ready`** where it sends `READY=1` today: the
  listener is in use, `server.started` is logged, and the `SIGTERM` and
  `SIGINT` handlers are installed (ADR-0043 §2).
- **The launcher answers `ready` with `READY=1`,** through the binary's
  existing sender (ADR-0043 §1). It is the main process, so
  `NotifyAccess=main` accepts it.
- **The server never notifies systemd.** `$NOTIFY_SOCKET` is not in its
  environment, and `NotifyAccess=main` would discard its datagrams
  anyway.
- **A failure before `ready` still fails the start.** If the server
  exits before `ready`, the launcher exits with failure (§5). So a bad
  host key, for example, still shows as a failed `systemctl start`.

### 4. Stopping

- **The launcher runs a current-thread tokio runtime.**
  - It runs on the calling thread only.
  - The launcher spawns no blocking task, so the process keeps one
    thread. A test checks that `/proc/<pid>/task` holds one entry.
  - It is the only way, with no `unsafe`, to wait for signals, the
    socket and child exits together (Context).
  - It installs its `SIGTERM` and `SIGINT` streams before it spawns the
    server.
- **The first `SIGTERM` or `SIGINT`:**
  1. The launcher sends `STOPPING=1` with `EXTEND_TIMEOUT_USEC=` set to
     the drain deadline plus 5 s. It computes this from the
     `drain_timeout` it read, as ADR-0043 §2 does.
  2. It sends `SIGTERM` to the server.
- **Each later `SIGTERM` or `SIGINT`:** the launcher sends `SIGTERM` to
  the server again. The server reads that as ADR-0028's second signal:
  drain no longer.
- **Signals reach the server safely.** They go to its PID while the
  launcher holds it unreaped, so the PID cannot have been reused.
- **The server drains as ADR-0028 describes.** Each session that ends on
  the way ends through `end` (ADR-0064 §4). Then the server exits.

### 5. When either process ends

| Event | What follows |
|---|---|
| The server exits before `ready` | The launcher has sent no `READY=1`. It ends every session and exits with 1, whatever the server's status (§3) |
| The server exits after `ready`, for any reason | The launcher ends every session (ADR-0064 §5), then exits: 0 if the server exited with 0, otherwise 1 |
| The launcher reads a zero-length record: an end of file, or an empty record (ADR-0063 §1) | It stops reading and waits for the server's exit, as in the rows above. The exit status comes from the server, never from the read |
| The launcher reads a malformed message (ADR-0063 §3) | It sends `SIGKILL` to the server, with no drain, because the server is faulty or compromised. It then ends every session and exits with 1 |
| The server reads end-of-file from the launcher, or an unexpected descriptor (ADR-0063 §4) | It can no longer start or end sessions, so it exits at once with failure, without draining |

- **The launcher dies.** Under systemd its exit stops the unit, and
  `KillMode=mixed` sends `SIGKILL` to whatever is left in the cgroup
  (ADR-0043 §3, ADR-0067).
- **Outside systemd, its sessions lose their server.** Their pipes and
  PTY master close.
- **A crash restarts both processes.** Exit status 1 makes
  `Restart=on-failure` restart the unit.

### 6. Logging

- **The launcher writes diagnostic records only,** through the server's
  logger and format (ADR-0024, RFC-0014), on the same stderr.
- **Every audit event stays the server's.** The launcher knows no
  connection.
- **The launcher writes no record per session,** though it knows which
  accounts got sessions. It shares the server's stderr, so a compromised
  server could imitate any record the launcher wrote there. An
  independent record would need its own log channel, which this ADR
  does not add. ADR-0069 states the residual: a compromised server can
  falsify the audit records of the sessions it starts.
- **`server.started` comes from the server** and carries
  `identity_mode` `account` (RFC-0019 §6).

### 7. Verification

The implementing PR adds an integration test. It runs as root in the
gate image (ADR-0059), in a disposable container, and starts the
launcher with `$NOTIFY_SOCKET` set. It checks:

- **readiness:** `READY=1` arrives once the port accepts connections;
- **the stop:** `SIGTERM` produces `STOPPING=1` and the extension, the
  drain runs, and the launcher exits with 0, leaving no session process;
- **the launcher:** it has one thread;
- **the server:**
  - its `Uid:` and `Gid:` are the service account's in all four places;
  - `Groups:` is empty;
  - `CapPrm`, `CapEff` and `CapInh` are zero;
  - `NoNewPrivs` is 1.

The systemd gate runs the same checks under the unit of ADR-0067.

## Consequences

### Positive

- **Root never reads the network.** The process that does holds no
  capability, no supplementary group and no way to gain privilege
  through `execve`.
- **The operator sees startup the same way as today.** Failures before
  readiness are start failures, and the drain and its stop timeout work
  as in ADR-0043.
- **A port below 1024 needs no capability grant** in account mode.

### Negative

- **Two processes start and stop together,** and a fault in either
  stops both.
- **The root process runs tokio's reactor and signal handling.** The
  binary already contains them, and the launcher uses no blocking pool.
- **The service account's name is fixed** to `quantumssh`.

### Neutral

- **Service-account mode does not change.**

## Alternatives considered

### Alternative 1: a launcher without tokio, on `poll(2)`

Rejected. `poll` would cover the socket and pidfds, but not signals.
Catching `SIGTERM` without `unsafe` needs a crate such as `signal-hook`,
which would be new. rustix has no `signalfd`.

### Alternative 2: systemd signals the server directly

`KillMode=control-group` would send `SIGTERM` to every process of the
unit. Rejected. Every session would get it at the start of the drain,
which ADR-0043's Context already ruled out.

### Alternative 3: the server inherits the listener at a fixed descriptor number

The launcher would clear `FD_CLOEXEC` on the listener, which rustix can
do safely, and pass the number as an argument. Rejected. The descriptor
would then also leak into any child spawned while the flag is clear.
`SCM_RIGHTS` is the mechanism sessions already use (ADR-0063 §4), so one
mechanism serves both.

### Alternative 4: a configuration key for the service account

Rejected for now. It would change the configuration grammar (RFC-0016)
for a need nobody has stated. It can be added later.

## Links

- [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §1, §8, §12.
- [ADR-0043](0043-systemd-notify-service-and-reference-unit.md) §1, §2, §3, §6; [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md).
- [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §1, §6, §8.
- capabilities(7), Linux man-pages 6.19, "Effect of user ID changes on capabilities".
- rustix 1.1.6: `src/thread/prctl.rs:631`; `src/not_implemented.rs:300` (`signalfd`).
