# ADR 0064: Sessions in the launcher: identifiers, PTY allocation, ending and reaping

- **Status:** Accepted
- **Date:** 2026-11-25 (accepted with the implementing PR [#306](https://github.com/gonzafg2/quantumssh/pull/306); drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §2, §3 and §6. It is the second item of RFC-0020 §12: "the session identifier's lifecycle: when the launcher allocates a PTY, when it releases one that was never started, and how it refuses a request for a session it has reaped".
  - Carried by the messages of [ADR-0063](0063-launcher-protocol-seqpacket-socket-pair-ssh-wire-encoding.md). Each session runs the helper of [ADR-0065](0065-session-helper-identity-change-checks-and-environment.md).
  - Moves into the launcher, unchanged, the supervision of [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §6 and §7, and [ADR-0023](0023-phase-1-channel-layer-scope.md)'s kill on early close.
  - Refines ADR-0038 §2's failure table for account mode (§2 below).

## Context

The network server supervises each child today. That code is
`exec.rs`, which implements ADR-0038 §6 and §7.

- **Waiting.** It waits for the leader's exit without reaping it, through
  a pidfd that becomes readable at exit. Where `pidfd_open` fails, it
  peeks with `waitid(EXITED | NOHANG | NOWAIT)` each time `SIGCHLD`
  arrives.
- **Killing.** It kills a pipe session's process group with `SIGKILL`.
  It hangs up a PTY session: `SIGHUP` to the leader, then the group's
  `SIGKILL` after a 1 s grace (`PTY_HANGUP_GRACE`).
- **Signalling safely.** It signals only an unreaped leader, so the
  leader's PID, which is also its process-group ID, cannot have been
  reused.

In account mode the server cannot do any of this. A session runs as
another UID, so the server cannot signal it, and it is the launcher's
child, so the server cannot reap it. RFC-0020 moves supervision to the
launcher and fixes three rules:

- **Identifiers.** The launcher gives each session an identifier that is
  never reused.
- **Signals.** It signals a session's group only while it still holds
  the leader unreaped.
- **Reaped sessions.** It refuses a request for a session it has already
  reaped.

RFC-0020 §2 also puts the `pty-req` fields in the start request. The PTY
is therefore allocated when the session starts. Today it is allocated at
`pty-req`.

## Decision

### 1. The session table

- **What a session holds.** Each live session is one entry: its
  identifier, the leader's `Child` handle and PID, whether it has a PTY,
  and the state of a kill in progress.
- **Identifiers.**
  - They start at 1 and increase by one for each `started`.
  - The launcher never reuses one while it runs. A 64-bit counter cannot
    wrap at any rate of sessions a host can sustain.
  - A restart starts again at 1. The server restarts with the launcher
    (ADR-0066), so no identifier outlives the process that issued it.
- **Bound.** The table holds at most `limits.max_connections` sessions,
  as the launcher read that value at startup (ADR-0028; the default is
  256). A `start` beyond the bound is refused with reason 3.
  - A well-behaved server never reaches the bound. There is one session
    per connection (ADR-0023).
  - The server keeps a connection open until its session's `exited`
    arrives, as it waits for the reap today before `connection.closed`
    (ADR-0038 §6).

### 2. Starting a session

The launcher handles a `start` in one turn of its loop, in this order.
No partly started session survives the turn.

1. **Check the account** (RFC-0020 §3).
   - It must be in the list read at startup. Otherwise the launcher
     refuses with reason 1.
   - It must resolve now in `/etc/passwd` and `/etc/group`, read for this
     session. Both files must pass RFC-0019 §8's check.
   - Its UID must be neither 0 nor the service account's UID, which the
     launcher recorded at startup (ADR-0066 §1). A session with the
     server's UID could signal the server and read its host key.
   - Otherwise the launcher refuses with reason 2.
2. **Check the bound** of §1. Otherwise it refuses with reason 3.
3. **Create the session's descriptors.**
   - **Without a PTY:** three `std::io::pipe()` pairs.
   - **With a PTY:** `pty::allocate`'s sequence (ADR-0038 §4), run as
     root, with the account's UID as the owner. In order:
     1. open `/dev/ptmx`, then `grantpt`;
     2. while the pair is still locked, `chown` the slave to the
        account's UID (the group is unchanged), and `chmod` it to `0600`;
     3. `unlockpt`, then open the slave with `ioctl_tiocgptpeer`;
     4. `fstat` the slave: its owner must be the account's UID and its
        mode `0600`;
     5. apply the modes (`tcsetattr`) and the window size
        (`tcsetwinsize`).

     A failed step refuses with reason 4.

     **Step 2 changes a path, and that path names this pair's slave.**
     The launcher opens exactly `/dev/ptmx`. The kernel serves it from
     the devpts instance mounted at `pts` in the same directory
     (`fs/devpts/inode.c`, `devpts_acquire` and `devpts_ptmx_path`, at
     torvalds/linux `8d7fe9885c62`). That instance is `/dev/pts`, where
     `ptsname`'s `/dev/pts/N` points. Only root could remount `/dev/pts`
     between the two calls.
4. **Start the helper** (ADR-0065), with the session's ends as its stdin,
   stdout and stderr. A failure refuses with reason 5.
5. **Close the launcher's copies of the session's ends** as soon as the
   spawn returns, the builder's copies included. Otherwise the master
   would never see the end of the session (ADR-0038 §5).
6. **Send `started`** with the identifier, the account's UID and the
   server's ends. The launcher then closes its own copies of the server's
   ends.

**A PTY that never started** is released in step 3 or 4 of the same
turn: on a refusal, every descriptor created for the session is closed
before `refused` is sent. No PTY stays allocated between two turns of
the loop. That answers RFC-0020 §12's question about such a PTY.

**What the server does with the PTY fields.**

- The server still answers `pty-req` itself, after its own checks:
  - the bounds and the `TERM` rule of ADR-0038 §2;
  - the modes parse;
  - the PTY permission gate of ADR-0038 §3.
- It then keeps the fields.
- A `window-change` that arrives before the start updates the kept
  size.
- `start` carries the fields to the launcher.

**What the client sees on a refusal.** Every reason gets the answer that
ADR-0038 §2 gives to a child that cannot be spawned. So does a `started`
whose descriptors the server could not all receive (ADR-0063 §4). The client sees exit
status 127. The audit log gets an `exec.started`/`exec.finished` pair,
whose `executing_uid` is the UID from the record the server read at
authentication (RFC-0019 §4), because no session ran.

**This refines ADR-0038 §2 for account mode.** A failed PTY allocation
there is answered at `pty-req` with `SSH_MSG_CHANNEL_FAILURE`. In account
mode it surfaces at `shell` or `exec`, as exit status 127.

### 3. Exit and reaping

- **Watching the leader.** The launcher watches each leader with
  `exec.rs`'s `wait_exit`:
  - first, a pidfd (`rustix::process::pidfd_open`);
  - where that fails, a `waitid` peek with `NOWAIT` each time `SIGCHLD`
    arrives.

  Neither reaps the leader.
- **When the leader exits:**
  1. if a hang-up is in progress (§4), the launcher sends `SIGKILL` to
     the group, while the leader is still unreaped;
  2. it reaps the leader;
  3. it sends `exited` with the status: the exit code, or the signal and
     the core-dumped flag;
  4. it removes the entry.
- **`exited` comes after the reap.** By the time the server reads it,
  the identifier no longer names anything. The server maps the status
  to `exit-status` or `exit-signal` as ADR-0038 §8 does.

### 4. Ending a session (`end`)

- **For a session in the table,** `end` starts ADR-0038 §7's kill
  sequence unchanged:
  - **pipes:** `SIGKILL` to the process group and to the leader;
  - **PTY:** `SIGHUP` to the leader, then `SIGKILL` to the group after
    the 1 s grace. If the leader exits during the grace, the group kill
    happens at once (§3).
- **Only the first `end` starts anything.** A repeated `end` changes
  nothing, as with today's kill request.
- **Every signal goes to an unreaped leader or its group,** so no PID or
  process-group ID can have been reused (RFC-0020 §2).
- **An identifier the launcher does not hold is ignored.** It sends no
  signal and no reply. There are two cases:
  - **It has been reaped.** An `end` the server sent can cross the
    `exited` the launcher sent. That is normal.
  - **It was never issued.** Only a faulty server sends one, and
    ignoring it signals nothing.

  This is how the launcher refuses a request for a session it has
  reaped (RFC-0020 §12).
- **When the server sends `end`:** on every path that kills a child
  today.
  - **ADR-0023's kill on early close:** the channel closes, or the
    client goes away.
  - **ADR-0038 §7's session failure:** a master read or write fails.
  - **The connection task's abort:** ADR-0028's last resort, which today
    runs the synchronous kill guard of `ChildScope`. That guard sends
    `end` without blocking. If the socket cannot take it, the session
    ends when the server exits (§5).

### 5. When the server exits

- **The launcher ends every session in the table at once:** `SIGKILL` to
  each leader and its group, with no hang-up grace. The server's own
  drain (ADR-0028) has already given each session its time.
- **It reaps each one** and sends no `exited`, since the server is gone.
- ADR-0066 §5 covers the rest of the shutdown.

## Consequences

### Positive

- **The kill sequence and the reaping rule do not change.** They move to
  the launcher, and so do the functions that implement them, `wait_exit`
  and the kill.
- **No half-started session.** A session and its PTY exist only once
  `started` has been sent.
- **Signals are safe.** An identifier the server names can reach only a
  leader the launcher still holds unreaped.

### Negative

- **A failed PTY allocation is reported later in account mode.** It is
  exit status 127 at `shell` or `exec`, not a failure at `pty-req`. A
  client that falls back to running without a PTY when `pty-req` fails,
  as OpenSSH's does, does not get that fallback. Such failures need a
  host out of PTYs or a broken `/dev/pts`.
- **An `end` lost from the abort path** leaves its session running until
  the server exits (§4).

### Neutral

- **The launcher's table is bounded by the server's connection limit.**
  Raising `limits.max_connections` raises both.

## Alternatives considered

### Alternative 1: allocate the PTY at `pty-req`

The server would ask the launcher for a PTY at `pty-req`, and start the
session on it later. Rejected:

- It needs a second request and a release message.
- It adds a state in which a PTY is allocated but not started.
- A compromised server could fill that state up to the bound, with
  root-allocated PTYs that no session uses.
- RFC-0020 §2 already puts the PTY fields in the start request.

### Alternative 2: reap on exit, then report

The launcher would reap the leader as soon as it exits. Rejected: once
the leader is reaped, its process-group ID can be reused, and a kill
still in progress would signal an unrelated process as root (RFC-0020
§2).

### Alternative 3: report `exited` before the reap

Rejected. The server could then act on an identifier whose leader is
still a zombie, and the rule "`exited` means gone" would no longer hold.

## Links

- [RFC-0020](../rfcs/0020-privilege-separation-root-launcher-and-session-helper.md) §2, §3, §6, §12.
- [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §2, §4, §5, §6, §7, §8.
- [ADR-0023](0023-phase-1-channel-layer-scope.md), one session channel per connection and the kill on early close.
- [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md), `limits.max_connections` and the abort.
- `crates/quantumssh-core/src/exec.rs`: `wait_exit`, `has_exited`, `kill_group`, `Reaper::begin_kill`.
