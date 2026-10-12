# ADR 0038: Phase 2 interactive sessions — PTY allocation through a safe re-exec helper, and `tokio::process` for every channel child

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-12)
- **Deciders:** Project lead
- **Related:** Extends [ADR-0023](0023-phase-1-channel-layer-scope.md)
  (channel-layer scope) for Phase 2, and answers the `tokio::process`
  question that [ADR-0022](0022-phase-1-async-runtime-tokio.md) §Decision
  deferred to "when PTY support lands in Phase 2". Constrained by
  [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md)
  (`unsafe_code = "forbid"`), [ADR-0016](0016-phase-1-service-account-uid-model.md)
  (service-account UID, sanitised environment, `rustix`),
  [ADR-0024](0024-phase-1-log-event-schema.md) (audit schema; once
  accepted, this ADR partially supersedes the field lists of its
  `exec.started` and `exec.finished` rows, §9), [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md)
  (shutdown drain, blocking-pool sizing) and
  [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md)
  (no configuration key is added here). Part of the Phase-2 milestone
  ([#109](https://github.com/gonzafg2/quantumssh/issues/109)); sequencing
  in [`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md) and the
  Phase-3 constraint in [`docs/plans/phase3-privsep-scoping.md`](../plans/phase3-privsep-scoping.md)
  (both non-authoritative).

## Context

The `0.1.0` MVP includes "an interactive PTY shell" (`README.md:57`).
Issue #109 and the Phase-2 scoping note route it to "an ADR extending
ADR-0023", which "forces the `tokio::process` runtime decision", with
`unsafe`-forbid still binding. What the code does today:

- Only `exec` is honoured. `pty-req`, `shell` and `window-change` get
  `SSH_MSG_CHANNEL_FAILURE` (`crates/quantumssh-core/src/channel.rs:725-742`).
- `exec` spawns `/bin/sh -c <command>` with `std::process::Command` in its
  own process group (`crates/quantumssh-core/src/exec.rs:133-145`). Four
  `spawn_blocking` tasks serve each child: three stdio pumps, and a reap
  that polls `try_wait` every 20 ms (`exec.rs:40`, `exec.rs:155-251`).
- A signal death is reported as `exit-status` 128 + n
  (`exec.rs:271-284`); ADR-0023 deferred `exit-signal` to Phase 2.
- The runtime's blocking pool is sized at 4 × the connection cap because
  of those four tasks (`crates/quantumssh/src/main.rs:41`, `main.rs:420-426`;
  ADR-0028, which says the sizing is "revisited when the PTY ADR
  reconsiders `tokio::process`").

Three forces shape the decision:

1. **The controlling-terminal step has no safe `std` API.** An
   interactive shell must lead its own session, with the PTY slave as
   its controlling terminal: `setsid()` and then `ioctl(TIOCSCTTY)`, in
   the child, before `execve`. `std` exposes that window only through
   `CommandExt::pre_exec`, which is an `unsafe fn` (std 1.99.0,
   `library/std/src/os/unix/process.rs:110`). Tokio's wrapper is also
   `pub unsafe fn pre_exec` (tokio 1.51.4, `src/process/mod.rs:749`).
   `CommandExt::setsid` is still unstable (`process_setsid`,
   rust-lang/rust#105376; `process.rs:219-220`), and `setsid` alone
   does not set a controlling terminal. ADR-0018 forbids the `unsafe`
   block, with no override.
2. **The PTY master must be closable by the session that owns it.**
   Interactive sessions last hours. Processes in the session can keep
   the slave open after the shell exits. A master read parked on a
   blocking-pool thread cannot be cancelled by the channel, so the
   thread and the descriptor stay held until every slave holder exits.
   The 20 ms polling reap is cheap for a short `exec`, but it wakes 50
   times a second for as long as an interactive session lives.
3. **Phase 3 depends on this design.** The privsep scoping note lists
   "the PTY ownership model" as a gating input. It also concludes that
   the identity change must happen in an isolated, single-threaded
   context, never inside the Tokio process.

These are recorded as one decision. Force 2 makes `tokio::process` the
runtime of the PTY child. Keeping pipe children on the old model would
then duplicate the same invariants in a second lifecycle (Alternative
6). The audit fields are how the new sessions appear in the log.
Implementation can still land in more than one PR (§11). That is a
matter of sequencing, not a second decision.

**Verification (2026-10-11).** A throwaway probe, not committed, was
built with `#![forbid(unsafe_code)]` against the pinned versions
(`rustix` 1.1.5, `tokio` 1.51.4). It ran as a non-root UID on macOS
and in a Debian bookworm container. The mechanism below:

- allocated the pair;
- applied a terminal mode and a window size, both seen by `stty` inside
  the session;
- made the shell a session leader with the slave as its controlling
  terminal (`/dev/tty` opened);
- passed `TERM`;
- reported a `SIGTERM` death and an `exit 3`;
- saw end-of-session on the master as `EIO` on Linux and as a 0-byte
  read on macOS.

On both systems:

- the new slave belonged to the opening UID, group `tty`, mode `0620`
  (the mount's settings). A `chmod` to `0600` while the pair was still
  locked succeeded, and the opened slave showed `0600` (§4);
- opening `/dev/ptmx` directly set `FD_CLOEXEC` atomically (§4);
- a `waitid(EXITED | NOHANG | NOWAIT)` peek saw a child's exit while
  tokio's `Child::id()` was still `Some`, and the child was reaped
  afterwards (§7).

With the features below enabled on the workspace,
`cargo check --locked --workspace` passed and `Cargo.lock` did not
change.

## Decision

We will honour `pty-req`, `shell` and `window-change` on the session
channel, and emit `exit-signal`. The pseudo-terminal is allocated with
`rustix`'s safe `pty` and `termios` functions. The child becomes a
session leader with the slave as its controlling terminal inside a
helper mode of the `quantumssh` binary, which the server re-executes, so
no `pre_exec` is needed. Every child of the channel layer is spawned
through `tokio::process`, and the PTY master is driven through
`tokio::io::unix::AsyncFd`.

### 1. Channel requests

ADR-0023's structural bounds stand: one `session` channel per
connection, one child per channel. Within that channel:

| Request | Direction | Phase 2 behaviour |
|---|---|---|
| `pty-req` | C→S | Honoured once, before the child starts (state `Idle`). Allocates the pair (§4). Refused once a child exists or a PTY is already allocated. |
| `shell` | C→S | Honoured once, in `Idle`, and exclusive with `exec`. Starts `/bin/sh` as a login shell (argv[0] `-sh`): on the PTY if one is allocated, otherwise on pipes, like `exec`. |
| `exec` | C→S | Unchanged (ADR-0023), except that after a `pty-req` it runs `/bin/sh -c <command>` on the PTY. This is what `ssh -t host cmd` sends. |
| `window-change` | C→S | Applied to the master while a PTY is allocated (§2). Refused when none is. |
| `exit-status`, `exit-signal` | S→C | See §8. |

Every request follows RFC 4254 §5.4's reply rule: `SSH_MSG_CHANNEL_SUCCESS`
or `SSH_MSG_CHANNEL_FAILURE` only when `want_reply` is set.

Still refused, with `SSH_MSG_CHANNEL_FAILURE` when `want_reply` is set:

- `env`: its policy belongs to `[session].accept_env` (ADR-0029);
- `subsystem`: SFTP is its own workstream;
- `x11-req` and `auth-agent-req@openssh.com`: explicit opt-ins
  (`README.md:57`, threat model §5.4.1), outside Phase-2 scope;
- `signal`, `break`, and any request type the server does not know.

The shell stays fixed at `/bin/sh`, for ADR-0023's M5 reason: the
service account's login shell is `/usr/sbin/nologin` (ADR-0016). A
`shell` request gets the login-shell convention clients expect, so
`/etc/profile` and then the service account's `~/.profile` run. No
configuration key selects another shell in this ADR.

PTYs are available by default, subject to §3. They are part of the
`0.1.0` MVP (`README.md:57`) and of threat model §6.2's MVP target ("PTY
and SFTP (Phase 2)"), not of what §6.2 makes "opt-in behind a feature
flag". §5.4 marks only agent forwarding (§5.4.1) and port forwarding
(§5.4.2) as off by default. ADR-0023's Context groups PTY with them,
but §5.4.3 carries no such rule.

### 2. Parsing and bounds

The peer is authenticated but untrusted (threat model §5.4). Every length
it controls has an explicit bound:

- **`pty-req` fields** (RFC 4254 §6.2): the `TERM` string, at most 64
  bytes; four `uint32` dimensions; the encoded modes string, at most
  1024 bytes.
- **`TERM`.** An empty value means no `TERM` in the child's environment.
  Otherwise it must match `[A-Za-z0-9._+-]+`: no `/`, whitespace or
  control bytes. Real names are short (`xterm-256color`,
  `screen.xterm-256color`). The longest of the 2,684 entries in macOS's
  bundled terminfo database is 23 bytes.
- **Dimensions.** Zero means "not specified", so that field keeps its
  current value (RFC 4254 §6.2: "Zero dimension parameters MUST be
  ignored"). A nonzero value is clamped to 65535, because `Winsize`
  fields are `u16` (rustix 1.1.5, `src/termios/types.rs:1436-1444`).
  `window-change` (§6.7) uses the same rule.
- **Encoded terminal modes** (RFC 4254 §8). A pure function parses the
  borrowed slice, with no allocation:
  - The opcode is one byte. 0 (`TTY_OP_END`) ends the stream.
    Opcodes 1–159 carry a `uint32`. Opcodes 160–255 stop parsing, as the
    RFC specifies. Reaching the end of the blob also ends it: an empty
    string carries no modes, and libssh2's `libssh2_channel_request_pty`
    passes none (`NULL, 0`).
  - The only malformed case is a truncated argument.
  - If an opcode repeats, the last value wins.
  - **Honoured:** each opcode whose termios field exists on the target
    platform in rustix's `termios` types. That covers special characters
    1–18 (255 means disabled, `_POSIX_VDISABLE`; a value above 255 is
    ignored), input flags 30–42 (including `IUTF8`, RFC 8160), local
    flags 50–62, output flags 70–75 and control flags 90–93. For flags,
    0 clears and nonzero sets.
  - **The exception is `CS7` (90) and `CS8` (91).** They are not
    independent flags but values of the multi-bit `CSIZE` field (POSIX
    `<termios.h>`). Setting or clearing them bit by bit can leave `CS8`
    when `CS7` was requested, or fall through to `CS5`. So after
    parsing:
    - if `CS8` is nonzero, `CSIZE` is cleared and set to `CS8`;
    - otherwise, if `CS7` is nonzero, it is set to `CS7`;
    - otherwise `CSIZE` keeps the pair's default.

    A zero value never selects a size, so no client can drive `CSIZE`
    to `CS5` or `CS6`. `PARENB` (92) and `PARODD` (93) use the
    flag rule above.
  - **Ignored:**
    - platform gaps (for example `IUCLC`/`XCASE` exist only on Linux,
      `VDSUSP`/`VSTATUS` only on BSD and macOS, and `OLCUC` not on macOS);
    - the speeds 128/129, which mean nothing on a pseudo-terminal;
    - every opcode the server does not know ("the server MAY ignore any
      modes it does not know about").
  - The result is applied with one `tcsetattr` on the slave before the
    child starts, starting from the pair's defaults (`tcgetattr`), which
    is what sshd does.

**Errors fail closed, and at the narrowest scope that is correct:**

| Failure | Response |
|---|---|
| A field fails to parse, exceeds its byte bound, or a mode argument is truncated | `SSH_DISCONNECT_PROTOCOL_ERROR`, as every existing channel-request parser does (`channel.rs:715-731`) |
| `pty-req` in the wrong state, a second `pty-req`, a refused `TERM`, a PTY denied by §3, or no helper executable configured (§5) | `SSH_MSG_CHANNEL_FAILURE`; no PTY state is created |
| Opening `/dev/ptmx`, `grantpt`, the slave owner check, `chmod`, `unlockpt`, the slave open or its `fstat` check, `tcsetattr` or `tcsetwinsize` fails | `SSH_MSG_CHANNEL_FAILURE`; every descriptor of the half-built pair is closed and the channel stays `Idle`. OpenSSH's client then reports the failure and continues without a PTY |
| The child cannot be spawned, or the helper cannot `exec` | As ADR-0023: an `exec.started`/`exec.finished` pair with exit status 127 |
| A `window-change` ioctl fails | Failure reply only if `want_reply` is set; the session continues |
| A master read or write fails with anything other than would-block or end-of-session | The session ends through §7's teardown |

### 3. PTY permission

One gate decides whether a `pty-req` may proceed. In this ADR it refuses
a PTY when the authorizing `authorized_keys` line carries an options
field. Today the options field is skipped unread
(`crates/quantumssh-core/src/auth.rs:14`, `auth.rs:166-167`,
`auth.rs:198-203`). Skipping `no-pty` or `restrict` was harmless while no
PTY could be allocated. Once PTYs exist, skipping them would silently
grant what the operator denied. Refusing every key with options is too
broad on purpose (a `from=`-only key loses its PTY), but it never
grants a denied PTY. It also gives operators a per-key off switch
today: `no-pty` works, as any option would. The per-key restriction work
(threat model §6.3) and the certificate implementation of RFC-0008
(where OpenSSH's input is the `permit-pty` extension) feed this same
gate. Their mappings are their own decisions.

### 4. Allocation (`rustix` 1.1.5, features `pty` and `termios`)

All of the following are safe `pub fn`s; their `unsafe` stays inside the
dependency, where ADR-0018 places it. In rustix 1.1.5, `ptsname`,
`unlockpt`, `grantpt` and `ioctl_tiocgptpeer` are at `src/pty.rs:135`,
`:150`, `:171` and `:196`.

1. **Master.** `rustix::fs::open("/dev/ptmx", RDWR | NOCTTY | CLOEXEC)`
   on both CI platforms, Linux and macOS. On Linux this is exactly what
   `rustix::pty::openpt` does (`src/pty.rs:91-101`). On macOS `openpt`
   cannot take `CLOEXEC`: `OpenptFlags::CLOEXEC` exists only on Linux,
   FreeBSD and NetBSD. A separate `fcntl_setfd` would leave a window in
   which a concurrent spawn in another connection could inherit the
   master, and that copy would block the hang-up that closing the
   master must deliver (§7). The flag is therefore set at open on every
   platform. Then `grantpt`, which is a no-op on Linux.
2. **Slave owner and mode, while the pair is still locked.** `devpts`
   takes the owner, group and mode of a new slave from its mount options
   (`uid=`, `gid=`, `mode=`). The kernel default mode is `0600`;
   distributions commonly mount with `gid=5,mode=620`. A permissive
   mount, such as `mode=0666`, would let other local users read or inject
   terminal input. The server therefore does not rely on the mount, and
   it acts before `unlockpt`, while nobody can open the slave yet:
   - `ptsname`, then `rustix::fs::stat`: the slave's owner must be the
     process UID, or the `pty-req` is refused (a `uid=` mount option
     could assign another owner);
   - `rustix::fs::chmod(…, 0600)` (rustix 1.1.5, `src/fs/abs.rs:60` and
     `:78`);
   - then `unlockpt`.
3. **Slave.** On Linux, `rustix::pty::ioctl_tiocgptpeer(master, RDWR |
   NOCTTY | CLOEXEC)` opens the peer without a path lookup (kernel ≥
   4.13). Elsewhere, `rustix::fs::open` on the `ptsname` path with
   `RDWR | NOCTTY | CLOEXEC`. `NOCTTY` keeps the server from ever
   acquiring a controlling terminal. A `rustix::fs::fstat` on the opened
   descriptor (`src/fs/fd.rs:156`) confirms the owner and the `0600`
   mode before anything else uses it.
4. The master is made non-blocking (`rustix::io::ioctl_fionbio`). The
   slave is a separate open file description and stays blocking for
   the child.
5. Modes go to the slave (`tcsetattr`) and the size to the master
   (`tcsetwinsize`). Later `window-change` requests also go to the
   master, and the kernel signals `SIGWINCH` to the foreground job.

The workspace `rustix` pin gains the features `pty` (which implies `fs`,
already enabled) and `termios`. It is a feature flag on a crate already
in the tree, like ADR-0029's `fs`.

### 5. Session leader without `pre_exec`: the re-exec helper

- **Spawn.** The server spawns its own executable with a reserved first
  argument, then the target program, its argv[0], and its arguments. On
  Linux the executable is `/proc/self/exe`, which names the running image
  even if the file on disk was replaced. Elsewhere it is
  `std::env::current_exe()`. The helper's stdin, stdout and stderr are
  duplicates of the slave (`Stdio::from(OwnedFd)`). Its environment is
  ADR-0016's allowlist plus `TERM` (§2), set before the helper runs, so
  no `RUST_*` variable reaches it. There is no `process_group` call: if
  the helper were a process-group leader, `setsid` would fail with
  `EPERM`.
- **Helper.** `main` checks for the reserved argument before CLI
  parsing, configuration, logging or the runtime. The helper is
  therefore single-threaded and never touches server state. It does
  three things:
  1. `rustix::process::setsid()` (rustix 1.1.5, `src/process/id.rs:234`);
  2. `rustix::process::ioctl_tiocsctty(stdin)` (`src/process/ioctl.rs:28`);
  3. `std::process::Command::new(program).arg0(argv0).args(…).exec()`.
     This call is safe. `std` resets `SIGPIPE` to its default before
     `execve` (std 1.99.0, `library/std/src/sys/process/unix/unix.rs:360-375`).

  On any failure the helper exits with 127, the conventional "could not
  execute" status. It prints nothing, because fd 2 is the user's
  terminal.
- **Slave copies.** The server closes its own copies of the slave as
  soon as the spawn returns, including those the `Command` builder
  holds. Otherwise the master would never see end-of-session.
- **Contract.** The reserved argument is an internal contract between
  one binary and itself, not an operator interface, and `--help` does
  not list it. Run by hand it grants nothing: it runs as the caller, on
  the caller's fd 0. The binary must not be writable by the service
  account, which is the standard install posture; it now also runs at
  the start of every PTY session.
- **Library boundary.** The helper's entry point lives in
  `quantumssh-core`. Any binary that hosts PTY sessions calls it first in
  `main`, as `quantumssh` does. The executable to re-exec is an optional
  field of `quantumssh-core::server::Config`, which the binary sets. When
  it is unset, `pty-req` is refused (§2's failure table): the library
  never spawns an executable that might not implement the helper and
  would exit with 127. `quantumssh-core` is not published (ADR-0017), and
  `Config` is the workspace-internal handoff that ADR-0026 (`rekey`) and
  ADR-0028 (`limits`) already extended in the ADR lane. PTY integration
  tests live in the binary crate and re-exec the real binary through
  Cargo's `CARGO_BIN_EXE_quantumssh`. The library's unit tests do not
  re-exec anything.

### 6. Runtime: `tokio::process` for every channel child

- **Feature delta.** `quantumssh-core`'s `tokio` gains `process`, and
  `signal` for the reaper's `SIGCHLD` wake-up (§6, "Reaping"). The
  lockfile gains no crate: these features need `bytes`, `libc`, `mio`
  and `signal-hook-registry`, and all four are already locked
  (`signal-hook-registry` 1.4.8 through ADR-0028's `signal` in the
  binary). ADR-0022 anticipated this: "possibly
  `tokio::process`. Each addition is a small, reviewable `Cargo.toml`
  change, not a re-decision of this ADR".
- **Pipe sessions** (`exec`, and `shell` without a PTY) leave the
  blocking pool. `ChildStdin`, `ChildStdout` and `ChildStderr` are
  async, and the pumps become runtime tasks. They feed the driver the
  same interface as today: output chunks and the exit, stdin with
  consumption acks, and kill. ADR-0023's flow-control and close logic is
  kept, not re-derived. `process_group(0)` and the environment
  sanitisation do not change.
- **PTY sessions.** The master is registered with `AsyncFd`, which needs
  only the already-enabled `net` feature (tokio 1.51.4,
  `src/io/mod.rs:255-258`). Reads and writes are non-blocking
  `rustix::io::read`/`write` calls under readiness. Each session has one
  master, and no task may keep it open after the channel ends.
- **Reaping.** An async task owns the unreaped `tokio::process::Child`
  and waits for either its exit or a kill request. Dropping the
  driver-side handle counts as a kill request; this is ADR-0023's
  no-orphan guard. The reap task outlives the cancellable connection
  future and carries out the request, whatever ended the channel (client
  close, connection loss, shutdown deadline):
  - pipe sessions get the immediate group `SIGKILL`;
  - PTY sessions get §7's hang-up sequence;
  - only the drop guard below kills both kinds immediately.
- **The reap task never outlives its connection task.** ADR-0028 allows
  no detached tasks: every connection lives in the server's `JoinSet`,
  and cooperative shutdown kills the child before the connection
  returns. So:
  - Each reap task is spawned into a `JoinSet` that the connection task
    owns (`handle` in `crates/quantumssh-core/src/server.rs:257`),
    outside the connection future that a shutdown deadline cancels.
  - The connection task awaits that set before it logs
    `connection.closed` and returns. A connection therefore leaves the
    server's `JoinSet` only after its child's teardown has finished.
  - The connection task can itself be aborted (ADR-0028's last resort).
    Dropping its `JoinSet` then only *requests* that the reap tasks abort
    (tokio 1.51.4, `src/task/join_set.rs:590-594`), and their drop
    guards run whenever the runtime gets to them. That can be after the
    server's `JoinSet` has already counted the connection as finished,
    so the reapers' guards alone cannot be relied on in this path.
  - The connection task therefore also owns a **synchronous kill
    guard**: a registry of its live children, behind a `std::sync::Mutex`.
    - When the aborted connection future is dropped, the guard's `Drop`
      sends `SIGKILL` to each registered child **by PID**
      (`rustix::process::kill_process`) and then to its **process group**
      (`kill_process_group`). Both are safe fns in rustix 1.1.5
      (`src/process/kill.rs:16`, `:35`). These are syscalls, with no
      await.
    - The PID kill closes the PTY helper's pre-`setsid` window. Between
      spawn and its own `setsid()`, the helper is still in the server's
      group, so no group with its PID exists yet and the group kill
      returns `ESRCH`. Once `setsid` has run, the group kill reaches the
      rest of the session. `ESRCH` is expected in either order and is
      ignored.
    - tokio drops an aborted task's future *before* it stores the
      task's result (`src/runtime/task/harness.rs:500-507`), so the kill
      happens before the server's `JoinSet` can observe the connection
      as complete.
    - **Reaping and deregistration are one critical section.** The
      reaper does not reap inside an await.
      1. It waits for the leader's exit *without reaping it*. On Linux it
         waits for a pidfd to become readable
         (`rustix::process::pidfd_open`, rustix 1.1.5
         `src/process/pidfd.rs:29`, under `AsyncFd`). Elsewhere, or where
         `pidfd_open` fails, tokio's `SIGCHLD` signal stream is the
         wake-up for §7's `waitid(EXITED | NOHANG | NOWAIT)` peek.
      2. Only then, holding the registry lock, it reaps with
         `Child::try_wait()` and removes the entry before releasing the
         lock. `try_wait` is non-blocking and reaps an exited child
         (tokio 1.51.4, `src/process/mod.rs:1401-1413`).

      A child is therefore registered for its whole unreaped life,
      running or zombie. The guard either finds it, with its PID still
      reserved and safe to signal, or does not find it because it has
      already been reaped. No live child is ever unregistered, and no
      reaped PID is ever registered, which keeps the no-reused-PGID rule
      below. On this last-resort path PTY sessions get no hang-up grace.

  The reaper therefore does not use `Child::wait()`, which reaps inside
  its own poll. It follows the same split tokio uses internally: a
  pidfd on Linux (kernel ≥ 5.3), and a `SIGCHLD` handler where that is
  unavailable and on macOS (tokio 1.51.4,
  `src/process/unix/mod.rs:123-137`). The difference is that the
  readiness wait and the reap are separated by the registry lock.
  Nothing polls and no thread is parked while a session runs. The only
  polling is the `NOWAIT` peek after a `SIGCHLD` wake-up and in §7's
  teardown grace.

  `quantumssh-core` gains tokio's `process` feature, and its `signal`
  feature for the `SIGCHLD` stream. Both are features of the existing
  tokio dependency, not new crates, so `Cargo.lock` gains no package.
- **Kill through the owned handle, always before reaping.** The kill,
  immediate for pipe sessions and after §7's grace for PTY sessions,
  sends `SIGKILL` to the process group
  (`rustix::process::kill_process_group`) and calls `start_kill()` on
  the leader. It is issued only while the leader is unreaped, running or
  a zombie, which shows as `Child::id()` still being `Some`; that
  becomes `None` once the child is reaped (tokio 1.51.4,
  `src/process/mod.rs:1222`). While the leader is unreaped, its pid,
  which is also its process-group id, cannot have been reused. This is
  ADR-0016's argument, kept on every path, including §7's grace. If the
  reap task itself is dropped (its connection task aborted, or the
  runtime torn down), a guard does the same thing synchronously.
  `kill_on_drop` alone would signal only the leader.
- **Blocking pool.** ADR-0028's bound (`main.rs:41`, `main.rs:420-426`)
  loses its consumer. It stays as an upper bound, since tokio starts
  blocking threads on demand. This ADR does not change it.

### 7. Flow control, EOF and close

- **Window accounting does not change** (ADR-0023):
  - Inbound credit is returned only for bytes the master or the stdin
    pipe accepted. When the PTY input queue is full, the write would
    block, credit is withheld, and the wire is backpressured.
  - The master is read only while the driver's output queue has room.
    That queue has the same bound as for `exec`: 8 chunks of 32 KiB
    (`exec.rs:31-36`). While the client's window is closed, the queue
    fills, the master is no longer read, the kernel's PTY buffer fills,
    and the session's writers block. Server memory stays bounded per
    session.
  - PTY output is a single stream sent as `CHANNEL_DATA`, because the
    terminal merges stdout and stderr. Inbound `EXTENDED_DATA` still
    disconnects.
  - Data that arrives before the child starts is buffered within the
    window and delivered at start, as for `exec`.
- **Client `CHANNEL_EOF` on a PTY session.** No further input is
  accepted, and data after EOF still disconnects. The master stays open
  for output, because a terminal has no half-close: the shell sees
  end-of-file only through the line discipline (`VEOF`). Pipe sessions
  are unchanged: stdin is closed.
- **The session leader exits.** The server reads what the master already
  holds, until the first would-block, `EIO` or 0-byte read, and then
  closes the master. It does not wait for other processes that still
  hold the slave. Then come `exit-status` or `exit-signal`, `EOF` and
  `CLOSE`, in ADR-0023's order.
  - No signal is sent to the leader's process group on a normal exit.
    What the leader deliberately left running is not killed. This
    matches `exec` today, whose reap kills only on a kill request
    (`exec.rs:232-251`), and sshd. It keeps `ssh host 'nohup job &'`
    working.
  - Processes that still hold the slave get the hang-up when the master
    closes.
- **The leader is still running when the channel ends** (client
  `CHANNEL_CLOSE`, connection loss, or ADR-0028's shutdown deadline). The
  server sends `SIGHUP` to the leader and closes the master. This is a
  terminal hang-up: shells forward it to their jobs and editors save
  recovery files. The server then waits up to 1 s for the leader to exit,
  **without reaping it**:
  - The reap task stops awaiting `Child::wait()`, which would reap.
  - Instead it peeks with
    `rustix::process::waitid(WaitId::Pid(pid), EXITED | NOHANG | NOWAIT)`
    (rustix 1.1.5, `src/process/wait.rs:488`, flags at `:56-67`) every
    20 ms, the current reap interval. The peek leaves the leader a
    zombie.
  - When the leader has exited or the second has passed, the server
    sends `SIGKILL` to the leader's process group, which is still safe
    (§6), and only then reaps.

  A shell that honours `SIGHUP` still exits early, and the group kill
  still reaches anything left in its group. Pipe sessions keep
  ADR-0023's immediate group `SIGKILL`. The 1 s figure is an initial
  value, not a measurement; changing it is an implementation constant,
  not a re-decision.
- **What "no orphan" covers.** The guarantee is the one `exec` has today.
  When the channel ends while the leader is still running, the leader
  and its process group are killed. Some processes can outlive the
  channel, as they can under OpenSSH:
  - processes the leader leaves behind when it exits normally (a
    `nohup`'d job, for example);
  - processes that left the group: a job-control group that ignores
    `SIGHUP`, or a command that calls `setsid`, which `exec` commands can
    already do.

  Containment beyond that (cgroups) belongs to the systemd ADR or to
  Phase 3.
- Every `exec.started` still produces exactly one `exec.finished`, on
  every path.

### 8. `exit-status` and `exit-signal`

- A normal exit sends `exit-status` with the exit code.
- A death by a signal on RFC 4254 §6.10's list (`ABRT ALRM FPE HUP ILL
  INT KILL PIPE QUIT SEGV TERM USR1 USR2`) sends `exit-signal`. It
  carries the name without `SIG`, the core-dumped flag
  (`ExitStatusExt::core_dumped`), and an empty message and language tag.
  This matches sshd's `session_exit_message`.
- A death by any other signal (for example `SIGBUS` or `SIGSYS`) keeps
  the Phase-1 `exit-status` of 128 + n. No vendor signal names are
  invented.
- An early client close sends neither (ADR-0023).
- The same rules apply to `exec`.

### 9. Audit (ADR-0024)

- **A shell session is an `exec` event.** Every child the channel layer
  starts emits `exec.started` and `exec.finished`, because the §2.7
  boundary is the server starting a process on the user's behalf.
  Separate `shell.*` events would let a consumer keyed on `exec.*` miss
  interactive sessions.
- **Two fields are added to both events:**
  - `request_type`: `"exec"` or `"shell"`;
  - `pty`: a boolean.

  `command` is still the verbatim client command for `exec`. For `shell`
  it is the empty string, because there is no client command, and
  `request_type` disambiguates. `authenticated_identity` and
  `executing_uid` stay mandatory and unchanged. `exit_status` keeps its
  meaning (the exit code, or 128 + n); the wire's `exit-signal` is not
  mirrored as a field.
- **Never logged:** `TERM`, the modes, window sizes, and session content
  (threat model §5.4.3).
- This is an additive change before the freeze, like ADR-0028's
  `connection.refused`, and it joins the `0.1.0` freeze checklist.
  It changes the field lists that ADR-0024 recorded for the two `exec.*`
  rows, so ADR-0024's Status field gains a partial-supersession pointer
  here, as ADR-0020's and ADR-0033's Status fields record theirs.
  ADR-0015 lets an accepted ADR change only its Status field and
  annotated errata. The pointer lands in the PR that flips this ADR to
  `Accepted` (§11), when the code starts emitting the fields. Until
  then, ADR-0024 keeps describing the schema the code actually emits.

### 10. Ownership and permissions, and what Phase 3 changes

- **Phase 2.** The server allocates the pair as the service account,
  checks that the slave belongs to that UID, and sets its mode to `0600`
  (§4). That is stricter than OpenSSH's `pty_setowner`, which sets group
  `tty` and mode `0620` (`sshpty.c`). With no group write bit, `write`,
  `wall` and `mesg y` cannot reach a QuantumSSH session. The server does
  no `chown`: as a non-root account it could not give the slave to
  another user, and the `tty` group cannot be relied on.
- **No isolation between sessions.** Any process of the service account
  can open any session's slave. Under §8.12 that is already true of
  everything else in the account.
- **No login records.** No `utmp`, `wtmp` or `lastlog` records are
  written, which would need root or the `utmp` group. The audit log is
  the record.
- **Phase 3 (not decided here).** The slave must belong to the target
  user. Either the privileged side allocates the pair and `fchown`s the
  slave before the drop, or the per-user helper allocates it after
  dropping privileges (`devpts` gives the slave to the UID that opens
  it). The §5 helper is the single-threaded point before `exec` that the
  scoping note's option C needs. This ADR leaves both choices to that
  RFC.

### 11. Implementation and tests

Implementation lands in later PRs; no code changes in this one. The
`exec` migration to `tokio::process`, which brings `exit-signal`, may
land first on its own. This ADR stays `Proposed` until the PTY path
lands. It flips to `Accepted` in that PR, which also adds ADR-0024's
Status pointer (§9). The implementation adds:

- unit tests for the mode parser and the `TERM` rule;
- PTY integration tests on both CI runners: ADR-0031 requires the
  Ubuntu and macOS builds;
- a PTY case in the OpenSSH interop gate (ADR-0020), for example `ssh -tt`
  observing a TTY, a window size and a mode from inside the session.

**Why an ADR, not an RFC.** `docs/rfcs/README.md` sends "a new dependency
that materially expands the trust base (anything in the crypto,
networking, or process-spawning paths)" and "a new public API surface"
to an RFC. This is recorded as an ADR for four reasons:

1. **No new dependency.** The change enables features on two existing
   pins, `rustix` (`pty`, `termios`) and `tokio` (`process`), and adds no
   crate. That is the lane ADR-0029 used for `rustix`'s `fs` and
   ADR-0028 used for `tokio`'s `signal`. ADR-0022 pre-cleared `process`
   as "a small, reviewable `Cargo.toml` change".
2. **No public interface.** The requests are RFC 4254 core, not
   extensions. The helper argument is internal to the binary. The new
   `Config` field belongs to the unpublished, workspace-internal
   `quantumssh-core` (ADR-0017), whose `Config` ADR-0026 and ADR-0028
   already extended. The operator-visible additions are two audit
   fields, and ADR-0028 set the precedent for adding one in an ADR.
3. **It refines no commitment.** The PTY shell is already in the
   README's `0.1.0` scope.
4. **It was routed here.** #109 and the Phase-2 scoping note route PTY
   to the ADR lane.

Alternative 2 below would need an RFC, because it adds a dependency in
the process-spawning path.

## Consequences

### Positive

- Interactive sessions with zero first-party `unsafe`. The mechanism was
  exercised on Linux and macOS by a `forbid(unsafe_code)` probe.
- No new crate, and `Cargo.lock` is unchanged.
- The channel layer leaves the blocking pool. Nothing polls during a
  session (only the ≤ 1 s teardown grace peeks), and no thread is parked
  per child. A session's master closes when the session decides, not
  when every slave holder has exited.
- One child lifecycle (spawn, owned-handle kill, reap, exit mapping)
  serves `exec`, `shell` and PTY sessions.
- `exit-signal` gives RFC-conformant clients the signal name and the
  core-dump flag.
- The helper is the single-threaded point before `exec` that Phase-3
  privsep option C needs, so the PTY design does not narrow that RFC.

### Negative

- **Startup and executable path.**
  - Each PTY session starts with one extra `execve` (the helper).
  - Linux needs `/proc` mounted; without it, PTY sessions end with exit
    status 127.
  - On other platforms `current_exe()` names a path. A binary replaced
    during an upgrade means new sessions run the new binary's helper.
- **`exit-signal` and the OpenSSH client.** OpenSSH's client does not
  parse `exit-signal`: `clientloop.c`'s `client_input_channel_req`
  handles `exit-status` and `eow@openssh.com` only. So `ssh` reports
  255 when a remote command dies by one of the thirteen named signals,
  as it already does against sshd, where Phase 1 reported 128 + n. The
  audit record keeps 128 + n.
- **Background processes.** Processes that leave the leader's process
  group can outlive the channel (§7). This is inherent to granting a
  shell, and the same escape already exists for `exec`.
- **No session isolation and no login records.** Sessions are not
  isolated from each other (the same UID owns every slave, §8.12), and
  `who`, `w` and `last` do not show QuantumSSH sessions.
- **Keys with options get no PTY** until per-key restrictions land (§3).
- **Behaviour change for `exec`.** Moving `exec` onto `tokio::process`
  touches tested Phase-1 code. The existing tests and the interop gate
  must stay green through the migration.
- **Process-wide `SIGCHLD` handler.** Tokio's `SIGCHLD` fallback
  (macOS, and Linux without `pidfd_open`) installs one.
- **Freeze surface.** `request_type` and `pty` add to the `0.1.0` freeze
  surface.
- **Shutdown and idle.** At shutdown, interactive sessions rarely exit
  before ADR-0028's drain deadline. They are ended by §7's hang-up
  sequence. When the server aborts their connection task at that same
  deadline, the reap task's drop guard ends them with an immediate
  `SIGKILL` instead, so the grace can be cut short at shutdown. Idle
  sessions have no timeout and each
  holds one connection slot. The channel phase stays un-timed
  (ADR-0023).

### Neutral

- The shell stays fixed at `/bin/sh`, as for `exec`. A `[session]` shell
  key can be added compatibly later, before or after the freeze.
- Still one channel per connection; SFTP brings multiplexing.
- Terminal speeds are ignored.

## Alternatives considered

### Alternative 1: re-exec helper (chosen)

Section 5. Its cost is one extra `execve` per PTY session and an
internal argument contract. Its gain: zero first-party `unsafe`, no
dependency, and the two syscalls run in a single-threaded process
instead of a forked copy of the multi-threaded runtime.

### Alternative 2: a crate that wraps `pre_exec`

- **`pty-process` 0.5.3** depends on `rustix` (`pty`, `process`, `fs`,
  `termios`). Its `async` feature also turns on `tokio`'s `fs`, which
  ADR-0022 excludes. Its spawn runs `setsid` and `TIOCSCTTY` in a
  `pre_exec` closure: `unsafe { self.inner.pre_exec(session_leader) }`
  (`src/command.rs:197`, closure in `src/sys.rs:149-160`).
- **`portable-pty` 0.9.0** calls `libc::setsid` and `libc::ioctl(0,
  TIOCSCTTY)` inside `pre_exec` (`src/unix.rs:238-271`). It brings
  `anyhow`, `downcast-rs`, `filedescriptor`, `log`, `nix`, `serial2` and
  `shell-words`, plus a blocking, thread-based I/O model.

Both move the same `unsafe` into a new dependency on the
process-spawning path, which is RFC lane. The closure still runs in a
child forked from the multi-threaded Tokio process, and must stay
async-signal-safe. `portable-pty` would also add `nix` as a second
syscall wrapper next to `rustix` (MANIFIESTO #4). What either saves is
the two syscalls the helper makes. Rejected.

### Alternative 3: an external `setsid` binary

util-linux `setsid --ctty` exists (2.38.1 in Debian bookworm). It is
Linux-only: macOS has no `setsid` binary, and the macOS build and test
is a required check (ADR-0031). It also trusts a host binary outside the
release artifact, whose path and version vary. And `setsid(1)` forks
when its caller is a process-group leader, so the pid the server holds
might not be the session leader. Rejected.

### Alternative 4: first-party `pre_exec`, or `CommandExt::setsid`

`pre_exec` is `unsafe`, and ADR-0018's `forbid` admits no override;
lifting it would take a superseding ADR, against MANIFIESTO #1.
`CommandExt::setsid` is unstable and would not set the controlling
terminal. Rejected, and not available on stable.

### Alternative 5: keep `spawn_blocking` for PTY sessions

A blocking master read cannot be cancelled by the channel. A job that
keeps the slave open pins a thread and a descriptor past the session,
and the polling reap runs for the session's whole life. Rejected (force
2).

### Alternative 6: `tokio::process` for PTY sessions only, `exec` unchanged

This keeps two lifecycles that enforce the same invariants: owned-handle
kill, exit before close, and the `exit-signal` mapping. They would be
duplicated, and they would drift. Rejected.

### Alternative 7: first-party pidfd reaping on `rustix`

`pidfd_open` plus an `AsyncFd`. It is Linux-only, macOS would need a
second path, and it re-implements what the pinned tokio already does.
Rejected.

### Alternative 8: separate `shell.*` audit events

Rejected (§9): a consumer that alerts on `exec.started` would miss every
interactive session.

### Alternative 9: refuse `shell` without a PTY

That would keep ADR-0023's Alternative 2 stance. ADR-0023 refused
`shell` without a PTY because interactive semantics belonged to Phase 2's
PTY work, which is this ADR. Scripts such as `ssh host <<EOF … EOF` send
`shell` with no `pty-req`, and without a PTY it is the same pipe path as
`exec`, with no new surface. Rejected.

## Links

- Code this decision changes, all of which exists today:
  `crates/quantumssh-core/src/channel.rs`, `crates/quantumssh-core/src/exec.rs`,
  `crates/quantumssh-core/src/auth.rs` (§3 gate input),
  `crates/quantumssh/src/main.rs` (helper dispatch),
  `Cargo.toml` and `crates/quantumssh-core/Cargo.toml` (features),
  `tests/interop/run_openssh_client.sh` (PTY case). A new PTY module in
  `quantumssh-core` does not exist yet.
- Related ADRs: [ADR-0023](0023-phase-1-channel-layer-scope.md) (extended),
  [ADR-0022](0022-phase-1-async-runtime-tokio.md) (`process` feature
  question answered), [ADR-0016](0016-phase-1-service-account-uid-model.md),
  [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md),
  [ADR-0024](0024-phase-1-log-event-schema.md) (`exec.*` field lists
  partially superseded on acceptance),
  [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md),
  [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md),
  [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md),
  [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md).
- Threat model: §2.5 and §2.7 (execution authority and its audit record),
  §4.2 ("every PTY allocated"), §5.4.1 and §5.4.3, §6.3 (per-key
  restrictions), §8.12.
- Standards: RFC 4254 §5.4, §6.2, §6.5, §6.7, §6.10 and §8; RFC 8160
  (`IUTF8`).
- Prior art: OpenSSH `session.c` (`session_pty_req`,
  `session_window_change_req`, `session_exit_message`, `sig2name`),
  `sshpty.c` (`pty_setowner`, `pty_make_controlling_tty`), and
  `clientloop.c` (`client_input_channel_req`).
- Pinned sources checked: `rustix` 1.1.5 (`Cargo.lock:520-521`),
  `tokio` 1.51.4 (`Cargo.lock:675-676`), and the Rust 1.99.0 standard
  library.
