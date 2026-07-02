# ADR 0023: Scope the Phase 1 channel layer to a single `session` channel running one `exec`

- **Status:** Accepted
- **Date:** 2026-06-30 (accepted in the #86 Phase-1 governance sweep)
- **Deciders:** Project lead
- **Related:** Fulfils the "ADR-TBD ('scope of single-command execution')" placeholder named in [RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) §"Reference-level explanation"; builds on [ADR-0021](0021-phase-1-negotiation-profile.md) (the transport this rides on) and [ADR-0022](0022-phase-1-async-runtime-tokio.md) (`spawn_blocking` exec model); realises `docs/threat-model.md` §2.5 (command-execution authority) and §5.4 (session-layer attack vectors); bounded by §8.12 (per-user UID non-goal). Planned implementation (TBD): the `channel` module of `quantumssh-core`, which does not exist yet.

## Context

[RFC-0003](../rfcs/0003-phase-1-ssh-stack-greenfield-vs-russh.md) committed Phase 1 to a greenfield transport and named, but deferred, the exact subset of the RFC 4254 connection protocol the walking skeleton implements: "the RFC 4254 channel layer subset documented in ADR-TBD ('scope of single-command execution')". This ADR is that document.

RFC 4254 defines a multiplexed channel layer: many concurrent channels per connection, several channel types (`session`, `direct-tcpip`, `forwarded-tcpip`, `x11`), and within a `session` channel a family of requests (`pty-req`, `shell`, `exec`, `subsystem`, `env`, `signal`, `window-change`, `exit-status`, `exit-signal`, …). The README scopes Phase 1 to "single-command execution" and defers PTY and SFTP to Phase 2; the threat model §5.4 makes forwarding and PTY opt-in, off by default. What remains undecided is the precise message- and request-level boundary an implementer codes against: which messages `channel.rs` parses and emits, which requests it honours, and how it answers everything else. Drawing that line too wide imports Phase 2/3 surface into the walking skeleton (against MANIFIESTO #4); drawing it too narrow produces a server a real OpenSSH client cannot drive through `ssh host cmd` cleanly (against the ADR-0020 interop gate).

## Decision

Phase 1 implements exactly **one `session` channel per connection, carrying exactly one `exec` request**, and nothing else. Concretely:

**Channel messages implemented** (RFC 4254 §5):

| Msg | Number | Role in Phase 1 |
|---|---|---|
| `SSH_MSG_CHANNEL_OPEN` | 90 | Accept iff `channel type == "session"` and no session channel is already open. |
| `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` | 91 | Sent in reply to an accepted `session` open. |
| `SSH_MSG_CHANNEL_OPEN_FAILURE` | 92 | Sent with the RFC 4254 §5.1 code matching the case: a non-`session` type (no handler in Phase 1) gets `SSH_OPEN_UNKNOWN_CHANNEL_TYPE` (3); a second `session` open — a type the server understands but refuses by policy — gets `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` (1). |
| `SSH_MSG_CHANNEL_WINDOW_ADJUST` | 93 | Honoured both directions — required for RFC 4254 flow-control compliance. |
| `SSH_MSG_CHANNEL_DATA` | 94 | Child stdout streamed to the client; inbound data accepted (stdin to the child). Inbound data arriving **before** an `exec` is honoured is buffered within the window (legitimate stdin pipelining) and delivered when the child starts; discarded if the channel closes without an `exec`. |
| `SSH_MSG_CHANNEL_EXTENDED_DATA` | 95 | Child stderr streamed to the client with `data_type_code == SSH_EXTENDED_DATA_STDERR` (1). **Inbound** extended data is rejected: RFC 4254 defines no client→server extended-data type, so receiving message 95 terminates the connection (`SSH_DISCONNECT_PROTOCOL_ERROR`). |
| `SSH_MSG_CHANNEL_EOF` | 96 | Sent when the child's output is fully drained; accepted from the client (closes the child's stdin). Inbound `CHANNEL_DATA` **after** the client's EOF violates RFC 4254 §5.3 and terminates the connection (`SSH_DISCONNECT_PROTOCOL_ERROR`). |
| `SSH_MSG_CHANNEL_CLOSE` | 97 | Sent after `exit-status`; the half-close handshake is completed before the channel is freed. |
| `SSH_MSG_CHANNEL_REQUEST` | 98 | Only `exec` is honoured (see below). |
| `SSH_MSG_CHANNEL_SUCCESS` | 99 | Sent in reply to an accepted `exec` request that set `want_reply`. |
| `SSH_MSG_CHANNEL_FAILURE` | 100 | Sent for any other request type that set `want_reply`. |

**Channel requests:**

- **`exec` is the only honoured request, and it is honoured once.** Its `command` string is passed to the child process spawn described in ADR-0022 (`std::process::Command` on `spawn_blocking`). A **second `exec` on the same channel** — while the child is still running or after it has exited — is answered with `SSH_MSG_CHANNEL_FAILURE`: the channel's single `exec` is consumed by the first accepted request. Under threat-model §8.12 the child runs as the QuantumSSH service-account UID, not a per-user UID — Phase 1 is single-user by design. Accepting the `exec` is the **audit boundary**: the server emits `exec.started` and `exec.finished` with `authenticated_identity` and `executing_uid` as separate first-class structured fields and `command` as a structured field, never interpolated — the binding authority is the hard rule in `CLAUDE.md`; the full event schema is being fixed by ADR-0024 (TBD — in review as PR #50).

  > **Note (M5): the command runs through a fixed shell, `/bin/sh -c "<command>"`.** SSH `exec` delivers a single opaque string (`ssh host 'echo hello'` sends `echo hello`); executing it requires an interpreter, and OpenSSH itself runs `exec` through the target user's login shell with `-c`. Phase 1 cannot use a *login* shell: the service account's login shell is `/usr/sbin/nologin` by design (ADR-0016), which refuses commands. So Phase 1 fixes the interpreter to `/bin/sh` and spawns `/bin/sh -c "<command>"`. This is the post-auth authority boundary — attacker-controlled input is interpreted by a shell (metacharacters, pipelines) — bounded by: the service-account UID (no privilege escalation; threat-model §8.12), the **sanitised environment** ADR-0016 already mandates (allowlist `PATH, HOME, USER, SHELL, LANG, LC_*`; no client-supplied `env`, which this ADR refuses), and the one-channel/one-exec scope. It is inherent to SSH `exec` semantics, not a QuantumSSH-specific widening. A future per-user model (Phase 3) would resolve the interpreter per user instead of fixing it.
- **`exit-status` is sent** as a `SSH_MSG_CHANNEL_REQUEST` (`want_reply = false`) carrying the child's exit code before `SSH_MSG_CHANNEL_CLOSE`. This is required for `ssh host cmd; echo $?` to report correctly and is asserted by the ADR-0020 interop gate.
- **All other requests are refused** with `SSH_MSG_CHANNEL_FAILURE` when they set `want_reply`, and ignored otherwise. This explicitly includes `pty-req` (Phase 2), `shell` (Phase 2), `subsystem` (SFTP is Phase 2), `env`, `signal`, and `window-change`. Refusing `pty-req` and `shell` is what makes "single-command execution, no interactive shell" true at the protocol level.

**Structural bounds:**

- **One channel per connection, for the connection's lifetime.** A second `SSH_MSG_CHANNEL_OPEN` — whether while the session channel is live **or after it has completed its close handshake** — is answered with `SSH_MSG_CHANNEL_OPEN_FAILURE`: the connection's single session channel is consumed by the first accepted open, preserving the "exactly one `exec` request per connection" invariant end to end. A client that wants a second command opens a new connection. SSH-2 permits multiplexing; Phase 1 deliberately does not. This collapses a whole class of channel-id bookkeeping and concurrent-channel state out of the walking skeleton.
- **No global requests.** `SSH_MSG_GLOBAL_REQUEST` (80) — used for `tcpip-forward` and friends — is answered with `SSH_MSG_REQUEST_FAILURE` (82). Port forwarding is off by default per threat-model §5.4.2.
- **Flow control is real, not stubbed — in both directions.** Outbound: the server never sends past the client's advertised window and honours `SSH_MSG_CHANNEL_WINDOW_ADJUST`; a stubbed/ignored window is a correctness bug an OpenSSH client surfaces under load. Inbound — the security-relevant half: the server never buffers beyond its own advertised window, so per-channel buffered memory is bounded by the initial window; a peer that sends `CHANNEL_DATA`/`EXTENDED_DATA` exceeding the advertised inbound window violates RFC 4254 §5.2 ("MUST NOT send more data than the window allows") and the connection is terminated with `SSH_MSG_DISCONNECT` (`SSH_DISCONNECT_PROTOCOL_ERROR`), not accommodated by over-buffering. Inbound window replenishment (`WINDOW_ADJUST`) is granted only as data is consumed by the child's stdin, so a stalled child applies backpressure to the wire instead of growing a queue. Phase 1 initial window: **2 MiB**; maximum packet size: **32 KiB** (matching OpenSSH's defaults, so the interop client's assumptions hold).
- **Child-process lifecycle.** The child is waited on the blocking thread (ADR-0022); when it exits, the server sends any remaining buffered stdout/stderr, then `exit-status`, then `SSH_MSG_CHANNEL_EOF`, then `SSH_MSG_CHANNEL_CLOSE`, and completes the close handshake. `exit-signal` (for processes killed by a signal) is **deferred to Phase 2**; a signal-terminated child reports a conventional non-zero `exit-status` in Phase 1. If the **client** sends `CHANNEL_CLOSE` while the child is still running (permitted by RFC 4254 §5.3, no prior EOF required), the server closes the child's stdin, terminates the child, replies with its own `CHANNEL_CLOSE`, and frees the channel; the wire-level `exit-status` is omitted — the client relinquished it by closing first. The **`exec.finished` audit event is emitted regardless**: every path that produced an `exec.started` produces an `exec.finished` (here with the terminated child's conventional non-zero exit status) — omitting a wire message never skips the audit record. No orphaned child survives its channel. During the **server-initiated half-close window** — after the server's `CHANNEL_CLOSE` has been sent but before the client's arrives — channel-scoped messages for the closing channel (`CHANNEL_DATA`, `WINDOW_ADJUST`, …) are accepted and silently discarded: RFC 4254 §5.3 lets the two `CHANNEL_CLOSE`s cross in flight, so such frames are legitimate, but the child has already exited and there is no sink. The channel is freed when the client's `CHANNEL_CLOSE` arrives; messages addressed to that channel number *after* that fall under the unknown-channel rule below and terminate the connection.
- **Stdin backpressure is intentional, not a liveness bug.** Because inbound replenishment is tied to the child's stdin consumption, a child that never reads stdin (`date`, `echo`) leaves the window unreplenished by design: a client streaming more than the 2 MiB initial window stalls — RFC 4254-compliantly — until the child exits and the close sequence releases it. The alternative (draining unread stdin to nowhere) would silently discard data and unbound the memory the window exists to bound.
- **Messages for unknown channels fail closed.** Any channel-scoped message (`CHANNEL_DATA`, `CHANNEL_REQUEST`, `CHANNEL_WINDOW_ADJUST`, …) whose recipient channel number was never opened and confirmed terminates the connection (`SSH_DISCONNECT_PROTOCOL_ERROR`) — consistent with the type-state posture: there is no "ignore and continue" path for traffic addressed to channels that do not exist.

## Consequences

### Positive

- `channel.rs` is small and total: eleven channel messages, one honoured request, one channel. It can be read in one sitting and fuzzed against a narrow grammar, consistent with MANIFIESTO #4 and threat-model §6.2.
- Every Phase 2 feature (PTY, SFTP, forwarding, multiple channels) is an explicit, reviewable addition — the "small surface, sharp edges" property holds because the refusals are coded, not merely undocumented.
- `exit-status` and correct windowing are exactly the two non-obvious things `ssh host cmd` needs to work against a real client; both are in scope, so the ADR-0020 gate is satisfiable.

### Negative

- Refusing `env` means a client's `SendEnv`/`SetEnv` is silently dropped (ignored when `want_reply` is false, as OpenSSH sends it). Scripts relying on forwarded environment variables will not get them in Phase 1. Acceptable for a walking skeleton; revisited with the config work in Phase 2.
- Deferring `exit-signal` means a child killed by, say, `SIGSEGV` is reported only as a non-zero exit code, losing the signal detail. A correctness nicety, not a blocker; Phase 2 adds it.
- One-channel-per-connection means a client that opens a second channel (some automation multiplexes) gets a failure rather than service. This is a deliberate scope cut, documented so it is not mistaken for a bug.

### Neutral

- The 2 MiB / 32 KiB window/packet defaults mirror OpenSSH. They are not tuned for throughput (Phase 1 is not a performance target per the README); they are chosen so the interop client's flow-control behaviour matches what Phase 1 expects.
- Inbound `SSH_MSG_CHANNEL_DATA` (stdin to the child) is accepted, so `echo foo | ssh host cat` works. This is within "single-command execution" and costs little; it is noted as in-scope so it is not assumed deferred.

## Alternatives considered

### Alternative 1: `exec` only, no stdin, no `exit-status`

The absolute minimum: spawn, stream stdout, close. Rejected on two counts: without `exit-status` the interop gate's `ssh host cmd` cannot verify exit codes and real scripts break on `$?`; without stdin, `… | ssh host cat`-style pipelines fail. Both are cheap to support and squarely inside "single-command execution", so excluding them buys nothing but a less useful skeleton.

### Alternative 2: Also honour `shell` (interactive shell without PTY)

A `shell` request with no PTY yields a non-interactive shell on a pipe — arguably still "not a PTY". Rejected: it is the thin end of interactive-session semantics (job control, prompt handling, line discipline expectations) that Phase 2's PTY work owns. Honouring `shell` now would invite clients to depend on half-implemented interactive behaviour. `shell` is refused cleanly; Phase 2 adds it deliberately.

### Alternative 3: Support multiple concurrent channels

Implement the full multiplexing model now, so Phase 2 features slot in without revisiting channel bookkeeping. Rejected: concurrent channels bring channel-id allocation, per-channel window state, and interleaving concerns that are pure cost for a single-exec skeleton. The transport's type-state design (ADR-0021) makes adding the second channel in Phase 2 a localised change; paying for it now violates YAGNI and MANIFIESTO #4.

### Alternative 4: Leave the boundary to the implementation PR

Let `channel.rs` define its own scope as it is written. Rejected for the reason RFC-0003 named this an ADR in the first place: the message- and request-level boundary is a security-relevant interface (it is the list of things the post-auth attacker in threat-model §5.4 can reach), and it deserves a recorded decision rather than an emergent one.

## Links

- Implementation: TBD — the `channel` module of `quantumssh-core`, once the first crate lands. Does not exist in the repository yet.
- Interop assertions: ADR-0020 `integration::openssh_smoke` (`ssh … echo hello` → `hello`, exit 0) exercises open → `exec` → data → `exit-status` → close.
- Related ADRs: [ADR-0021](0021-phase-1-negotiation-profile.md) (transport the channel rides on), [ADR-0022](0022-phase-1-async-runtime-tokio.md) (`spawn_blocking` child-process model), [ADR-0016](0016-phase-1-service-account-uid-model.md) (the service-account UID the child runs as).
- Threat model: §2.5 (command-execution authority), §5.4.1–§5.4.4 (session-layer vectors — agent/port forwarding, PTY escapes, exfiltration; all out of scope or off by default here), §8.12 (per-user UID non-goal that bounds what `exec` means in Phase 1).
- Standards: RFC 4254 §5 (channel mechanism), §6.5 (`exec` / `shell` / `subsystem` requests), §6.10 (`exit-status` / `exit-signal`).
