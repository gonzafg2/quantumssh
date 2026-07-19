# ADR 0028: Phase 2 runtime — concurrent connections, admission limits, graceful shutdown

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the implementing Phase-2 runtime PRs merge)
- **Deciders:** Project lead
- **Related:** Extends [ADR-0022](0022-phase-1-async-runtime-tokio.md) (runtime, feature set, the sequential spawn-and-join loop this ADR removes); constrained by [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"`) and [ADR-0024](0024-phase-1-log-event-schema.md) (log schema — one new event below). Part of the Phase-2 milestone ([#109](https://github.com/gonzafg2/quantumssh/issues/109)); sequencing rationale in [`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md) (non-authoritative). The systemd ADR (TBD) will build on the shutdown path decided here.

## Context

ADR-0022 fixed the Phase-1 accept loop as spawn-and-join: one connection served to completion before the next accept, with the `Send` bound compiler-enforced from the first crate precisely so that Phase 2's move to real concurrency would be "*removing* the immediate join … not a refactor". That ADR also deferred three things to Phase 2, all now due:

1. **Concurrent connections.** The sequential loop lets an adversary serialise slow handshakes back-to-back and monopolise the listener — accepted in Phase 1 as a pre-alpha ceiling (ADR-0022 §Consequences; threat model §8.3), recorded again by the Phase-1 security review. Phase 2 closes it.
2. **Admission limits.** Threat model §5.1.3 requires per-source connection rate limits, total half-open connection caps, and handshake deadlines, all configurable with documented defaults and a slow-handshake test scenario. Phase 1 shipped only the handshake deadline (30 s, `--handshake-timeout`); under a concurrent loop the other two stop being properties of the loop shape and must become explicit.
3. **Graceful shutdown on OS signals.** ADR-0022 excluded the `signal` feature ("a Phase 2 operational concern"); the systemd workstream depends on it.

## Decision

We will replace the spawn-and-join loop with a concurrent accept loop with explicit admission control, and terminate on SIGTERM/SIGINT by draining active sessions under a deadline.

- **Task tracking: `tokio::task::JoinSet`.** The accept loop `tokio::select!`s over `accept()`, `JoinSet::join_next()`, and the shutdown signal. Every task completion is reaped; a `JoinError` (panic) is logged as `connection.closed` with the panic reason as a structured `reason` field — never interpolated into the message text, per ADR-0024's discipline for attacker-influenceable values; threat model §4.3 independently requires that panic output never carries key material — preserving ADR-0022's panic-isolation and audit-trace guarantees. No detached tasks: every connection the server holds is in the set.
- **Admission control, checked before spawn.** A connection counts as **half-open** from TCP accept until userauth success (the same span the handshake budget covers). Four checks, evaluated in this order — the per-source rate limit (next bullet) first, then the three caps below; the first check that fails names the structured `reason` on the refusal event:
  1. **Global concurrent-connection cap** — default **256**. Bounds file descriptors and per-connection memory regardless of auth state.
  2. **Total half-open cap** — default **100** (OpenSSH's `MaxStartups` hard cap; we adopt the deterministic full-stop value, not the probabilistic early-drop band).
  3. **Per-source half-open cap** — default **10** per source (the `MaxStartups` start-drop point, applied deterministically per source). "Source" is the peer IPv4 address, or the /64 for IPv6 (a single IPv6 host trivially holds a /64; finer granularity would make the cap trivially evadable).
  A connection that fails any check is closed immediately after accept — no version banner is sent — and logged as a new **`connection.refused`** event, emitted inside the ADR-0024 `connection` span (events inherit `peer_addr` from the span, never repeat it as a field) with a structured field naming the limit that was hit. `connection.refused` and `connection.accepted` are mutually exclusive within a connection's span: `connection.accepted` marks admission past all four checks, so a refused connection never emits it. Counting is by RAII guard tied to the connection task, so a panicking handler releases its slots.
- **Per-source accept rate limit: token bucket.** Default **burst 10, refill 1 token/second** per source, same source granularity as above. Implemented first-party (a token bucket is a few dozen lines; per-source state lives in a map pruned when a source's bucket is full and it holds no connections) — no new dependency. These defaults are initial values chosen against OpenSSH prior art, **not yet validated under load**; the §5.1.3 slow-handshake test scenario is the acceptance gate, and tuning a default is a config change, not a re-decision of this ADR.
- **Graceful shutdown.** Add the `signal` feature. This workstream **introduces** the `sync::broadcast` shutdown channel — ADR-0022 described one as already existing in Phase 1 ("driven by tests"), but no broadcast path was ever implemented; the `sync` feature is in use only for the exec layer's mpsc channels (corrected by the ADR-0022 erratum landing with this amendment). On SIGTERM or SIGINT: stop accepting, broadcast shutdown, wait up to a **drain deadline (default 30 s)** for tasks in the `JoinSet` to finish, then abort the remainder (each abort logged as `connection.closed`, reason `shutdown`). A second SIGTERM or SIGINT during the drain skips the remaining deadline and aborts immediately. Exit code is 0 on both the drained and the aborted path — the shutdown completed as commanded; the difference is visible in the per-connection `connection.closed` reasons. The systemd ADR consumes this behaviour; it does not redefine it.
- **Cooperative shutdown, per connection.** The broadcast carries the drain deadline. A connection still in the handshake disconnects immediately. A connection in the channel phase lets the in-flight `exec` run until it exits or the deadline is imminent, then kills the child through the existing owned-`Child` kill path, emits `exec.finished`, completes the close, and returns — the ADR-0023 invariant (every `exec.started` produces an `exec.finished`) **holds on the shutdown path**. The implementation must also preserve that invariant on the abort and panic paths: `exec.finished` is today emitted only on the async happy path, so a drop-guard that emits the owed event is the expected mechanism. With cooperative shutdown in place, the `JoinSet` abort at the deadline is the last resort for a stuck task, not the routine end of long-running commands.
- **Blocking-pool sizing.** Each active `exec` holds up to four `spawn_blocking` tasks (the stdout/stderr/stdin pumps and the reap — `crates/quantumssh-core/src/exec.rs`), so the global connection cap couples to tokio's blocking pool: the default `max_blocking_threads` (512) sits below the default cap's worst case (256 × 4). The binary sizes the runtime with `max_blocking_threads ≥ 4 ×` the configured global cap, so admission control — not thread-pool starvation — is what bounds concurrency. Revisited when the PTY ADR reconsiders `tokio::process` (the ADR-0022 flag).
- **Configuration surface.** All knobs above (three caps, rate limit, drain deadline) are exposed through the RFC-0010 TOML config file; exact key names and shapes belong to that schema, not here. Until the config file lands, interim CLI flags follow the `--handshake-timeout` precedent and are removed when the config file absorbs them.
- **Feature-set delta to ADR-0022's allowlist:** `signal` only, on the `quantumssh` binary — the OS-signal listener fires the shutdown broadcast introduced above. `quantumssh-core` already enables `macros`, so `tokio::select!` in the accept loop needs no delta. The tokio LTS pin (1.51, restored in [#119](https://github.com/gonzafg2/quantumssh/pull/119)) is unchanged and not re-opened here.

## Consequences

### Positive

- The pre-auth availability ceiling accepted in Phase 1 (listener monopolisation by serialised slow handshakes) is closed: slow peers now cost one slot out of 100, not the whole server.
- All three §5.1.3 test handles (rate limits, half-open caps, deadlines) exist, are configurable, and have documented defaults — the threat-model requirement is fully discharged.
- ADR-0022's bet pays out as designed: the per-connection future was born `Send`, so this change is loop-shape and admission logic only; the transport machine is untouched.
- No new dependency: caps use `tokio::sync` primitives already in the feature set, the token bucket and source map are small first-party code (MANIFIESTO #4).

### Negative

- Per-source state is kept in server memory; an adversary rotating source addresses (or /64s) grows the map. The pruning rule bounds steady-state growth, but address-rotation resistance is explicitly **not** claimed — consistent with §8.3's non-DoS posture. Distributed attacks remain the network layer's problem.
- The default caps are judgement calls anchored on OpenSSH's defaults, not on measurements of this server. Until the slow-handshake scenario and real deployments exercise them, they may be too tight for legitimate bursty automation or too loose for small hosts.
- `connection.refused` is a new audit-log event type; it must be in its final shape before the 0.1.0 log-schema freeze ([ADR-0024](0024-phase-1-log-event-schema.md) §Consequences) — one more item on the freeze checklist.
- Commands still running when the drain deadline arrives are killed (cooperatively, with their `exec.finished` emitted). That is the deliberate trade of a bounded shutdown; operators needing longer drains configure a longer deadline.
- An attacker controlling ten or more sources can hold the half-open pool at its cap and deterministically refuse new legitimate connections for the duration of the attack — the saturation behaviour Alternative 4 discusses. Accepted under §8.3; the probabilistic band remains the named revisit if this bites in practice.

### Neutral

- The `exec`-on-`spawn_blocking` model from ADR-0022 is untouched here; the `tokio::process` question stays parked for the PTY ADR, as ADR-0022 flagged.
- Per-target-user rate limiting (threat model §5.3, auth-layer) is out of scope: this ADR is admission control at the connection layer; auth-attempt budgets already exist per connection.

## Alternatives considered

### Alternative 1: unbounded concurrent accept (spawn-and-forget, no caps)

The minimal diff from Phase 1. Rejected: it trades the "one slow peer blocks everyone" failure for "any peer can exhaust descriptors and memory", which is §5.1.3 verbatim. Concurrency without admission control is strictly worse than the sequential loop under attack.

### Alternative 2: a rate-limiting dependency (`governor` or similar)

Mature GCRA implementations exist. Rejected: the need is one token bucket and a map, well under the bar for a new dependency (MANIFIESTO #4, the CLAUDE.md dependency rule); a library would bring an API surface and transitive deps for what is a page of auditable first-party code.

### Alternative 3: delegate limits to the platform (systemd `MaxConnections`-style socket limits, nftables)

Real deployments should also do this, and the systemd ADR may recommend it. Rejected as the *only* mechanism: §5.1.3 requires the limits to be configurable in the server with documented defaults — the binary must be safe when run bare, and per-source half-open accounting (auth-state-aware) is invisible to the network layer.

### Alternative 4: probabilistic early drop (full OpenSSH `MaxStartups` 10:30:100 semantics)

Rejected for now, with the trade-off stated honestly: the probabilistic band is what preserves a nonzero admission probability for legitimate clients near saturation, and deterministic caps do **not** replicate that — an attacker holding ten sources at their per-source cap locks the half-open pool completely, refreshing slots as fast as the handshake timeout frees them. Deterministic caps are chosen anyway because they are exact, testable, and auditable, and full-saturation lockout falls inside the threat model's accepted non-DoS posture (§8.3). Revisit — including adopting the probabilistic band — if real-world contention shows cliff effects.

### Alternative 5: track tasks in a `Vec<JoinHandle>` with manual reaping

What Phase 1's "track the handle instead" comment gestured at. Rejected: manual reaping either leaks completed handles or requires a reap pass on every loop iteration; `JoinSet` is the runtime's purpose-built primitive, already inside the pinned tokio version, and its `join_next()` integrates directly with `select!`.

## Links

- Implementation: TBD — `crates/quantumssh-core/src/server.rs` (accept loop, admission control, shutdown drain), `crates/quantumssh-core/src/channel.rs` and `src/exec.rs` (cooperative shutdown, the `exec.finished` drop-guard), both `Cargo.toml`s (feature delta), the runtime builder in `crates/quantumssh/src/main.rs` (blocking-pool sizing). Paths exist today; the concurrent shapes do not.
- Related ADRs: [ADR-0022](0022-phase-1-async-runtime-tokio.md) (extended by this one), [ADR-0024](0024-phase-1-log-event-schema.md) (`connection.refused` addition; freeze interaction), [ADR-0023](0023-phase-1-channel-layer-scope.md) (un-timed channel phase — why draining needs a deadline).
- Background: [`docs/threat-model.md`](../threat-model.md) §5.1.3 (the three test handles), §8.3 (the non-DoS posture bounding what this ADR claims); [`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md) (workstream map; non-authoritative).
- Prior art: OpenSSH `sshd_config(5)` `MaxStartups` (default `10:30:100`) and `PerSourceMaxStartups` — the anchor for the default cap values.
