# ADR 0024: Fix the Phase 1 structured-log event schema

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the first Phase 1 crate lands)
- **Deciders:** Project lead
- **Related:** Realises `docs/threat-model.md` §2.7 (audit record) and its mandated `authenticated_identity` / `executing_uid` fields; makes the §8.12 per-user-UID gap visible in logs; consumes [ADR-0022](0022-phase-1-async-runtime-tokio.md) (the runtime that emits) and [ADR-0023](0023-phase-1-channel-layer-scope.md) (the exec boundary that produces `exec.*` events). Planned implementation (TBD): `tracing` calls in `quantumssh-core`, subscriber init in the `quantumssh` binary. Neither exists yet.

## Context

RFC-0003 and the README commit Phase 1 to "structured logging via `tracing`", and `docs/threat-model.md` §2.7 goes further: it names two fields the audit record **must** carry on every command-execution boundary — `authenticated_identity` (the key fingerprint that authenticated) and `executing_uid` (the OS UID the command actually ran under) — precisely so the §8.12 gap (Phase 1 runs commands as the service account, not a per-user UID) is visible to anyone reading the logs. §6.2 then states that the log schema becomes part of the public interface from Phase 2 onward.

What does not yet exist is the concrete event list: which events Phase 1 emits, what fields each carries, and how the library and binary split the `tracing` responsibility. Without that fixed before code, the mandated fields end up as ad-hoc strings scattered across call sites, impossible to monitor reliably and expensive to stabilise once Phase 2 freezes the schema. This ADR fixes the schema while it is still cheap.

## Decision

Phase 1 emits the following events via `tracing`. Each connection is wrapped in a `tracing` **span** carrying `peer_addr`, so every event below inherits `peer_addr` from its span rather than repeating it as a field.

**Connection-scoped span:** `connection` with field `peer_addr: SocketAddr`.

**Events** (name = `tracing` event target/message; fields are structured `tracing` fields, not interpolated strings):

| Event | Level | Fields (beyond span's `peer_addr`) |
|---|---|---|
| `connection.accepted` | INFO | — |
| `kex.completed` | INFO | `kex_algorithm`, `host_key_algorithm` |
| `auth.succeeded` | INFO | `authenticated_identity`, `auth_method` |
| `auth.failed` | WARN | `auth_method`, `failure_count` |
| `exec.started` | INFO | `authenticated_identity`, `executing_uid`, `command` |
| `exec.finished` | INFO | `authenticated_identity`, `executing_uid`, `exit_status` |
| `connection.closed` | INFO | `reason` |
| `server.started` | INFO | `listen_addr`, `host_key_fingerprint` |
| `server.config_error` | ERROR | `message` |

Field semantics that are load-bearing:

- **`authenticated_identity`** is the SSH key fingerprint that authenticated, formatted as OpenSSH does it: `SHA256:` + base64(SHA-256(key blob)), no padding (e.g. `SHA256:abc123…`). It appears on `auth.succeeded`, `exec.started`, and `exec.finished` so a command is always attributable to the key that authorised it.
- **`executing_uid`** is the numeric OS UID the child process ran under — in Phase 1 always the service-account UID (§8.12, [ADR-0016](0016-phase-1-service-account-uid-model.md)). It is a **first-class field on every `exec.*` event**, distinct from `authenticated_identity`, so the gap between "who authenticated" and "what UID ran" is machine-readable, exactly as §2.7 requires. The two fields being separate is the point; collapsing them would hide the gap.
- **`command`** is recorded verbatim as a structured field (not interpolated into a message string), so a downstream JSON consumer gets it as a discrete value and terminal-escape content in the command cannot corrupt a naive log reader (threat-model §5.4.3).
- **`auth.failed.failure_count`** is per-source (the span's `peer_addr`), **not** per-target-user. Per-user counters are deliberately omitted: on a pubkey-only server they create a user-enumeration oracle (threat-model §5.3.1). Session content is never logged — only this event metadata (§5.4.3, §5.4.4).

**Library / binary split:**

- `quantumssh-core` emits events using only the `tracing` facade (`tracing::{info!, warn!, error!, info_span!}`). It **never** initialises a subscriber and never picks an output format. A library that installs a global subscriber is unusable by any embedder, and Phase 4's client would collide with it.
- The `quantumssh` binary is the **only** place a subscriber is constructed. Phase 1 uses `tracing-subscriber` with `EnvFilter` (honouring `RUST_LOG`) and offers two formats selected at startup: a human-readable default and a `--log-format json` mode (`tracing_subscriber::fmt().json()`) for the one-way-to-an-external-sink shipping that threat-model §5.5.1 and §6.2 describe.
- **Schema versioning starts at Phase 2.** Phase 1's schema is not yet a stability contract (no users exist); the JSON output gains an explicit `schema_version` field when Phase 2 cuts `0.1.0`, per §6.2. This ADR is the input that Phase 2's versioned schema freezes.

## Consequences

### Positive

- The two §2.7-mandated fields are guaranteed present and structurally separate from the first crate, not bolted on later. The §8.12 UID gap is auditable in logs by construction.
- Structured fields (not string interpolation) make the logs JSON-shippable and immune to the terminal-escape log-injection of §5.4.3, and align with the one-way-sink posture of §5.5.1.
- The library/binary split keeps `quantumssh-core` embeddable (Phase 4 client, tests, downstream users) — no global-subscriber landmine.
- Fixing the event list now means Phase 2's schema-freeze has a reviewed starting point rather than whatever emerged ad hoc.

### Negative

- Committing to event names and fields now means a Phase 2 rename is a schema change with a migration note, even though Phase 1 has no users. This is the intended cost of treating the schema as an interface early; the alternative (decide later) is what produces unmonitorable logs.
- `failure_count` being per-source not per-user means an operator cannot see "how many times was *user X* targeted" from these logs. That is a deliberate trade against the enumeration oracle; operators who need per-user views must derive them from `authenticated_identity` on successes, accepting the asymmetry.

### Neutral

- Choosing `tracing` + `tracing-subscriber` is not re-litigated — RFC-0003 and the README already commit to `tracing`, the de facto Rust structured-logging facade. This ADR fixes the *schema*, not the library.
- The human-readable default vs JSON choice is a binary-side startup flag; adding more sinks (OTLP, journald-native) later is a binary concern that does not touch the core's event emission.

## Alternatives considered

### Alternative 1: One `command` event collapsing `authenticated_identity` and `executing_uid`

Simpler: log "user X ran command Y" as a single identity. Rejected: it hides exactly the gap §2.7 exists to surface. In Phase 1 the authenticated identity and the executing UID are *different things* (a key fingerprint vs the service-account UID), and a reader must see both to understand what authority actually ran. The two-field separation is mandated, not stylistic.

### Alternative 2: Interpolate fields into human-readable message strings

`info!("{peer} ran {command}")` is the path of least resistance. Rejected: it defeats JSON shipping (the consumer gets a string to re-parse), and it routes attacker-influenced content (`command`) into a message that a naive `cat` of the log renders with live terminal escapes (§5.4.3). Structured fields close both.

### Alternative 3: Initialise the subscriber inside `quantumssh-core`

Convenient for tests and examples. Rejected: a library that installs a global `tracing` subscriber cannot be embedded (the Phase 4 client, integration harnesses, and any downstream consumer would fight it for the global default). Subscriber init belongs to the binary; the library only emits.

### Alternative 4: Add `schema_version` and freeze the schema in Phase 1

Treat the schema as stable immediately. Rejected as premature: Phase 1 has no consumers, and freezing now would force a version bump for every exploratory change during implementation. §6.2 already scopes the stability contract to Phase 2; this ADR feeds that, rather than pre-empting it.

## Links

- Implementation: TBD — `tracing` event/span calls throughout `quantumssh-core`; `tracing-subscriber` init in `quantumssh/src/main.rs`. Neither exists yet.
- Related ADRs: [ADR-0016](0016-phase-1-service-account-uid-model.md) (the service-account UID that `executing_uid` records), [ADR-0022](0022-phase-1-async-runtime-tokio.md) (runtime), [ADR-0023](0023-phase-1-channel-layer-scope.md) (the exec boundary producing `exec.*`).
- Threat model: §2.7 (audit record and the mandated fields), §5.3.1 (why `failure_count` is per-source), §5.4.3 / §5.4.4 (no session content; escape-safe metadata), §5.5.1 (one-way sink, JSON shipping), §6.2 (schema as public interface from Phase 2), §8.12 (the UID gap this schema makes visible).
- Standards / conventions: OpenSSH key-fingerprint format (`SHA256:` base64, unpadded) for `authenticated_identity`; [`tracing`](https://docs.rs/tracing) and [`tracing-subscriber`](https://docs.rs/tracing-subscriber) as the emission and subscriber layers.
