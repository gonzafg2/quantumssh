# ADR 0046: Audit-log schema version 1 — the superseded ADR parts, and the binary's own encoder

- **Status:** Accepted
- **Date:** 2026-10-29 (accepted with the implementing PR [#220](https://github.com/gonzafg2/quantumssh/pull/220))
- **Deciders:** Project lead
- **Related:** The superseding ADR [RFC-0014](../rfcs/0014-audit-log-schema-v1.md) §6 requires. It supersedes the parts of [ADR-0024](0024-phase-1-log-event-schema.md), [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md) and [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md) listed in §Decision 1. It also records the implementation choices RFC-0014 §7 left non-normative.

## Context

RFC-0014 fixes the audit log's schema version 1, the public contract
`0.1.0` freezes. It changes decisions that accepted ADRs record. An
accepted ADR changes only through a superseding ADR
([`docs/adr/README.md`](README.md)), so RFC-0014 §6 asks its
implementing PR for one ADR that supersedes the affected parts and is
pointed at from their Status fields.

RFC-0014 §7 sketches the implementation without binding it. Three
choices came up while implementing it:
- the encoder;
- where `peer_addr` comes from;
- which component emits `server.started`, now that it carries
  `config_file`.

## Decision

1. **Superseded parts.**
   - **ADR-0024:**
     - the JSON layout (`tracing-subscriber`'s format, §Decision's
       binary bullet) gives way to RFC-0014 §2's envelope;
     - the audit tier's membership (the "audit tier is not
       operator-suppressible" bullet) grows to the whole RFC-0014 §3
       catalogue, so `server.started`, `server.config_error`,
       `connection.accepted`, `connection.refused`, `connection.closed`
       and `kex.completed` join it;
     - `server.config_error`'s `message` field becomes `class`, `error`
       and `config_file`, `server.started` gains `config_file`, and
       `server.config_override` joins the event table.
   - **ADR-0028:** the admission-control bullet's structured `reason` on
     `connection.refused` is `limit`, the name the code has always
     emitted.
   - **ADR-0029:** the retained-flags bullet's "logged at info" override
     becomes the `server.config_override` audit event. Its `key` is the
     TOML path (`server.listen`, `server.host_key`,
     `auth.authorized_keys`, `server.handshake_timeout`,
     `logging.format`).
2. **The encoder is the binary's own, without `serde_json`.** `JsonV1`
   (`crates/quantumssh/src/log_json.rs`) is a `FormatEvent` that writes
   RFC-0014 §2's line itself.
   - Strings go through one escape that writes `"`, `\` and every
     `char::is_control` character (C0, DEL, C1) as `\u00XX`. That is the
     set §2 requires, wider than `serde_json`'s.
   - Integers and booleans are written as they are. A non-finite float
     becomes a string, since JSON has no NaN.
   - `tracing-subscriber`'s `json` feature is dropped. Five crates leave
     `Cargo.lock` with it: `serde_json`, `tracing-serde`, `itoa`,
     `valuable` and `zmij`.
     RFC-0014 §7's outline had kept `serde_json`, but it would still
     have needed the wider escape around it.
3. **`peer_addr` comes from a span extension.** An unfiltered layer,
   `ConnectionPeer`, records the `connection` span's `peer_addr` in the
   span's extensions when the span is created. The formatter takes it
   from the event's span scope. The audit layer still admits every span
   (ADR-0024), so audit lines carry `peer_addr` under any `RUST_LOG`.
4. **The binary emits `server.started`, after binding.** Only the
   binary knows the configuration file. `Server::bind` no longer emits
   the event. The binary emits it from the bound address, the host key's
   fingerprint and `config_file`, before `READY=1` (ADR-0043).
5. **`server.config_error` classes, by failure:**
   - a `ConfigError` keeps its RFC-0010 class;
   - an unreadable host key after `StrictModes` is `file_unavailable`;
   - a host key or `authorized_keys` that does not load is
     `invalid_host_key` or `invalid_authorized_keys`;
   - a missing one is `missing_setting`;
   - binding, the runtime and the accept loop are `bind_failed`,
     `runtime_failed` and `listener_failed`.

## Consequences

### Positive

- The contract's escaping rule holds by construction, in one function,
  for every string the line carries.
- Five crates leave the dependency tree, and no crate enters it.
- The library keeps emitting through the `tracing` facade only, and no
  configuration notion enters it.

### Negative

- The project maintains the encoder, about 170 lines of code with the
  span layer. Golden tests cover every catalogue event, and an
  end-to-end test runs the built binary.

### Neutral

- The human format is unchanged, and not part of the contract
  (RFC-0014 §1). Catalogue events now show the `audit` target there.

## Alternatives considered

- **`serde_json` with a pre-escape.** Rejected: it keeps five crates
  for a writer that is short, and still needs the extra escape.
- **`config_file` on the library's `Config`.** It would keep
  `server.started` in `Server::bind`. Rejected: the library would carry
  a field it uses only to log.

## Links

- Contract: [RFC-0014](../rfcs/0014-audit-log-schema-v1.md) §2–§6.
- Implementation: `crates/quantumssh/src/log_json.rs`,
  `crates/quantumssh/src/main.rs`, `crates/quantumssh-core/src/server.rs`;
  tests in `log_json.rs` and `crates/quantumssh/tests/audit_log.rs`.
