# ADR 0044: Freeze the audit-log schema as version 1, in a project-owned JSON envelope

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-13)
- **Deciders:** Project lead
- **Related:** The first item of the `0.1.0` freeze checklist ([`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md); [#109](https://github.com/gonzafg2/quantumssh/issues/109)). Freezes the schema [ADR-0024](0024-phase-1-log-event-schema.md) calls "the input that Phase 2's versioned schema freezes", with the events and fields added since by [ADR-0026](0026-phase-1-rekeying-policy.md) (`rekey.completed`), [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md) (`connection.refused`) and [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §9 (`request_type`, `pty`). Supersedes in part ADR-0024's JSON format, its audit-tier membership and the `message` field of `server.config_error` (§4 below). Realises threat model §2.7, §5.5.1 and §6.2 ("schema-versioned"). The `peer_addr` fix it relies on is [#202](https://github.com/gonzafg2/quantumssh/pull/202).

## Context

Cutting `0.1.0` turns the audit log into a public compatibility
contract. Threat model §5.5.1 makes format stability "part of the
public interface from Phase 2 onward", so that log-shipping
configurations do not silently break. §6.2 restates it as
"schema-versioned". ADR-0024 fixed the Phase-1 events and deferred the
version: "the JSON output gains an explicit `schema_version` field when
Phase 2 cuts `0.1.0`".

An inventory of what the server emits today (`main` at `312598c`,
checked with a real OpenSSH session) shows that the current JSON cannot
simply be frozen as it is:

- **The layout belongs to a dependency.** Each line is
  `tracing-subscriber` 0.3's JSON format:
  `{"timestamp","level","fields":{"message":<event>,…},"target","span","spans"}`.
  Freezing it would freeze another crate's output, and that crate's
  next major release is free to change it.
- **Internal names leak.** `target` is the Rust module path for every
  event outside the audit tier (`"quantumssh_core::server"`), so a
  module rename would change the contract. `span.name` and the
  duplicated `spans` list are the same kind of internal detail.
- **One record is not valid JSON in practice.** `server.config_error`
  carries a field named `message` (ADR-0024's table), which collides
  with the `message` key `tracing` uses for the event name. The object
  holds `"message"` twice, and the common parsers keep only the last
  value, so the event name is lost:
  `{"fields":{"message":"server.config_error","message":"file_unavailable: …"}}`.
- **The audit tier is not the whole audit record.** ADR-0024 puts only
  `auth.*`, `exec.*` and `kex.failed` on the non-suppressible `audit`
  target (`rekey.completed` joined later). `connection.*`,
  `kex.completed`, `server.started` and `server.config_error` go
  through `RUST_LOG`, so `RUST_LOG=warn` drops every connection record.
  Threat model §2.7, however, lists "connection acceptance … session
  lifecycle events … configuration load" as audit content.
- **Audit records lost their source.** The audit layer filtered out the
  `connection` span, so audit events carried no `peer_addr`, against
  ADR-0024. That is a bug, fixed in #202. The envelope below depends on
  that fix.
- **There is no place for the version.** `tracing-subscriber`'s JSON
  format has no hook that adds a key to every record.

## Decision

We will make the JSON log a project-owned, versioned format, with
`schema_version: 1` on every record. Every event in a fixed catalogue
goes on the non-suppressible audit tier, and explicit rules define
which changes need a new version. The human-readable format is not
part of the contract.

### 1. Scope of the contract

- **Covered:** the JSON output. That is the default whenever stderr is
  not a terminal, and the format threat model §5.5.1 ships.
- **Not covered:** the human-readable format. It is for terminals and
  may change in any release.
- **Covered within the JSON:** the envelope (§2) and the catalogue
  events (§3).
- **Not covered:** diagnostic records, the free-text lines outside the
  catalogue such as `shutdown signal received; draining`. They share
  the envelope, but their text and fields may change in any release,
  and consumers must not parse them.

### 2. The envelope

Each record is one JSON object on one line, with these keys:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `schema_version` | integer | always | `1` for this ADR |
| `timestamp` | string | always | RFC 3339, UTC, microseconds, `Z` suffix (as today) |
| `level` | string | always | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE` |
| `event` | string | catalogue records only | the event name of §3 |
| `message` | string | diagnostic records only | free text, not part of the contract |
| `peer_addr` | string | records emitted inside a connection | the client's `IP:port`, from the `connection` span |
| *event fields* | per §3 | per §3 | at the top level, next to the keys above |

Five rules govern the envelope:

- **`event` and `message` are exclusive.** A record carries exactly one
  of them, so a consumer selects the contract with `has("event")`.
- **Event fields are flat.** They sit at the top level, not nested
  under `fields`. No event field may reuse an envelope key name.
- **No internal names.** There is no `target`, no span name and no
  span list.
- **No escape sequences survive.** Control bytes in string values are
  escaped by the JSON encoder, as today (threat model §5.4.3).
- **One encoder.** The binary owns the formatter: a `FormatEvent`
  implementation for `tracing-subscriber`'s `fmt` layer, encoding with
  `serde_json`. `serde_json` is already in the build through
  `tracing-subscriber`'s `json` feature, so making it a direct
  dependency adds nothing to the tree. The library keeps emitting
  through the `tracing` facade only (ADR-0024).

### 3. The version-1 catalogue

Every catalogue event is emitted on the `audit` target, the tier
whose filter is compiled in and that no `RUST_LOG` directive reaches
(ADR-0024). Six events move onto it here: `server.started`,
`server.config_error`, `connection.accepted`, `connection.refused`,
`connection.closed` and `kex.completed`. `RUST_LOG` then governs
diagnostic records only.

| Event | Level | `peer_addr` | Fields |
|---|---|---|---|
| `server.started` | INFO | no | `listen_addr` (string), `host_key_fingerprint` (string) |
| `server.config_error` | ERROR | no | `error` (string, free text) |
| `connection.accepted` | INFO | yes | — |
| `connection.refused` | INFO | yes | `limit` (open enumeration: `max_connections`, `max_half_open`, `max_per_source`, `accept_rate`) |
| `connection.closed` | INFO | yes | `reason` (string, free text) |
| `kex.completed` | INFO | yes | `kex_algorithm` (string), `host_key_algorithm` (string) |
| `kex.failed` | WARN | yes | `reason` (open enumeration of kebab-case tokens: `no-hybrid-kex`, `no-strict-kex`, …), `disconnect_code` (integer) |
| `rekey.completed` | INFO | yes | `kex_algorithm`, `host_key_algorithm` (strings), `initiator` (`server` or `peer`), `trigger` (`time`, `bytes` or `peer`), `bytes_rx`, `bytes_tx`, `seconds` (integers) |
| `auth.succeeded` | INFO | yes | `authenticated_identity` (string), `auth_method` (string) |
| `auth.failed` | WARN | yes | `auth_method` (string), `failure_count` (integer) |
| `exec.started` | INFO | yes | `authenticated_identity` (string), `executing_uid` (integer), `command` (string), `request_type` (open enumeration: `exec`, `shell`), `pty` (boolean) |
| `exec.finished` | INFO | yes | the five `exec.started` fields, plus `exit_status` (integer) |

Field semantics that are load-bearing:

- **Unchanged from ADR-0024 and its amendments.** This covers
  `authenticated_identity` (`SHA256:` and unpadded base64),
  `executing_uid` as a separate first-class field (§2.7, §8.12),
  `command` verbatim, and `failure_count` per source.
- **Every listed field is always present on its event.** None is
  omitted when empty: `command` is `""` for a shell (ADR-0038 §9).
- **Open enumerations may gain values** in a later release (§5).
  `request_type` gains `subsystem` with SFTP (ADR-0041), for example.
- **Free-text fields** (`error`, and `reason` on `connection.closed`)
  carry error detail for people. They are not stable values to match
  on.

### 4. What changes against ADR-0024 and its amendments

- **The JSON layout:** from `tracing-subscriber`'s format to the
  envelope of §2.
- **`server.config_error`:** its `message` field becomes `error`, which
  ends the duplicate key.
- **The audit tier:** gains the six events listed in §3.

The events, their names and every other field are unchanged. When this
ADR is accepted, ADR-0024's Status gains a pointer to it, as it did for
ADR-0038.

### 5. Compatibility rules for version 1

**Additive changes keep `schema_version` 1.** Consumers must accept
them:

- a new catalogue event;
- a new field on an existing event;
- a new value of an open enumeration;
- any change to diagnostic records.

The SFTP stack already planned before the tag adds exactly such
changes: `request_type` `subsystem`, and `bytes_received` and
`bytes_sent` on `exec.finished` (ADR-0041, ADR-0042).

**Breaking changes require `schema_version` 2.** Each one also needs
a new ADR and a migration note in the CHANGELOG:

- removing or renaming an event or a field;
- changing a field's type, unit or meaning;
- making a listed field conditional;
- changing an envelope key or the timestamp format;
- moving an event off the audit tier.

**Consumers** must ignore keys and events they do not know, and must
select the contract by `event`, never by `message`.

### 6. Implementation

The implementing PR flips this ADR to `Accepted`. It does five things:

- **The formatter:** `crates/quantumssh/src/log_json.rs`, wired in
  `init_logging` for `LogFormat::Json`.
- **The tier moves:** the six events in `quantumssh-core` and the
  binary get `target: "audit"`.
- **The rename:** `server.config_error` gets `error = …`.
- **Golden tests:** one per catalogue event, each pinning the exact
  key set of its JSON line, plus one diagnostic record without
  `event`.
- **Docs:** the operator guide's log section, the CHANGELOG, and the
  threat-model §6.2 wording, which then names the version.

## Consequences

### Positive

- **Shippers get a contract they can test.** One flat object per line
  carries its own version, and a stable `event` key separates the
  contract from diagnostics.
- **A dependency upgrade cannot change the format.** The format no
  longer depends on `tracing-subscriber`'s layout or on Rust module
  paths.
- **§2.7's whole audit record survives any `RUST_LOG` setting.**
  Connection acceptance, refusal and closure, and configuration
  outcomes are no longer suppressible.
- **The duplicate-key record is gone.**
- **The compatibility rules let the SFTP fields and later additions
  land without a version bump.**

### Negative

- **The project maintains a formatter,** about a hundred lines with
  their tests, instead of using the library's.
- **Existing JSON consumers must adapt once:** `fields.message` becomes
  `event`, and `span.peer_addr` becomes `peer_addr`. Pre-alpha has no
  known consumers, and this is the reason to do it before the tag.
- **Six more events are always on.** A busy server writes three more
  lines per connection that `RUST_LOG` cannot turn off:
  `connection.accepted`, `kex.completed` and `connection.closed`.
- **Two fields are free text,** `connection.closed`'s `reason` and
  `server.config_error`'s `error`. A stable cause enumeration would
  need a later, additive field.

### Neutral

- **The human-readable format and `RUST_LOG`'s behaviour on
  diagnostics do not change.**
- **Values evolve without breaking the schema.** The host-key
  algorithm and fingerprint values change with RFC-0012's cut-over,
  but these are values of existing string fields.

## Alternatives considered

### Alternative 1: freeze `tracing-subscriber`'s JSON layout as it is

This would need the least code. But it freezes a dependency's output
and the Rust module paths in `target`. It keeps the duplicate
`message` key unless the field is renamed anyway. It also offers no
per-record hook for `schema_version`, short of repeating the field in
every event macro. Rejected.

### Alternative 2: `tracing-subscriber`'s `flatten_event` option, with the version in `server.started` only

This removes the `fields` nesting with a setting. But a version
recorded once per process does not travel with records that a shipper
splits, samples or reorders. `target` and the span list would remain
as well. Rejected.

### Alternative 3: a `major.minor` version

The minor number would count additive changes, which consumers must
tolerate anyway under §5. A single integer that moves only on breaking
changes says what a consumer needs to know. Rejected.

### Alternative 4: keep the two tiers as ADR-0024 drew them

`RUST_LOG=warn` would keep dropping connection records that §2.7
counts as audit content. Rejected.

### Alternative 5: also freeze the human-readable format

It is a terminal format with escaped control bytes (ADR-0024), not a
shipping format, and freezing it would constrain readability for no
consumer. Rejected.

## Links

- **Implementation:** TBD (the PR that flips this ADR); the `peer_addr`
  fix it relies on is #202.
- **Related decisions:**
  - ADR-0024, the schema this ADR freezes;
  - ADR-0026, `rekey.completed`;
  - ADR-0028, `connection.refused` and the freeze checklist item;
  - ADR-0038 §9, `request_type` and `pty`;
  - ADR-0041 and ADR-0042, additive fields due before the tag.
- **Threat model:**
  - §2.7, audit record content;
  - §5.4.3, escaping;
  - §5.5.1, the one-way sink and format stability;
  - §6.2, "schema-versioned";
  - §8.12, `executing_uid`.
- **Inventory:** `main` at `312598c`. The quoted lines come from a real
  session with OpenSSH 10.3 against the release binary.
