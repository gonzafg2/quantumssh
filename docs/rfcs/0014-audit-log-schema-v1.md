# RFC 0014: Audit-log schema version 1 — a project-owned, versioned JSON contract

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-10-13 (drafted as ADR-0044; moved to the RFC lane on 2026-10-14)
- **Roadmap issue:** [#109](https://github.com/gonzafg2/quantumssh/issues/109)
- **Implementation PR:** TBD

## Summary

Cutting `0.1.0` turns the audit log into a public compatibility
contract. This RFC defines that contract as **schema version 1**:

- **The envelope.** Each record is one flat JSON object per line that
  carries `schema_version`. The project owns the layout, not
  `tracing-subscriber`.
- **The catalogue.** It lists every event and its fields, and it puts
  every catalogue event on the audit tier, which `RUST_LOG` cannot
  reach.
- **The rules.** They say which changes keep version 1 and which need
  version 2.

The RFC refines three accepted decisions so that they fit one contract:

- ADR-0024's log format and audit-tier membership, and ADR-0028's
  refusal field name;
- RFC-0010's statement that configuration-error classes are values of
  the `message` field;
- RFC-0008's statement about what `authenticated_identity` records for
  certificates.

It is the first item of the `0.1.0` freeze checklist
([`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md)).

## Motivation

Threat model §5.5.1 makes the format stability of the log schema "part
of the public interface from Phase 2 onward", so that log-shipping
configurations do not silently break. §6.2 restates it as
"schema-versioned". [ADR-0024](../adr/0024-phase-1-log-event-schema.md)
fixed the Phase-1 events and deferred the version: "the JSON output
gains an explicit `schema_version` field when Phase 2 cuts `0.1.0`".

An inventory of what the server emits on `main` at `312598c`, checked
with a real OpenSSH 10.3 session against the release binary, shows that
today's JSON cannot be frozen as it is:

- **The layout belongs to a dependency.** Each line is
  `tracing-subscriber` 0.3's JSON format:
  `{"timestamp","level","fields":{"message":<event>,…},"target","span","spans"}`.
  Freezing it would freeze another crate's output, and that format
  offers no hook to add a key to every record. Its only options are
  `flatten_event`, `with_current_span` and `with_span_list`.
- **Internal names leak.** `target` is a Rust module path
  (`quantumssh_core::server`) for every event outside the audit tier,
  so renaming a module would change the contract.
- **One record holds the same key twice.** `server.config_error` has a
  field named `message`, which collides with the key `tracing` uses for
  the event name:
  `{"fields":{"message":"server.config_error","message":"file_unavailable: …"}}`.
  The common parsers keep the last value, so the event name is lost.
- **`RUST_LOG=warn` drops whole parts of the audit record.** ADR-0024's
  audit tier holds `auth.*`, `exec.*` and `kex.failed`
  (`rekey.completed` joined it later). `connection.*`, `kex.completed`,
  `server.started` and `server.config_error` go through `RUST_LOG`, but
  threat model §2.7 lists "connection acceptance … session lifecycle
  events … configuration load" as audit content.
- **A successful configuration load leaves no record.** `server.started`
  looks the same with or without `--config`.
- **Two audit gaps, both bugs against ADR-0024, are fixed separately:**
  - audit events carried no `peer_addr`, fixed in
    [#202](https://github.com/gonzafg2/quantumssh/pull/202);
  - the failed attempt that exhausts the authentication budget emitted
    no `auth.failed`, fixed in
    [#204](https://github.com/gonzafg2/quantumssh/pull/204).

Freezing is one-way. Every gap left now becomes a version-2 change
later.

## Guide-level explanation

A shipper or SIEM reads one JSON object per line. A catalogue record
looks like this:

```json
{"schema_version":1,"timestamp":"2026-10-13T06:19:29.010619Z","level":"INFO","event":"exec.started","peer_addr":"192.0.2.7:50022","authenticated_identity":"SHA256:cp4BNirSzGclLcIrv4GSoYcZD47+bqGl0GdHc/vPJE8","executing_uid":993,"command":"echo hi","request_type":"exec","pty":false}
```

A diagnostic record, which is not part of the contract, carries
`message` instead of `event`:

```json
{"schema_version":1,"timestamp":"2026-10-13T06:20:01.000000Z","level":"INFO","message":"shutdown signal received; draining","drain_seconds":30}
```

A consumer selects the contract with `has("event")`, ignores keys and
events it does not know, and checks `schema_version` before it
interprets fields. The events, their fields and the rules for change
are below. Every catalogue event is always written, whatever
`RUST_LOG` says. `RUST_LOG` governs diagnostics only.

## Reference-level explanation

### 1. Scope of the contract

- **The contract covers the JSON output.** That is the default whenever
  stderr is not a terminal, and it is the format threat model §5.5.1
  ships.
- **The human-readable format is not part of the contract.** It is for
  terminals, and its control-byte escaping (ADR-0024) stays.
- **Diagnostic records share the envelope but are not part of the
  contract.** Their text and fields may change in any release.

### 2. The envelope

Each record is one JSON object on one line:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `schema_version` | integer | always | `1` |
| `timestamp` | string | always | RFC 3339, UTC, microseconds, `Z` suffix |
| `level` | string | always | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE` |
| `event` | string | catalogue records only | the event name (§3) |
| `message` | string | diagnostic records only | free text |
| `peer_addr` | string | records emitted inside a connection | the client's address, `IP:port`, or `[IPv6]:port` |
| *event fields* | per §3 | per §3 | at the top level, next to the keys above |

Five rules govern the envelope:

- **`event` and `message` are exclusive.** A record carries exactly
  one of them.
- **Event fields sit at the top level.** No event field may reuse an
  envelope key name.
- **No internal names.** There is no `target`, no span name and no
  span list.
- **Control bytes are escaped.** The JSON encoder escapes them in
  string values (threat model §5.4.3).
- **One encoder.** The binary owns the encoder (§7). The library keeps
  emitting through the `tracing` facade only (ADR-0024).

### 3. The version-1 catalogue

Every catalogue event is emitted on the `audit` target. That tier's
filter is compiled in, and no `RUST_LOG` directive reaches it
(ADR-0024).

| Event | Level | `peer_addr` | Fields |
|---|---|---|---|
| `server.started` | INFO | no | `listen_addr` (string), `host_key_fingerprint` (string), `config_file` (string) |
| `server.config_override` | INFO | no | `key` (enumeration: the config key a command-line flag overrode) |
| `server.config_error` | ERROR | no | `class` (enumeration, §4), `error` (string, free text), `config_file` (string) |
| `connection.accepted` | INFO | yes | — |
| `connection.refused` | INFO | yes | `limit` (enumeration: `max_connections`, `max_half_open`, `max_per_source`, `accept_rate`) |
| `connection.closed` | INFO | yes | `reason` (string, free text) |
| `kex.completed` | INFO | yes | `kex_algorithm`, `host_key_algorithm` (strings) |
| `kex.failed` | WARN | yes | `reason` (enumeration of kebab-case tokens: `no-hybrid-kex`, `no-strict-kex`, …), `disconnect_code` (integer) |
| `rekey.completed` | INFO | yes | `kex_algorithm`, `host_key_algorithm` (strings), `initiator` (enumeration: `server`, `peer`), `trigger` (enumeration: `time`, `bytes`, `peer`), `bytes_rx`, `bytes_tx`, `seconds` (integers) |
| `auth.succeeded` | INFO | yes | `authenticated_identity` (string), `auth_method` (string) |
| `auth.failed` | WARN | yes | `auth_method` (string), `failure_count` (integer) |
| `exec.started` | INFO | yes | `authenticated_identity` (string), `executing_uid` (integer), `command` (string), `request_type` (enumeration: `exec`, `shell`), `pty` (boolean) |
| `exec.finished` | INFO | yes | the five `exec.started` fields, plus `exit_status` (integer) |

### 4. Field semantics

- **Presence.** Every field listed in §3 is always present on its
  event. `command` is `""` for a shell (ADR-0038 §9). Only a field added
  after version 1 may be conditional, and only if the change that adds
  it says so (§5).
- **`config_file`** names the configuration file the server was started
  with: its canonical path once StrictModes resolved it, the path as
  given when that failed, or `""` without `--config`. It is on
  `server.started` and on every `server.config_error`. A failure after a
  successful load, such as a bad host key or a taken port, therefore
  still names the configuration that produced it, with no
  `server.started` to pair it with.
- **Enumerations are open.** A consumer must accept values it does not
  know.
- **`authenticated_identity`** is `SHA256:` followed by the unpadded
  base64 SHA-256 of the public key the client proved possession of
  (ADR-0024). The field and `executing_uid` stay separate first-class
  fields (§2.7, §8.12).
- **`failure_count`** counts failed authentication requests within one
  connection, and it starts again at 1 on a new connection.
  - **Every failure emits `auth.failed`,** the one that exhausts the
    attempt budget included (#204).
  - **Detecting repeated attempts across connections** means grouping
    `auth.failed` by the IP part of `peer_addr`.
- **`server.config_error`'s `class`** is one of these values:
  - RFC-0010's four classes: `file_unavailable`, `schema_error`,
    `version_unsupported` and `insecure_permissions`;
  - `missing_setting`: the host key or `authorized_keys` was not
    given;
  - `invalid_host_key` and `invalid_authorized_keys`: the file was
    read but could not be loaded;
  - `bind_failed`, `runtime_failed` and `listener_failed`.

  `error` carries the detail for people, naming the file and predicate
  as RFC-0010 requires.
- **`server.config_override`** is emitted once per command-line flag
  that overrides a value the config file set (RFC-0010's precedence).
  Together with `config_file`, it records which configuration the
  server loaded (§2.7).
- **Free-text fields** are `connection.closed`'s `reason` and
  `server.config_error`'s `error`. They carry detail for people, and
  consumers must not match on them.

### 5. Compatibility rules for version 1

**Additive changes keep `schema_version` 1.** Consumers must accept
them:

- a new catalogue event;
- a new field on an existing event, conditional only if the change
  that adds it says so;
- a new value of an enumeration;
- any change to diagnostic records.

Two planned changes fall in this class:

- **The SFTP stack** proposed in
  [#194](https://github.com/gonzafg2/quantumssh/pull/194) and
  [#195](https://github.com/gonzafg2/quantumssh/pull/195) (TBD). It
  adds `request_type` `subsystem`, and `bytes_received` and
  `bytes_sent` on `exec.finished`.
- **Certificate authentication** (RFC-0008, TBD). It adds the
  certificate fields, which are present on certificate authentications
  only (§6).

**Breaking changes require `schema_version` 2.** Each one needs its own
RFC, and a migration note in the CHANGELOG:

- removing or renaming an event or a field;
- changing a field's type, unit or meaning;
- making a version-1 field conditional;
- changing an event's `level`;
- changing an envelope key or the timestamp format;
- moving an event off the audit tier.

**Consumers** ignore keys and events they do not know, and select the
contract by `event`, never by `message`.

### 6. Changes to accepted decisions

When this RFC is accepted, each affected document gains a Status
pointer to it.

- **[ADR-0024](../adr/0024-phase-1-log-event-schema.md):**
  - the JSON layout becomes §2;
  - the six events `server.started`, `server.config_error`,
    `connection.accepted`, `connection.refused`, `connection.closed`
    and `kex.completed` join the audit tier;
  - `server.config_error`'s `message` becomes `class` plus `error`;
  - `server.started` and `server.config_error` gain `config_file`, and
    `server.config_override` joins the catalogue;
  - `exec.finished` lists `command`, which the code has emitted since
    `a3921d5` but ADR-0024's row omitted. An erratum is proposed for
    that in [#196](https://github.com/gonzafg2/quantumssh/pull/196).
- **[ADR-0028](../adr/0028-phase-2-concurrent-connections-limits-graceful-shutdown.md)**
  calls the `connection.refused` field `reason`. The code has always
  emitted `limit`, whose values match the `[limits]` config keys
  (`admission.rs`). Version 1 keeps `limit`.
- **[RFC-0010](0010-configuration-file.md)** §"Failure modes" calls its
  four classes "values of the `message` field". They become values of
  `class`, with the same names and meanings.
- **[RFC-0008](0008-ssh-certificate-authentication.md)** §"Type-state
  and audit" says `authenticated_identity` "must record the certificate
  identity".
  - **`authenticated_identity` stays the fingerprint of the key whose
    possession was proven.** For a certificate, that is the certified
    key.
  - **Certificate fields are additive.** The certificate's identity
    (key ID, serial, CA fingerprint and principal) is recorded by
    those fields, which RFC-0008's implementing ADR names.
  - **Consumers keep one format.** A consumer keyed on
    `authenticated_identity` sees one format for every authentication.

### 7. Implementation outline (non-normative)

This RFC needs no separate ADR. Its implementing PR does six things:

- **The formatter:** a `FormatEvent` for `tracing-subscriber`'s `fmt`
  layer, in the binary, that writes §2's envelope.
  - **Encoding:** `serde_json`, already in the build through
    `tracing-subscriber`'s `json` feature, becomes a direct dependency
    with no new crate in the tree.
  - **`peer_addr`:** taken from the `connection` span's recorded fields.
- **The tier moves:** the six events move to the audit target.
- **The new fields:** `server.started` gains `config_file`;
  `server.config_override` replaces the override diagnostic; and
  `server.config_error` gains `class`, `error` and `config_file`.
- **Golden tests:** one per catalogue event, each pinning the exact key
  set of its line, plus one diagnostic line.
- **The flip:** the PR flips this RFC to Accepted and adds the Status
  pointers of §6.
- **Docs:** the operator guide's log section, the CHANGELOG, and the
  threat-model §6.2 wording, which then names the version.

## Drawbacks

- **The project maintains a formatter,** about a hundred lines with
  their tests, instead of using the library's.
- **Existing JSON consumers must adapt once.** `fields.message` becomes
  `event`, `span.peer_addr` becomes `peer_addr`, and
  `server.config_error` splits into `class` and `error`. Pre-alpha has
  no known consumers, and this is the reason to do it before the tag.
- **More events are always on.** Each connection writes three more
  lines that `RUST_LOG` cannot turn off: `connection.accepted`,
  `kex.completed` and `connection.closed`. Startup writes
  `server.config_override` once per overridden key.
- **Two fields stay free text.** A stable cause enumeration for
  `connection.closed`, or a `protocol.violation` event for post-KEX
  protocol errors, would be a later additive change.

## Rationale and alternatives

### Alternative 1: freeze `tracing-subscriber`'s JSON layout as it is

This would need the least code. But it freezes a dependency's output
and the Rust module paths in `target`. It keeps the duplicate
`message` key unless the field is renamed anyway. It also offers no
per-record hook for `schema_version`, short of repeating the field in
every event macro.

### Alternative 2: `flatten_event`, with the version in `server.started` only

A version recorded once per process does not travel with records that
a shipper splits, samples or reorders. `target` and the span list
would remain as well.

### Alternative 3: a `major.minor` version

The minor number would count additive changes, which consumers must
tolerate anyway under §5. A single integer that moves only on breaking
changes says what a consumer needs to know.

### Alternative 4: keep ADR-0024's two tiers

`RUST_LOG=warn` would keep dropping the connection and configuration
records that §2.7 counts as audit content.

### Alternative 5: make `authenticated_identity` the certificate identity

This is RFC-0008's literal wording. The field would then change format
with the authentication method, and a consumer keyed on it would break
when certificates arrive. Separate, additive certificate fields record
the same information and keep one format.

### Alternative 6: keep the configuration-error class inside a free-text field

This is RFC-0010's `class: detail` prefix. Consumers would have to
parse a string to get a value the contract can carry as its own field.

## Prior art

- **Kubernetes audit events** carry `apiVersion` (`audit.k8s.io/v1`)
  on every event.
- **AWS CloudTrail records** carry `eventVersion` on every record.
- **The Elastic Common Schema** carries `ecs.version` per document.

In all three the version travels with each record, as in §2, because
shippers handle records one at a time. OpenSSH writes unstructured
syslog text, which is the situation a contract avoids.

## Unresolved questions

- **The certificate field names** are left to RFC-0008's implementing
  ADR. They are additive under §5.
- **Post-KEX protocol violations** stay diagnostics in version 1. A
  `protocol.violation` catalogue event is a possible additive change.
- **`connection.closed`'s `reason`** stays free text. A stable cause
  enumeration is a possible additive field.

## Future possibilities

- **New catalogue events**, all additive: `server.stopping` and
  `server.stopped` for the server lifecycle, and `protocol.violation`.
- **Other sinks,** such as journald-native or OTLP. They would be
  binary concerns that encode the same catalogue.
