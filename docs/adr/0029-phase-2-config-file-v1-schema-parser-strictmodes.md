# ADR 0029: Configuration file v1 — schema, parser crate, and StrictModes startup checks

- **Status:** Proposed
- **Date:** TBD (advances to Accepted when the implementing PR merges)
- **Deciders:** Project lead
- **Related:** Implements [RFC-0010](../rfcs/0010-configuration-file.md) (the shape: TOML, schema-versioned, fail-closed, restart-time, `CLI > config > default`); this ADR locks the operative details the RFC left open — exact keys, value grammars, the parser crate, the retained flag set, and the permission-check implementation. Constrained by [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md) (`unsafe_code = "forbid"` — checks go through `rustix`) and [ADR-0024](0024-phase-1-log-event-schema.md) (failure modes are `server.config_error` messages, no new event names). Part of the Phase-2 milestone ([#109](https://github.com/gonzafg2/quantumssh/issues/109)).

## Context

RFC-0010 decided *that* QuantumSSH adopts a TOML configuration file and fixed its
shape, deferring to an implementing ADR: the exact key set, section boundaries,
value grammars, the TOML crate (chosen against `cargo deny` at implementation
time), whether the config is required, and the retained CLI flag set. The freeze
pressure is real — at `0.1.0` the schema becomes a public compatibility contract —
so v1 must be the minimum that is right, not a speculative superset
([RFC-0007](../rfcs/0007-cryptographic-primitive-migration-procedure.md)'s
warning, quoted by the RFC).

## Decision

We will implement RFC-0010 as follows.

- **Schema v1 covers exactly today's surface** — the five Phase-1 flags, no more:

  ```toml
  schema_version = 1            # mandatory, integer

  [server]
  listen            = "127.0.0.1:2222"   # string, parsed as SocketAddr
  host_key          = "/etc/quantumssh/ssh_host_ed25519_key"   # path string
  handshake_timeout = 30                 # integer seconds

  [auth]
  authorized_keys   = "/etc/quantumssh/authorized_keys"        # path string

  [logging]
  format = "json"               # "json" | "human"
  ```

  Every key is optional; defaults are the Phase-1 defaults. `host_key` and
  `authorized_keys` must still come from *somewhere* (flag or config) for the
  server to start, exactly as today. The deferred Phase-2 policy — `[limits]`
  ([ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md)),
  `[session].accept_env` (the ADR-0023 successor), `[auth].trusted_user_ca_keys`
  ([RFC-0008](../rfcs/0008-ssh-certificate-authentication.md)) — is **not** in v1:
  each feature's implementing PR adds its keys when the feature exists, before the
  `0.1.0` freeze. Under the fail-closed rule a config naming them earlier refuses
  to start, which is correct — a directive the binary cannot enforce must never be
  silently accepted.
- **Value grammars: no bespoke parsing.** Durations are **integer seconds**
  (matching the existing `--handshake-timeout <SECS>`), not `"30s"` strings — a
  duration grammar is parser surface with no expressiveness gain at this scale,
  and the type of a shipped key can never change, so this is decided once, now.
  Paths and the listen address are TOML strings, parsed with the same `std`
  parsers the flags already use.
- **Parser crate: `basic-toml`, with `serde` derive.** `serde` is already in the
  binary's build graph (`tracing-subscriber`'s JSON output), so the lockfile
  delta is **one crate**. `basic-toml` (a maintained, serde-only fork of `toml`
  0.5) has no further dependencies — the full `toml` crate would add `winnow`,
  `indexmap`, `toml_datetime`, and `serde_spanned` for span-quality we do not
  need. Config structs derive `Deserialize` with `deny_unknown_fields` on every
  section — the RFC's fail-closed unknown-key rule comes from the deserializer,
  not hand-rolled key checks — and `basic-toml`'s errors carry line/column for
  the `schema_error` message. Verified against `cargo deny` in the implementing
  PR.
- **`schema_version` handling.** Mandatory; the binary accepts exactly `1` in v1.
  Anything else refuses to start (`version_unsupported`). The
  accepted-versions set widens only when a future schema change documents its
  compatibility rule, per the RFC.
- **Retained flags: all five, plus `--config <PATH>`.** `--listen`, `--host-key`,
  `--authorized-keys`, `--handshake-timeout`, `--log-format` all remain, as
  overrides (`CLI > config > default`); existing invocations keep working
  unchanged. The config file is **optional** (the RFC's optional-but-primary
  recommendation): no `--config` means flags-and-defaults, as today. An
  explicitly-passed `--config` whose file is missing is a refuse-to-start, not a
  silent fallback. A flag overriding a set config key is logged at info, per the
  RFC's failure-mode table.
- **StrictModes checks, first-party over `rustix`.** The full RFC predicate set,
  implemented with `rustix::fs::stat`/`statat` (already in the tree, no new
  dependency, `unsafe`-free):
  - *Integrity*, for the config file, `authorized_keys`, and the host key: not
    group/world-writable; owned by root or the process UID; no group/world-writable
    ancestor directory up to the filesystem root.
  - *Confidentiality*, for the host key additionally: not group/world-readable.

  The checks run on the resolved trusted-file set **regardless of whether each
  path came from a flag or the config file** — the threat-model §4.2/§4.4/§5.5.3
  obligations attach to the files, not to how they were named. Failures refuse to
  start with `insecure_permissions`, naming the file and the offending predicate.
- **Placement: the `quantumssh` binary crate**, in a new `config` module beside
  the existing hand-rolled CLI parsing. The library stays protocol-only
  ([ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md) split;
  [ADR-0022](0022-phase-1-async-runtime-tokio.md)'s synchronous startup I/O
  already lives in the binary). `quantumssh-core::server::Config` remains the
  typed handoff; TOML and flags both resolve into it.

## Consequences

### Positive

- The keystone unblocks: `[limits]`, `[session]`, and `[auth].trusted_user_ca_keys`
  now have a typed, versioned home to land in, and Phase 3's privsep sections a
  place to extend.
- One new crate in the lockfile; the fail-closed schema costs zero first-party
  parser code (`deny_unknown_fields` does it).
- Flag-only deployments gain the StrictModes protection they never had — the
  §5.5.3 world-readable-host-key refusal now actually exists.
- v1 freezes only keys that have shipped behaviour, so the `0.1.0` contract
  contains nothing speculative.

### Negative

- **StrictModes is a behaviour change for existing flag-only deployments**: a
  world-readable host key or group-writable `authorized_keys` that served in
  Phase 1 now refuses to start. Deliberate (the threat model mandates it), but
  it will surprise dev setups; the interop harness and examples must set correct
  modes. The error message names file, predicate, and observed mode to make the
  fix obvious.
- `serde_derive` starts being compiled (it was in the lock but unbuilt) — a
  proc-macro build-time cost on a project that watches its surface. Accepted:
  the alternative is hand-writing `Deserialize` impls whose unknown-key handling
  is exactly the code most likely to be wrong.
- Integer-second durations cannot express sub-second values. Nothing configurable
  today needs one; a future key that does picks its own grammar without breaking
  these.
- The ancestor-directory walk makes startup sensitive to where operators place
  files (`/tmp/…` configs will fail integrity). That is the point, but it is
  friction OpenSSH operators will recognise.

### Neutral

- The config module is more code in the "thin" binary crate. It is operator
  surface, not protocol — the ADR-0017 split keeps the library clean precisely so
  this kind of code has a home that is not `quantumssh-core`.
- Hot reload, drop-in directories, and host-key-rotation keys stay in RFC-0010
  §Future; nothing here forecloses them.

## Alternatives considered

### Alternative 1: the full `toml` crate

Richer diagnostics (spans via `serde_spanned`) and the ecosystem default. Rejected:
it brings `winnow`, `indexmap`, `toml_datetime`, and `serde_spanned` into the
trust base for error-message polish on an operator-trusted, startup-only file.
`basic-toml`'s line/column errors satisfy the RFC's `schema_error` requirement.

### Alternative 2: `toml_edit` without serde

Avoids `serde_derive` compilation. Rejected: unknown-key detection, type checking,
and struct mapping become ~200 lines of hand-rolled traversal — reimplementing
`deny_unknown_fields`, worse, in exactly the fail-closed logic that must not have
bugs. It also still adds `winnow` + `indexmap`.

### Alternative 3: hand-rolled TOML-subset parser, zero new dependencies

Maximum surface-minimalism. Rejected: a bespoke config grammar that accretes
features is the exact trap RFC-0010 §Rationale rejected in `sshd_config`, and a
first-party parser is *more* new attack surface than a vetted crate, not less —
MANIFIESTO #4 cuts the other way here.

### Alternative 4: duration strings (`"30s"`) per the RFC's illustration

More sshd-familiar. Rejected for v1: it needs a duration grammar (dependency or
first-party parser) while every current consumer is whole seconds, and the flag
it must stay symmetric with (`--handshake-timeout <SECS>`) is already integer.
The RFC listed the grammar as an open question; it closes here on the side of
less parser.

### Alternative 5: require the config file at `0.1.0`

The RFC left required-vs-optional open. Rejected: forcing every dev invocation
and CI job to materialise a file buys no security (the trusted-file checks run
either way) and breaks the RFC's "existing invocations keep working" promise.

## Links

- Implementation: TBD — `crates/quantumssh/src/config.rs` (new: TOML schema,
  StrictModes checks, precedence merge), `crates/quantumssh/src/main.rs`
  (`--config` flag, resolution order), `crates/quantumssh/Cargo.toml`
  (`basic-toml`, `serde`, `rustix`), `Cargo.toml` (workspace pins). The paths in
  `crates/` exist today except `config.rs`.
- Related: [RFC-0010](../rfcs/0010-configuration-file.md) (the shape this
  implements), [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md)
  (`[limits]` lands with its implementation), [ADR-0024](0024-phase-1-log-event-schema.md)
  (`server.config_error` carries the failure modes), threat model §4.2, §4.4,
  §5.5.3 (the permission obligations).
- Prior art: OpenSSH `StrictModes` / `secure_filename()` (the predicate set),
  `sshd -o` precedence (the override rule).
