# RFC 0010: TOML configuration file

- **Status:** Accepted (2026-07-17)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-07-06
- **Roadmap issue:** [`#109`](https://github.com/gonzafg2/quantumssh/issues/109)
- **Implementation PR:** TBD — the keystone Phase-2 workstream ([`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md)).

## Summary

QuantumSSH is configured today only by command-line flags (`--listen`,
`--host-key`, `--authorized-keys`, `--handshake-timeout`, `--log-format`). This
RFC makes **one shape-determining decision**: **adopt a TOML configuration file
as QuantumSSH's configuration interface from Phase 2**, the surface the README
roadmap already names ("Configuration file (TOML, not `sshd_config`)"). It sets
the *shape* of that surface — a **schema-versioned**, **fail-closed**,
**restart-time-loaded**, **operator-trusted** TOML file, with a documented
CLI-override precedence — while the exact key set and the parser crate are locked
by implementing ADRs that cite it. The file is the **extensible home** the rest
of Phase 2 and Phase 3 plug into: the `TrustedUserCAKeys`-equivalent CA-trust
surface [RFC-0008](0008-ssh-certificate-authentication.md) defers to "the Phase-2
config RFC", the `env`/`SetEnv` policy [ADR-0023](../adr/0023-phase-1-channel-layer-scope.md)
defers "to the config work in Phase 2", the per-source rate-limits and half-open
caps [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) lands with Phase 2,
and the key→UID / PAM / chroot / rlimit policy the Phase-3 privilege-separation
work needs ([`phase3-privsep-scoping.md`](../plans/phase3-privsep-scoping.md)).
It adds no feature by itself; it decides *that* those settings have a typed,
versioned home, and sketches its shape.

## Motivation

**The gap.** Phase 2 ("Usable", `0.1.0`) adds interactive PTY, SFTP, certificate
auth, per-source rate-limits, and an `env` policy — each of which needs
configuration that a flag list cannot carry. A CA-trust anchor, an environment
allow-list, and per-source limits are not five-flag concerns; they are structured
policy. Two already-accepted documents explicitly defer their configuration to
"the Phase-2 config file" that does not yet exist
([RFC-0008](0008-ssh-certificate-authentication.md) §Trust-anchoring;
[ADR-0023](../adr/0023-phase-1-channel-layer-scope.md) §Consequences). A third,
[ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) §Decision, defers the
per-source rate-limits and half-open caps *as a feature* to Phase 2's concurrent
accept loop — a feature that will need its configuration here. This is the
keystone Phase-2 workstream: much waits on it, nothing blocks it.

**Why decide now, and why it must be right.** Cutting `0.1.0` turns the config
schema into a **public compatibility contract** — the same one-way freeze that
binds the negotiation profile ([ADR-0021](../adr/0021-phase-1-negotiation-profile.md))
and the audit-log schema ([ADR-0024](../adr/0024-phase-1-log-event-schema.md)).
A key renamed or a section restructured after `0.1.0` breaks every deployed
config. The schema therefore needs a version field and a compatibility rule
**from its first commit**, and the surface shipped at `0.1.0` should be the
minimum that covers Phase-2, not a speculative superset
([RFC-0007](0007-cryptographic-primitive-migration-procedure.md) explicitly warns
against "over-generalizing … a config surface that does not exist").

**The operational cost it removes.** Every non-trivial deployment today must
encode all policy in the service manager's flag string. There is no place to
express "trust this CA", "these environment variables may pass", or "cap
half-open connections at N" — because there is no configuration surface at all.

## Guide-level explanation

An operator runs `quantumssh --config /etc/quantumssh/config.toml`. The file is
TOML, sectioned by concern:

```toml
# /etc/quantumssh/config.toml
schema_version = 1

[server]
listen            = "0.0.0.0:22"
host_key          = "/etc/quantumssh/ssh_host_ed25519_key"
handshake_timeout = "30s"

[auth]
authorized_keys       = "/etc/quantumssh/authorized_keys"
# CA-trust anchor — populated per RFC-0008; empty until certificates ship.
trusted_user_ca_keys  = "/etc/quantumssh/trusted_user_ca_keys"

[limits]
# Per-source pre-auth limits (ADR-0022); the availability-DoS mitigation.
max_half_open         = 128
max_per_source        = 8

[logging]
format = "json"   # "json" | "human"

[session]
# The env allow-list ADR-0023 defers here; empty = forward nothing.
accept_env = ["LANG", "LC_*"]
```

Precedence is **least-surprise, sshd-shaped**: a value set on the command line
overrides the file, which overrides the built-in default (`CLI > config >
default`). The Phase-1 flags remain as overrides for the values they already
cover, so existing invocations keep working; everything new lives only in the
file. The config file is **optional** — a server started with just the Phase-1
flags still boots — but it is the *primary* surface, and the only one that can
express the Phase-2 policy above.

The file is **operator-trusted, not attacker-facing**: it is read **once at
startup** (the [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) non-async
startup I/O), never on the pre-auth path, and changing it requires a restart.
Before reading it, QuantumSSH runs **two orthogonal permission checks**, and a
failure of either is a **fail-closed refuse to start**:

- **Integrity** — the config file and every trusted file it names
  (`authorized_keys`, the CA-trust file, the host key) must not be writable by
  anyone but their owner, must be owned by root or the service account, and must
  sit in a path no one else can write. A config — or a path to it — an attacker
  can edit is a config that authenticates the attacker.
- **Confidentiality** — the **private host key** must additionally be **not
  readable by group or world**. A readable private key is a key an attacker can
  copy off disk.

Together these are the OpenSSH-`StrictModes` posture (mode, ownership, and the
parent-directory chain); the host key is subject to *both* (it is a trusted input
*and* a secret). The reference-level section specifies each predicate.

An **unknown or malformed key is a hard error** (fail closed), not a silent
ignore: a typo in a security-relevant setting must stop the server, not
half-apply. The `schema_version` field lets a future binary tell "old config,
still valid" from "config from a newer binary I cannot safely interpret".

## Reference-level explanation

### The decision, precisely

Adopt a TOML file as the configuration interface, with these properties as the
*shape* (each finalised in an implementing ADR, per the one-decision-per-RFC
discipline):

1. **Format: TOML**, already committed by the README. Recorded rationale under
   §Rationale.
2. **Loaded once at startup, never pre-auth.** The config is parsed in the
   synchronous startup path and frozen for the process lifetime. This keeps it
   out of the §4.1 highest-trust surface: it is a trusted *input* (threat-model
   §4.4 config integrity), governed by filesystem permissions, not a network
   parser. Reload is restart-only in Phase 2 (hot reload is §Future).
3. **Fail-closed permission checks — two orthogonal controls.** Both are
   refuse-to-start; they defend different threats and neither replaces the other.
   Each is the **full** OpenSSH-`StrictModes` predicate set, not a mode-bits-only
   subset — a mode check alone is bypassable (an attacker-owned `0600` file, or a
   correctly-moded file inside a group-writable directory), so the shape names all
   three:
   - **Integrity (writability).** For the config file and every trusted file it
     names (`authorized_keys`, CA-trust file, host key): (a) the file is not
     group- or world-writable; (b) the file is owned by root or the service UID
     (never an untrusted owner who could rewrite their own trust file); and (c) no
     ancestor directory in its path is group- or world-writable (else the file can
     be unlinked and replaced regardless of its own mode). A writable trust file —
     or a writable path to it — lets an attacker edit their way to authentication.
     Authority: threat-model §4.2 (process boundary) names host-key material,
     `authorized_keys`, **and** configuration files as the permission-trusted set;
     §4.4 states the config-integrity goal ("exclude unauthorised writers"). This
     RFC's contribution is *generalising* the check to every trusted file the
     config references, with the ownership and parent-chain predicates that make
     "exclude unauthorised writers" actually hold.
   - **Confidentiality (readability).** The **private host key** must additionally
     be **not group- or world-readable**. This **extends** the threat-model §5.5.3
     mandate — the server "refuse to start if host-key file permissions are
     world-readable in the default configuration" — tightening world-readable to
     also reject group-readable (`0640`); it is **not** replaced by the writability
     check.

   The host key is subject to both; a mode-`0644` host key (owner-writable-only
   but world-readable) fails the confidentiality check and must be rejected.
   Together these are the OpenSSH-`StrictModes` posture (`secure_filename` /
   `safe_path`: mode, ownership, and the parent-directory chain).
4. **Fail-closed schema.** Unknown keys, unknown sections, and type-mismatched
   values are startup errors, not warnings. This catches the typo-in-security-config
   failure mode that a permissive parser silently ships.
5. **`schema_version` from v1.** A mandatory top-level integer. The binary
   accepts its own version and documented-compatible older versions; a *newer*
   version it does not understand is a fail-closed refuse-to-start (better than
   mis-parsing a security config). This is the mechanism that makes the `0.1.0`
   freeze survivable — the schema can evolve across versions with an explicit
   compatibility statement instead of a silent break.
6. **CLI-override precedence: `CLI > config > default`**, with the Phase-1 flag
   set retained as overrides. The exact retained flag set is an implementing-ADR
   detail.

### Schema shape (recommended; exact keys in an implementing ADR)

Sections map the current flags plus the deferred Phase-2 policy. The seed set:

| Section | Keys (illustrative) | Source of the requirement |
|---|---|---|
| `[server]` | `listen`, `host_key`, `handshake_timeout` | Phase-1 flags; threat-model §4.4 (host-key paths in config) |
| `[auth]` | `authorized_keys`, `trusted_user_ca_keys` | Phase-1 flag; [RFC-0008](0008-ssh-certificate-authentication.md) §Trust-anchoring |
| `[limits]` | `max_half_open`, `max_per_source` | [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md) §Decision |
| `[logging]` | `format` | Phase-1 flag; interacts with the [ADR-0024](../adr/0024-phase-1-log-event-schema.md) schema freeze |
| `[session]` | `accept_env` | [ADR-0023](../adr/0023-phase-1-channel-layer-scope.md) §Consequences (`env`/`SetEnv`) |

The `trusted_user_ca_keys` key is the **slot** RFC-0008 named; its exact
semantics (file format, multiple CAs, KRL reference) are that RFC's implementing
concern, not decided here. Phase-3's key→UID / PAM / chroot / rlimit policy adds
sections later ([`phase3-privsep-scoping.md`](../plans/phase3-privsep-scoping.md))
— the schema is designed to be extended by new sections without touching existing
ones.

### The parser and its dependency

TOML parsing needs a crate — a new dependency that must be justified and pass
`cargo deny` (MANIFIESTO commitment #4). Because the config is **not** on the
pre-auth path,
the bounded-allocation / must-be-fuzzable rule of the highest-trust surface
(§4.1) does not bind it with the same force; a well-audited, serde-based TOML
crate (e.g. `toml`, or the smaller `basic-toml`) is acceptable. The specific
crate is an implementing-ADR choice made against `cargo deny` at the time, on the
smallest-surface-that-works principle.

### Failure modes

The codes below are **values of the `message` field in the existing
`server.config_error` event** ([ADR-0024](../adr/0024-phase-1-log-event-schema.md));
this RFC introduces **no new audit event names** — minting one would extend the
frozen schema and require a superseding ADR, which the config surface must not do.

- **Integrity failure on a config or trust file** — group/world-writable, owned
  by an untrusted UID, or reachable through a group/world-writable ancestor
  directory → refuse to start (`insecure_permissions`).
- **World/group-readable private host key** (confidentiality, threat-model
  §5.5.3) → refuse to start (`insecure_permissions`).
- **Unknown key / section / type mismatch** → refuse to start (`schema_error`,
  with the offending key and line).
- **`schema_version` newer than the binary understands** → refuse to start
  (`version_unsupported`).
- **Referenced file missing** → refuse to start, same as today's flag path.
- **Both a flag and its config key set** → the flag wins; the server boots
  normally, logged at startup (info) so the override is visible — **not** an error.

The first five abort startup through `server.config_error`; the precedence
override is an info-level note and the server continues. None of these conditions
reach the network.

## Drawbacks

- **A new parser and a new dependency on a project that prizes small surface.**
  A TOML crate is net-new trust base. Mitigated: it is off the pre-auth path, the
  crate is a vetted serde-ecosystem one gated by `cargo deny`, and TOML is
  simpler than the alternatives (§Rationale). Still, it is more code than "parse
  five flags".
- **The schema freezes into a public contract at `0.1.0`.** Getting a section
  boundary or a key name wrong is expensive to correct afterward. Mitigated by
  `schema_version` and by shipping the *minimum* Phase-2 surface, not a
  speculative one — but the freeze is real and the design bar is correspondingly
  high.
- **Fail-closed on unknown keys hurts forward-compatibility.** A newer config on
  an older binary refuses to start. This is the deliberate trade: for
  security-relevant config, a hard stop beats silently ignoring a directive the
  operator believes is in force. `schema_version` makes the failure legible
  rather than mysterious.
- **Two configuration surfaces (flags + file) add precedence complexity.**
  Mitigated by a single documented rule (`CLI > config > default`) and by keeping
  the retained flag set minimal — but it is more than one surface to reason about.
- **`StrictModes`-style permission checks are a known friction source.** OpenSSH
  operators hit "bad ownership or modes" often. Mitigated by a precise error
  message naming the file and the offending mode; the check is default-on because
  the failure it prevents (attacker-writable trust config) is severe.

## Rationale and alternatives

**The decision — adopt a TOML config file in Phase 2 — against its alternatives:**

- **Adopt it (this RFC).** Gives the Phase-2 policy (cert trust, `env`, limits)
  and the Phase-3 privsep policy a typed, versioned home, and fixes the interface
  before `0.1.0` freezes it.
- **Stay CLI-only.** Rejected: a flag list cannot carry a CA-trust anchor, an
  environment allow-list, or per-source limits without becoming unusable, and
  three accepted documents already defer their config here. It does not scale to
  "Usable".
- **Defer past `0.1.0`.** Rejected: like the certificate case, adding the config
  surface after the release makes it an unplanned breaking change to how every
  deployment is operated.

**Format sub-choice (the shape this RFC recommends; the README already commits to
TOML):**

- *TOML* over ***`sshd_config`* format** — the bespoke keyword-per-line grammar is
  a hand-rolled parser (more surface, not less) and carries decades of legacy
  keyword baggage the project explicitly sheds ("not `sshd_config`").
- *TOML* over **YAML** — YAML's parser surface and footguns (implicit typing, the
  "Norway problem", anchors/aliases) are exactly the large, surprising surface
  MANIFIESTO commitment #4 refuses.
- *TOML* over **JSON** — JSON has no comments and is poor for a hand-edited
  operator file.
- *TOML* is typed, commentable, minimal, and already the Rust ecosystem's config
  language (`Cargo.toml`) — the least-surprise choice for a Rust operator.

**Not doing this** leaves Phase 2 unbuildable: certificate trust, the `env`
policy, and per-source limits have nowhere to live, and Phase-3 privilege
separation stays blocked on the config-schema prerequisite it names.

## Prior art

- **OpenSSH `sshd_config`** — the reference for `-o` override precedence and for
  `StrictModes` (the permission check this RFC mirrors and extends to referenced
  trust files). Also the cautionary case: a bespoke config grammar accreting
  keywords over decades.
- **`Cargo.toml` and the Rust ecosystem** — TOML as the established Rust config
  format; the `toml` / `basic-toml` / `serde` crates as the parser options.
- **The TOML specification** ([toml.io](https://toml.io)) — typed, minimal,
  comment-bearing.
- Internal: [RFC-0008](0008-ssh-certificate-authentication.md) (the CA-trust
  surface this file hosts), [ADR-0022](../adr/0022-phase-1-async-runtime-tokio.md)
  (startup I/O model, the limits this carries), [ADR-0023](../adr/0023-phase-1-channel-layer-scope.md)
  (the `env` policy), [ADR-0021](../adr/0021-phase-1-negotiation-profile.md) /
  [ADR-0024](../adr/0024-phase-1-log-event-schema.md) (the parallel `0.1.0`
  freezes), and [RFC-0007](0007-cryptographic-primitive-migration-procedure.md)
  (the YAGNI warning against over-generalizing a not-yet-existent config surface).

## Unresolved questions

- **The exact retained CLI flag set** (all of Phase-1's, or a reduced set with
  the rest moved file-only) — an implementing-ADR detail.
- **Exact key names, section boundaries, and value grammars** (e.g. is
  `handshake_timeout` a `"30s"` string or an integer-seconds?) — implementing ADR.
- **The TOML crate** — decided against `cargo deny` at implementation time.
- **Config required vs optional.** This RFC recommends *optional-but-primary*
  (the Phase-1 flag path still boots); whether `0.1.0` instead requires a config
  file is open.
- **Whether host-key rotation config** (threat-model §5.5.3: operators "must have
  a documented rotation procedure (Phase 2)") lands in this schema or a follow-up.
- **The exact `env`/`accept_env` grammar** — coordinated with the ADR-0023
  successor that adds `env` support, not fixed here.

## Future possibilities

- **The Phase-3 privsep sections**: the key→OS-user mapping, PAM, chroot, and
  `setrlimit` policy the privilege-separation RFC ([#43](https://github.com/gonzafg2/quantumssh/issues/43))
  needs — the single biggest consumer of this surface.
- **RFC-0008's full config-trust surface**: `trusted_user_ca_keys` semantics and
  any KRL configuration, beyond the slot this RFC reserves.
- **Hot reload** (`SIGHUP`) — re-reading the file without dropping connections,
  once the restart-only model proves limiting.
- **Drop-in directories** (`config.d/`) — sshd-style composition for packaged
  deployments.
- **Config-driven crypto-migration knobs** — the per-deployment algorithm policy
  [RFC-0007](0007-cryptographic-primitive-migration-procedure.md) deferred until a
  config surface exists; explicitly *not* proposed now (its own YAGNI warning
  applies). Any future form is bounded by **MANIFIESTO commitment #2**: migration
  navigates between approved hybrid PQ profiles only — **no non-hybrid or
  classical-only KEX may ever be expressible via config** (e.g. no
  `kex_algorithm = "curve25519-sha256"`). The config surface cannot become a
  downgrade path.
