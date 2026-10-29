# RFC 0016: Configuration-file schema version 1 — the contract `0.1.0` freezes, and when `schema_version` moves

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-10-29
- **Roadmap issue:** [#109](https://github.com/gonzafg2/quantumssh/issues/109)
- **Implementation PR:** TBD

## Summary

Cutting `0.1.0` makes the TOML configuration file a public interface:
operators will write files against it and keep them across upgrades.
This RFC freezes the file as **schema version 1**:

- **The keys** are [ADR-0029](../adr/0029-phase-2-config-file-v1-schema-parser-strictmodes.md)'s
  and [ADR-0028](../adr/0028-phase-2-concurrent-connections-limits-graceful-shutdown.md)'s,
  unchanged.
- **The rule** says when `schema_version` moves: only on a breaking
  change. An additive change keeps version 1.
- **Defaults** are documented, and changing one is a behaviour change
  with its own process, not a schema change.

It refines [RFC-0010](0010-configuration-file.md) §5, which makes
`schema_version` mandatory and says a binary accepts "its own version
and documented-compatible older versions" without saying which changes
need a new version. It is the last open item of the `0.1.0` freeze
checklist that has no external blocker
([`docs/plans/phase2-scoping.md`](../plans/phase2-scoping.md)).

## Motivation

RFC-0010 already names the risk: "Getting a section boundary or a key
name wrong is expensive to correct afterward". It also accepts a
trade: the schema is fail-closed, so an unknown key or section stops
the server, and "a newer config on an older binary refuses to start".

A review on 2026-10-29 checked the shipped schema
(`crates/quantumssh/src/config.rs`) for what it lets the project do
after the tag:

- **The names hold.** `host_key` names no algorithm, so RFC-0012's
  composite key needs no rename. The keys already announced
  (`[auth] trusted_user_ca_keys` for RFC-0008, `[session] accept_env`
  for ADR-0023) are new keys in new or existing sections.
- **Three keys are single-valued and may need lists:** `listen`
  (several addresses), `host_key` (two keys during an RFC-0007
  migration) and `authorized_keys`. Accepting "a string or a list"
  later keeps every version-1 file valid.
- **The rule is missing.** Nothing says whether adding a key, widening a
  type or changing a default bumps `schema_version`. Without that rule,
  every later change reopens the question, and an operator cannot tell
  from the version what a file may contain.

## Guide-level explanation

A configuration file that `0.1.0` accepts is accepted, with the same
meaning, by every later release that still reads `schema_version = 1`.
Later releases may add keys and sections, and accept more forms for an
existing key. A file that uses one of those additions fails closed on an
older release, naming the unknown key or value. A change that would
make a version-1 file invalid, or change what it means, ships as
`schema_version = 2`, with a migration note. The binary keeps accepting
the versions it documents.

## Reference-level explanation

### 1. The version-1 schema

`schema_version` is a mandatory top-level integer, `1`. All other keys
are optional:

| Key | Type | Default | Defined by |
|---|---|---|---|
| `server.listen` | a string `IPv4:port` or `[IPv6]:port`; no hostname | `127.0.0.1:2222` | ADR-0029 |
| `server.host_key` | path | none (required by flag or file) | ADR-0029 |
| `server.handshake_timeout` | integer seconds, 1 to 2⁶⁴ − 1 | `30` | ADR-0029 |
| `server.drain_timeout` | integer seconds, 1 to 2⁶⁴ − 1 | `30` | ADR-0028 |
| `auth.authorized_keys` | path | none (required by flag or file) | ADR-0029 |
| `logging.format` | `"json"` or `"human"` | `json` unless stderr is a terminal | ADR-0029 |
| `limits.max_connections` | integer, 1 to the platform's `usize` maximum | `256` | ADR-0028 |
| `limits.max_half_open` | integer, 1 to the platform's `usize` maximum | `100` | ADR-0028 |
| `limits.max_per_source` | integer, 1 to the platform's `usize` maximum | `10` | ADR-0028 |
| `limits.accept_rate` | integer tokens per second, 1 to 2³² − 1 | `1` | ADR-0028 |
| `limits.accept_burst` | integer, 1 to 2³² − 1 | `10` | ADR-0028 |

The ranges are the accepted set version 1 freezes. A value outside one
(zero, negative, or above the maximum) is a `schema_error`, and so is a
value of the wrong TOML type. Accepting a wider range or another form
later, such as a hostname for `listen`, is an additive widening under
§2. Accepting a narrower one is breaking.

These version-1 rules stand as RFC-0010 and ADR-0029 fixed them:
- the schema is fail-closed (unknown key, unknown section, type
  mismatch, a zero where > 0 is required);
- `CLI > config > default` precedence, with `server.config_override`
  recording each override (RFC-0014);
- the StrictModes checks on the file and the files it names.

### 2. When `schema_version` moves

**Additive changes keep `schema_version = 1`.** Every version-1 file
stays valid and keeps its meaning:

- a new optional key, or a new section of optional keys;
- a new accepted value of an enumerated key, such as a new
  `logging.format`;
- **widening a key's accepted forms**, such as `listen` taking a string
  or a list of strings, or a duration taking an integer or a suffixed
  string. The form version 1 defines stays accepted, with the same
  meaning.

A file that uses an addition fails closed on an older binary with
`schema_error`, naming the key or value. That is RFC-0010's accepted
trade, and the error names what the older binary lacks.

**Breaking changes require `schema_version = 2`:**

- removing or renaming a key or a section;
- narrowing a key's accepted forms, or changing a key's type, unit or
  meaning;
- making an optional key mandatory;
- changing the precedence rule, or what a key applies to.

A new command-line flag that overrides a file key is additive. The
precedence rule stays `CLI > config > default`, and the flag reaches
`server.config_override` with the key's TOML path (RFC-0014).

A binary that reads version 2 keeps reading version 1 as version 1
says, until a later RFC retires it. The set of accepted versions grows
only through an RFC, which records the migration. A version the binary
does not document is `version_unsupported`, which is RFC-0010's rule.

### 3. Defaults

Defaults are part of the documentation, not of the schema. Changing one
leaves every file valid, so it does not move `schema_version`. It does
change what a file that omits the key means, so:

- **a default change needs a new or superseding ADR, and a CHANGELOG
  entry.** Accepted ADRs are not edited in place, so changing an
  ADR-0028 limit supersedes that part of ADR-0028;
- **a change that widens exposure is listed under Security.** Examples
  are a wider `listen` address, higher `limits`, or a longer timeout.

### 4. What this changes in accepted decisions

None of ADR-0028's or ADR-0029's decisions change. This RFC refines
RFC-0010 §5 by stating which changes need a new version. It records
the version-1 key set as this RFC's §1 without editing those documents
(`README.md`, "After acceptance").

### 5. Implementation outline (non-normative)

The implementing PR:

- adds a golden test that parses a file setting every §1 key, so a
  rename or removal fails the build. It also checks each range's ends.
  The wrong-type case is already covered (`type_mismatch_is_schema_error`);
- makes the `version_unsupported` message stop calling every unknown
  version "newer". It says `schema_version 0 is newer than this binary
  understands (supported: 1)` today. The message should build the
  supported list from `SUPPORTED_SCHEMA_VERSIONS`, so it stays right
  when version 2 lands;
- adds §2's rule, in a sentence, to the operator guide's configuration
  section, then flips this RFC to Accepted.

## Drawbacks

- **An addition breaks older binaries.** A file that uses a new key does
  not start on a release that lacks it, because the schema is
  fail-closed. The error names the key, and RFC-0010 accepted the trade
  for security-relevant configuration.
- **One version for many additions.** `schema_version = 1` does not say
  which additions a file uses, only that it is a version-1 file. The
  release notes carry the additions.

## Rationale and alternatives

### Alternative 1: bump `schema_version` on every addition

An older binary would then fail with `version_unsupported`, which is
plainer than `schema_error`. Rejected: the version would move with
nearly every release, and each binary would carry a growing accepted
set. The fail-closed `schema_error` already names the unknown key.
This is the rule RFC-0014 chose for the audit log.

### Alternative 2: ignore unknown keys

Old binaries would start on newer files. Rejected, as RFC-0010
rejected it: a directive the operator believes is in force would be
silently dropped.

### Alternative 3: freeze the defaults too

It would make a default change a version-2 change. Rejected: it adds
no protection a file can rely on, because the file stays valid either
way. §3 makes the change visible instead.

## Prior art

- **OpenSSH `sshd_config`** has no version and warns on deprecated
  options. A misspelt or unknown option is an error, as here.
- **The audit log** (RFC-0014) uses the same additive-keeps-version
  rule, so the project has one compatibility vocabulary.

## Unresolved questions

- **The list forms** of `listen`, `host_key` and `authorized_keys`
  wait for the change that needs them. §2 already makes them additive.

## Future possibilities

- A `quantumssh --check-config` mode that loads and validates a file
  without starting, so an operator can test a file against a binary
  before an upgrade.
