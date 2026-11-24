# ADR 0070: The `[[account]]` grammar, and the errors account mode reports at startup

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-11-24)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §1, §3, §5 and §8. It is the first item of RFC-0019 §9: "the exact grammar of `[[account]]` and its error messages".
  - Adds to the version-1 schema of [RFC-0016](../rfcs/0016-config-schema-v1.md) under its §2. It is parsed as [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md) parses the rest of the file.
  - Adds a value to `server.config_error`'s `class` ([RFC-0014](../rfcs/0014-audit-log-schema-v1.md) §4), which RFC-0014 §5 allows.
  - The account records come from the parser of [ADR-0071](0071-passwd-and-group-parser-bounds-and-malformed-lines.md). The launcher's own startup checks are [ADR-0066](0066-account-mode-start-readiness-and-stop.md) §1.

## Context

RFC-0019 selects account mode by one or more `[[account]]` entries, and
sketches the grammar:

```toml
[[account]]
name = "alice"
authorized_keys = "/etc/quantumssh/keys/alice"
```

It leaves "its exact keys" and the error messages to this ADR. It does
fix the rules those errors enforce:

- **Names follow `useradd(8)`'s rule** (§3), with at most 256 bytes.
- **These are startup errors:**
  - a name outside the rule, or a name listed twice;
  - a listed UID 0;
  - an entry with no key file when no CA is set (§3);
  - a file that fails the account-mode check (§8).
- **These are not errors:** an account with no entry in `/etc/passwd`,
  or one with no key and no CA. Each fails closed alone, and a
  diagnostic record names it (§3).
- **The two modes do not mix:** in account mode, `auth.authorized_keys`
  and `--authorized-keys` are errors (§1). Account mode is Linux only.

What the code does today, for the version-1 file:

- **The parser.** `config.rs` deserializes the file with `serde` and
  `deny_unknown_fields` on every struct. An unknown key, a wrong type or
  a value out of range is a `schema_error` with its line and column.
- **The error event.** Every startup failure is a `server.config_error`
  record. Its `class` is one of RFC-0014 §4's values, and its message
  starts with the class (`schema_error: …`).

## Decision

### 1. The grammar

```toml
[[account]]
name = "alice"                                   # required
authorized_keys = "/etc/quantumssh/keys/alice"   # optional
```

| Key | Type | Required | Meaning |
|---|---|---|---|
| `account` | array of tables | no | One entry per listed account. Absent selects service-account mode (RFC-0019 §1) |
| `account[].name` | string | yes | The account's name, under the rule of §2 |
| `account[].authorized_keys` | path | no | The account's key file: today's format, `ssh-ed25519` lines with no options (ADR-0040). In account mode it may hold no key (RFC-0019 §5) |

- **Nothing else goes in an entry.** `deny_unknown_fields` applies to
  the entry, so any other key is a `schema_error`. Per-account policy,
  such as a forced command, is RFC-0019's unresolved question 4. It
  would arrive as new optional keys here.
- **No flag sets an account.** The list lives in the file only, like
  `auth.trusted_user_ca_keys` (RFC-0010).
- **Schema version.** This is a new optional key of RFC-0016 §2's kind,
  so `schema_version` stays 1. An older binary refuses a file that uses
  it, with a `schema_error` that names `account`.

### 2. The name rule

A name is 1 to 256 bytes long, the user-name bound the server already
applies (`auth.rs`, `USER_NAME_BOUND`). It must also be:

- **made of ASCII letters, digits, `_` and `-`,** with an optional final
  `$`;
- **not starting with `-`;**
- **not all digits.**

`.` and `..`, which useradd(8) also forbids, cannot occur, because `.`
is not in the alphabet. The rule is checked byte by byte on the TOML
string. Nothing is normalized: `Alice` and `alice` are two names, as
they are in `/etc/passwd`.

### 3. The errors

**Two classes.**

- **Deserializer errors keep `schema_error`.** That covers an unknown
  key in an entry, a missing `name`, a value of the wrong type, and an
  `account` that is not an array of tables. The message is the
  deserializer's, with line and column, as today.
- **Every other account-mode rule is a new class, `account_mode`.**

**How a message names an entry.** It uses the entry's position, 1-based,
and its name: `account #2 ("deploy")`. Names come from the operator's
file. RFC-0014's encoder escapes them like any other string.

| Condition | Class | Message, after `<class>: ` |
|---|---|---|
| `account = []` | `account_mode` | `account: an empty list selects no account; remove it for service-account mode` |
| A name breaks §2 | `account_mode` | `account #2 ("Al ice"): not a valid account name (RFC-0019 §3)` |
| A name is listed twice | `account_mode` | `account #3 ("alice"): listed twice, first as account #1` |
| A listed name has UID 0 in `/etc/passwd` | `account_mode` | `account #1 ("toor"): UID 0 cannot be listed` |
| An entry has no `authorized_keys` and `auth.trusted_user_ca_keys` is unset | `account_mode` | `account #2 ("deploy"): no authorized_keys and no trusted_user_ca_keys, so nothing could log in to it` |
| `auth.authorized_keys` is set in account mode | `account_mode` | `auth.authorized_keys: not allowed in account mode; each [[account]] names its own key file` |
| `--authorized-keys` is given in account mode | `account_mode` | `--authorized-keys: not allowed in account mode; each [[account]] names its own key file` |
| `[[account]]` on a platform other than Linux | `account_mode` | `account mode exists on Linux only` |
| Account mode, not started as root (ADR-0066 §1) | `account_mode` | `account mode must start as root` |
| `--require-account-mode` with no account (ADR-0066 §1) | `account_mode` | `--require-account-mode: the configuration lists no account` |
| The service account is missing, has UID or GID 0, or shares its UID with a listed account (ADR-0066 §1) | `account_mode` | for example `service account "quantumssh": UID 999 is also account #2 ("ops")` |
| A file fails RFC-0019 §8's root rule or its no-symlink rule | `insecure_permissions` | the file and the predicate, for example `/etc/quantumssh/keys/alice: not owned by root (account mode)`, or `/etc/quantumssh/keys/deploy: not a canonical path, resolves to /srv/keys/deploy (account mode)` |
| A key file, `/etc/passwd` or `/etc/group` cannot be read | `file_unavailable` | as today, naming the file |
| A key file cannot be loaded | `invalid_authorized_keys` | as today, prefixed with the entry, for example `account #2 ("deploy"): …` |

- **The order of the checks.** The binary runs the deserializer first,
  then the rules that need only the file, then the rules that read
  `/etc/passwd` and the file checks. The first failure stops the start.
- **Who writes the record.** The process that runs the check writes it:
  - the binary, before it chooses its mode;
  - the launcher, for ADR-0066 §1's checks;
  - the server, for the checks it repeats when it reads the file again.

  This adds to ADR-0066 §6, which otherwise leaves every audit event to
  the server.
- **The new class is additive.** A new value of `class` is additive
  under RFC-0014 §5. A consumer that does not know it still reads the
  record as a startup failure.

### 4. An account that cannot be reached is not an error

When a listed account cannot be reached at startup, the binary starts
anyway, and writes one diagnostic record per such account (RFC-0019 §3).
The record is at level `WARN`, with the message `account unreachable`,
the field `account` (its name), and the field `reason`:

| `reason` | Meaning |
|---|---|
| `no_passwd_entry` | `/etc/passwd` has no line for the name |
| `malformed_entry` | the first line for the name is malformed (ADR-0071 §3) |
| `no_key` | its key file holds no key, and `auth.trusted_user_ca_keys` is unset |

These records are diagnostic, not audit. RFC-0014 §5 lets diagnostic
records change freely.

## Consequences

### Positive

- **A file either means one thing or does not start.** No account-mode
  rule is silent.
- **The operator gets the entry, the name and the rule in one line,**
  and the record's class sorts account-mode failures from the others.
- **The grammar leaves room for per-account policy** without a new
  section.

### Negative

- **Positions in messages shift** when entries are added or removed.
  The name is printed next to each position for that reason.
- **One more `class` value** for log consumers to learn.

### Neutral

- **Service-account files are untouched.** Without `account`, none of
  these rules runs.

## Alternatives considered

### Alternative 1: a table keyed by name, `[account.alice]`

Rejected. TOML keys follow their own quoting rules, so a name such as
`svc$` would need quotes. A duplicate would also be a TOML parse error,
not the message of §3. The array keeps the name a plain value, checked
by one rule.

### Alternative 2: put every account-mode error under `schema_error`

Rejected. Some of these errors depend on the host, such as UID 0 in
`/etc/passwd`, the platform, or the starting UID, not on the file's
form. A distinct class lets an operator tell "the file is malformed"
from "the file is valid, but account mode cannot run here".

### Alternative 3: make an unreachable account a startup error

Rejected by RFC-0019 §3. After a `userdel`, every account would be shut
out at the next restart.

## Links

- [RFC-0019](../rfcs/0019-identity-model-ssh-user-name-to-os-account.md) §1, §3, §5, §7, §8, §9; [RFC-0016](../rfcs/0016-config-schema-v1.md) §1, §2; [RFC-0014](../rfcs/0014-audit-log-schema-v1.md) §4, §5.
- [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md); [ADR-0040](0040-refuse-authorized-keys-options-until-enforced.md); [ADR-0066](0066-account-mode-start-readiness-and-stop.md) §1, §6.
- useradd(8), "Caveats": the user-name rule.
- `crates/quantumssh/src/config.rs`; `crates/quantumssh-core/src/auth.rs`, `USER_NAME_BOUND`.
