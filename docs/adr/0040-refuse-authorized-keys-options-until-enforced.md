# ADR 0040: Refuse `authorized_keys` lines that carry options until per-key restrictions are enforced

- **Status:** Accepted
- **Date:** 2026-10-12 (accepted with the implementing PR [#184](https://github.com/gonzafg2/quantumssh/pull/184); drafted 2026-10-12)
- **Deciders:** Project lead
- **Related:** Fixes [#183](https://github.com/gonzafg2/quantumssh/issues/183). Applies the fail-closed rule of [RFC-0010](../rfcs/0010-configuration-file.md) ("a typo in a security-relevant setting must stop the server, not half-apply") to the `authorized_keys` loader that [ADR-0022](0022-phase-1-async-runtime-tokio.md) reads once at startup and [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md) names. Uses the existing `server.config_error` message of [ADR-0024](0024-phase-1-log-event-schema.md), with no new event. Interacts with [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §3 (the PTY permission gate). Aligns threat model §5.3.2 and §6.3. Part of the Phase-2 milestone ([#109](https://github.com/gonzafg2/quantumssh/issues/109)).

## Context

An OpenSSH `authorized_keys` line has the form
`[options] keytype base64 [comment]` (sshd(8), "AUTHORIZED_KEYS FILE
FORMAT"). The options field restricts or redefines the key: `from=`
limits source addresses, `command=` forces one command, `restrict`
turns off every optional capability, and `cert-authority` marks the
key as a certificate authority rather than a user key.

Until this ADR, `AuthorizedKeys::load` skipped the options field
with a quote-aware scanner. It then loaded the key with no
restriction at all. The module doc justified this as "Phase 1 —
ADR-0023 scope cut", but ADR-0023 does not mention options, so the
decision was never recorded. The effect was fail-open:

- `restrict,from="10.0.0.0/8",command="/usr/local/bin/backup"` loaded a
  key that could run any command from any address.
- A `cert-authority` line loaded the CA's own key as a user key.
  OpenSSH never authorizes a plain key from such a line
  (`auth2-pubkeyfile.c:318` at `V_10_6_P1`: a plain key fails when
  `keyopts->cert_authority` is set).
- Threat model §6.3 listed per-key restrictions as a mitigation, and
  §5.3.2 named them as a compensating control. Neither existed in the
  code.

An operator who reused an OpenSSH file, or who trusted the threat
model, believed a key was confined when it was not. ADR-0038 raises
the stakes, because interactive shells follow. Its §3 already refuses
a PTY to any key with options, but `exec` stayed unrestricted.

The loader already fails closed on every other line it cannot honour.
An unsupported key type, a malformed blob or a small-order key each
fail the whole load, the binary logs `server.config_error` and the
server does not start.

## Decision

We will refuse every `authorized_keys` line that carries an options
field, until per-key restrictions are enforced.

- **Detection.** A line whose first field is not shaped like a key
  type (`ssh-`, `ecdsa-` or `sk-`, the families sshd(8) recognises)
  carries an options field. No OpenSSH option name starts with one of
  these prefixes.
- **Failure.** Such a line fails the whole load with
  `AuthError::KeyOptions { line }`, as an unsupported key type does
  today. The binary reports it through the existing
  `server.config_error` message and does not start. Nothing is
  skipped and nothing is partly loaded.
- **No option is recognised.** This includes options whose capability
  does not exist yet (`no-port-forwarding`, `no-agent-forwarding`,
  `no-X11-forwarding`) and `no-pty`.
- **The diagnostic names the line, not its contents.** The line
  number is enough to find it, and option values (commands, paths,
  address lists) stay out of the log stream.
- **Lifting the refusal is a separate decision.** Per-key restrictions
  will be designed in their own ADR or RFC (the threat model's
  "QuantumSSH's own syntax", plausibly through the RFC-0010 config
  file). That decision may accept an option only once the server
  enforces it, and it supersedes this ADR or narrows it.
- **Documentation follows the code.** The `auth.rs` module doc drops
  the non-existent ADR-0023 citation. Threat model §6.3 marks per-key
  restrictions as planned, and §5.3.2 notes that they are not yet
  implemented.

**Relation to ADR-0038 §3.** The PTY gate keeps its rule: no PTY for
a key whose line carries options. While this ADR holds, no such key is
loaded, so the gate has nothing to refuse until per-key restrictions or
the certificates of RFC-0008 feed it. §3 also notes that `no-pty`
"works" as a per-key PTY off switch. That switch is withdrawn here: a
`no-pty` line now stops startup.

## Consequences

### Positive

- The server enforces exactly what the file says, or refuses to start.
  No operator restriction is dropped silently.
- The threat model no longer claims a control the code lacks.
- The quote-aware options scanner is gone, so the startup parser no
  longer needs to understand the option grammar.

### Negative

- An OpenSSH `authorized_keys` file that uses options does not load.
  The operator must delete the line, or delete its options and so make
  the key unrestricted on purpose.
- One such line stops the server for every key. This is the same cost
  every other bad line already carries, and the file is read only at
  startup, so the failure appears at deploy time, not at login.
- There is no per-key PTY off switch until per-key restrictions land
  (see the relation to ADR-0038 §3).
- `AuthError` gains a variant, which changes the library API. That is
  acceptable before `0.1.0`.

### Neutral

- No new dependency, no new log event, and no change to the wire
  protocol.
- The interop gate (ADR-0020) is unaffected, because its
  `authorized_keys` line carries no options.

## Alternatives considered

### Alternative 1: Skip the line and log an error

Each line with options would fail closed on its own, while the other
keys kept working. This was not chosen because it introduces a
partly loaded state into a loader that has none: an error in the log,
and a server running without one of the keys the operator listed. It
also departs from how the loader treats every other bad line, and from
RFC-0010's "stop the server, not half-apply".

### Alternative 2: Accept options whose capability does not exist

`no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding` and,
before ADR-0038, `no-pty` hold trivially while the feature is absent.
An allowlist would let common OpenSSH files load. This was not chosen
because each entry becomes a silent fail-open on the day its feature
lands: `no-pty` with the ADR-0038 implementation, and forwarding later.
The allowlist would need a re-audit at every feature. It would also
require parsing the option grammar exactly. `restrict` cannot be
honoured this way at all, because OpenSSH defines it to cover
restrictions added in future versions.

### Alternative 3: Implement `from=` and `command=` now

This is the per-key restriction work itself. It has to decide the
syntax, source-address matching and how a forced command interacts
with ADR-0024's `command` audit field. That design is larger than this
fix and deserves its own decision. Refusing options now does not
constrain it.

### Alternative 4: Keep ignoring options and document it

Documentation does not reach an operator who copies an OpenSSH file.
This alternative also contradicts the project's fail-closed rule and
the threat model, so it was not chosen.

## Links

- Code: `crates/quantumssh-core/src/auth.rs` (`AuthorizedKeys::load`,
  `AuthError::KeyOptions`), `crates/quantumssh/src/main.rs` (the
  `server.config_error` report).
- Related ADRs: ADR-0022, ADR-0024, ADR-0029, ADR-0038.
- Related RFCs: RFC-0008 (certificates), RFC-0010 (configuration file).
- Threat model: §5.3.2, §6.3.
- Issue: [#183](https://github.com/gonzafg2/quantumssh/issues/183).
- Prior art: OpenSSH `auth2-pubkeyfile.c` (`auth_check_authkey_line`)
  and `auth-options.c` at `V_10_6_P1`.
