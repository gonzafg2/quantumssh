# ADR 0051: Certificate authentications carry four `cert_*` audit fields

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-30)
- **Deciders:** Project lead
- **Related:** Names the certificate fields that [RFC-0014](../rfcs/0014-audit-log-schema-v1.md) §5 and §6 leave to [RFC-0008](../rfcs/0008-ssh-certificate-authentication.md)'s implementing ADR. The feature is [ADR-0050](0050-accept-openssh-user-certificates.md), and both are implemented in the same PR. The change is additive under RFC-0014 §5, so `schema_version` stays `1`. It keeps the [ADR-0024](0024-phase-1-log-event-schema.md) rule that every `exec.*` event names who ran the command. Part of the Phase-2 milestone ([#109](https://github.com/gonzafg2/quantumssh/issues/109)).

## Context

RFC-0008 asks the audit log to record a certificate's serial, key ID,
CA fingerprint and authenticated principal. RFC-0014 settled part of
that before the freeze:

- `authenticated_identity` stays the fingerprint of the key whose
  possession was proven. For a certificate, that is the certified key.
- The certificate's identity goes into additive fields, which RFC-0008's
  implementing ADR names.
- A field added after version 1 may be conditional, if the change that
  adds it says so (§4, "Presence").
- Event fields sit at the top level of the record, and every string is
  escaped by one encoder (§2).

ADR-0024 puts `authenticated_identity` on every `exec.*` event so that
each command can be attributed. A certificate weakens that attribution:
issuers can generate a fresh key for each certificate, and the
fingerprint of such a key names nothing an operator recognises. The key
ID and the serial do.

## Decision

We will add four string fields to `auth.succeeded`, `exec.started` and
`exec.finished` when the session authenticated with a certificate:

| Field | Value |
|---|---|
| `cert_key_id` | the certificate's identifier field (`draft-ietf-sshm-cert` §2.1.1) |
| `cert_serial` | the serial number, in decimal |
| `cert_ca_fingerprint` | the CA key's fingerprint: `SHA256:` and unpadded base64, the format of `authenticated_identity` |
| `cert_principal` | the principal that matched, which is the requested user name (ADR-0050 §5) |

- **All or none.** The four fields appear together on a certificate
  session and never on a bare-key session. A consumer tells the two
  apart by the presence of `cert_ca_fingerprint`. This is the statement
  RFC-0014 §4 requires for conditional fields.
- **`cert_serial` is a string.** A serial is any 64-bit value the issuer
  chooses. A JSON number above 2^53 loses precision in common
  consumers, such as JavaScript and arithmetic in `jq`. A decimal
  string keeps every value exact.
- **`authenticated_identity` does not change.** It remains the
  fingerprint of the certified key, so a consumer keyed on it sees one
  format for every authentication.
- **`auth.failed` does not change.** On a failure, nothing in the
  certificate has been authenticated (ADR-0050 §5), and the audit tier
  records no unauthenticated identity.
- **The CA chooses the text.** `cert_key_id` and `cert_principal` are
  bounded by ADR-0050's 16 KiB certificate bound and escaped like any
  other string (RFC-0014 §2). Neither field is truncated, because a
  truncated identity is not one.

## Consequences

### Positive

- Every command on a certificate session names the identity the CA
  asserted and the issuance it came from, even when the certified key
  is ephemeral.
- After a CA compromise, `cert_ca_fingerprint` finds every session that
  CA authorized.
- No version-1 field changes meaning, and no event is added.

### Negative

- Consumers must treat the four fields as optional.
- `exec.started` and `exec.finished` grow by four fields on certificate
  sessions.

### Neutral

- Bare-key records are byte-for-byte unchanged.
- Within version 1, a later change may add more certificate fields (for
  example, validity), under the same conditional rule.

## Alternatives considered

### Alternative 1: Make `authenticated_identity` the key ID

Rejected by RFC-0014 (§6 and its Alternative 5). One field would hold
two formats, and a consumer keyed on fingerprints would break.

### Alternative 2: `cert_serial` as an integer

This would match the other integers in the catalogue. Rejected because
values above 2^53 lose precision in consumers that decode JSON numbers
as doubles, and serials are not bounded by the issuer.

### Alternative 3: Fields on `auth.succeeded` only

Smaller records. Rejected because RFC-0014 has no connection
identifier: an `exec.*` record could be tied to its certificate only by
`peer_addr` and time, which ADR-0024's attribution rule exists to avoid.

### Alternative 4: One nested `certificate` object

This would group the fields. Rejected because RFC-0014 §2 puts every
event field at the top level of the record.

## Links

- Decision sources: [RFC-0008](../rfcs/0008-ssh-certificate-authentication.md)
  §"Type-state and audit"; [RFC-0014](../rfcs/0014-audit-log-schema-v1.md)
  §2, §4, §5 and §6.
- Feature: [ADR-0050](0050-accept-openssh-user-certificates.md).
- Related: [ADR-0024](0024-phase-1-log-event-schema.md),
  [ADR-0046](0046-audit-log-schema-v1-supersessions-and-encoder.md)
  (the encoder).
- Standard: [`draft-ietf-sshm-cert`](https://datatracker.ietf.org/doc/draft-ietf-sshm-cert/)
  (`-01`), §2.1.1.
