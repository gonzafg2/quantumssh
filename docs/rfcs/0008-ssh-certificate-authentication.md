# RFC 0008: SSH certificate authentication

- **Status:** Accepted (2026-07-01)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-07-01
- **Roadmap issue:** [`#41`](https://github.com/gonzafg2/quantumssh/issues/41)
- **Implementation PR:** TBD — a Phase-2 feature; see the config-surface dependency in [§Reference-level explanation](#reference-level-explanation).

## Summary

QuantumSSH authenticates users with bare `ssh-ed25519` keys listed in
`authorized_keys` (M4). This RFC designs the Phase-2 addition the threat model
names in §5.3.2: **SSH certificate authentication**. It fixes three decisions:
(1) adopt the **native OpenSSH certificate format** (`*-cert-v01@openssh.com`,
tracking [`draft-ietf-sshm-cert`](https://datatracker.ietf.org/doc/draft-ietf-sshm-cert/)),
and **reject X.509** outright on the small-surface commitment; (2) the **CA
signing key is bound to [RFC-0006](0006-post-quantum-host-key-signatures.md)'s
composite ML-DSA+Ed25519 posture and its two adoption gates** — because a CA key
is higher-value than any single host key (one forgery = universal
impersonation); (3) **short-lived certificates are the primary revocation
story** (time-replaces-revocation), with KRL as a bounded, opt-in add-on, not a
launch requirement. It does not add code now; it removes the ambiguity of *what
format, what CA posture, what revocation*.

## Motivation

**The gap ([#41](https://github.com/gonzafg2/quantumssh/issues/41)).** The threat
model names "certificate-based authentication with short lifetimes" as a **Phase-2
mitigant** for the stolen-private-key attack (§5.3.2) and lists per-key
restrictions in §6.3 — but the certificate path is undesigned. The promise exists;
the mechanism does not.

**The operational cost it removes.** Without certificates, revoking a compromised
key means editing `authorized_keys` on every host that trusts it. At any real
scale (>3 hosts) that is a genuine operational burden, and it is the standard
motivation for certificate auth (OpenSSH has had it since 2010). Short-lived
certificates additionally make "what do we do when a key is stolen?" answerable
without a revocation dance: the credential simply expires.

**Why decide now.** Phase 2 introduces the config file and `0.1.0` — the point at
which the authentication surface (trust anchoring, cert format, audit fields)
becomes public interface. Designing certificates after `0.1.0` without a plan is
a breaking change to the wire, the config, and the audit schema at once.

## Guide-level explanation

An operator today lists each user's public key in `authorized_keys`. With
certificate auth, the operator instead trusts a **certificate authority (CA)**:
any user presenting a certificate signed by that CA, valid for the requested
principal and within its validity window, authenticates — no per-key enrollment.

A QuantumSSH certificate is the **native OpenSSH certificate** (the same object
`ssh-keygen -s` produces): a signed statement binding a public key to a set of
**principals** (usernames it may act as), a **validity window** (`valid after` /
`valid before`), and **critical options / extensions** (e.g. `force-command`,
`source-address`). QuantumSSH verifies the CA signature, that the certificate is
a **user** certificate (host-type certificates are rejected), the validity
window, the principal, and the critical options, then treats the certificate's
key as authenticated.

The **recommended deployment is short-lived certificates**: an issuing service
(Teleport, HashiCorp Vault's SSH engine, step-ca, or `ssh-keygen -s` in a script)
signs certificates with a TTL of minutes to hours. Revocation becomes expiry —
no server-side revocation list to distribute. This is the pattern the ecosystem
has converged on.

Nothing changes for the bare-key path: `authorized_keys` continues to work.
Certificates are additive.

## Reference-level explanation

### Format: native OpenSSH, not X.509

QuantumSSH adopts `ssh-ed25519-cert-v01@openssh.com` and its composite-CA
successor (below), tracking [`draft-ietf-sshm-cert`](https://datatracker.ietf.org/doc/draft-ietf-sshm-cert/)
(WG-adopted; formalises the long-standing `PROTOCOL.certkeys`). The wire object
carries: a `nonce` (≥16 bytes, at the front, anti-chosen-prefix), the public-key
fields, `serial` (uint64), `type` (user/host), key id, valid principals
(zero-length = any — QuantumSSH **rejects** the zero-length "any" form for user
certs; a principal is mandatory), `valid after` / `valid before`, `critical
options`, `extensions`, and the **signature key + signature**.

**X.509 (`x509v3-*`, RFC 6187) is rejected** on commitment #4: it pulls an
ASN.1/DER parsing surface onto the pre-auth path, which is precisely the kind of
large, historically CVE-dense surface the project refuses. The native format is
smaller, is what the ADR-0020 reference client speaks, and is the WG's SSH-native
track.

### The CA signing key is bound to RFC-0006

The certificate's `signature key` field is **algorithm-agnostic** — the format
does not care what key type signs it. This lets the *format* and the *CA
algorithm* be sequenced independently. The decision:

- **The CA signing key adopts [RFC-0006](0006-post-quantum-host-key-signatures.md)'s
  composite `ssh-mldsa44-ed25519@openssh.com` target and its two adoption gates**
  (SSHM WG adoption + a stock OpenSSH release). Rationale: a CA key is strictly
  higher-value than a single host key — one forgery yields *universal*
  impersonation of every principal the CA can sign — so it deserves the highest
  bar, not a lower one.
- **The format may ship earlier with an Ed25519 CA** under the same
  harvest-now asymmetry RFC-0006 uses for host keys (a certificate signature is
  only forgeable *live*, at validation time, so no HNDL exposure), then flip the
  CA to composite when RFC-0006's gates fire. This is a documented interim, not a
  standing exception to zero-legacy.

### Trust anchoring, revocation, and policy

- **Trust anchoring.** Two surfaces: the `cert-authority` marker in
  `authorized_keys` (fits the *current* surface — the server already reads that
  file) and a `TrustedUserCAKeys`-equivalent in the **Phase-2 config file**.
  Because that config file does not exist yet, `cert-authority`-in-`authorized_keys`
  is the only Phase-2 trust surface this RFC commits to; the config-file form is
  a Phase-2-config-RFC extension.
- **Revocation.** **Short-lived certificates are primary** (expiry replaces
  revocation). **KRL** ([`PROTOCOL.krl`](https://www.openssh.com/txt/PROTOCOL.krl))
  is an **opt-in, explicitly-bounded** add-on, not a launch requirement: a KRL is
  attacker-influenced input loaded by the server, so it must be size-bounded and
  fuzzable, and — per OpenSSH ≥9.4 — SSHSIG-signed rather than internally signed.
- **Critical options / extensions.** Unrecognised **critical options MUST be
  rejected** (fail closed); unrecognised **extensions MAY be ignored** (per the
  format). QuantumSSH honours a bounded, explicit allow-list of critical options
  and reconciles them with the existing per-key `from=` / `command=` semantics
  (threat-model §6.3): the certificate is the single policy source when present,
  the `authorized_keys` options when a bare key is used — never both silently
  merged.

### Type-state and audit

- **Verification lives in the userauth stage** of the type-state machine
  ([RFC-0003](0003-phase-1-ssh-stack-greenfield-vs-russh.md)): CA-trust check,
  **certificate type (MUST be `user`; host-type certificates are rejected)**,
  validity window, principal match, critical-options, and (if configured)
  revocation, added as new logic in that stage — **without** loosening the
  machine to "accept and branch" (the Terrapin bug class CLAUDE.md forbids).
- **Audit schema.** Certificates introduce first-class fields the ADR-0024
  schema lacks: certificate `serial`, key id, CA fingerprint, and the authenticated
  `principal`. `authenticated_identity` (today the key fingerprint) must record
  the certificate identity. Because [ADR-0024](../adr/0024-phase-1-log-event-schema.md)
  is Accepted and immutable, these fields land via a **superseding ADR**, per the
  RFC-0007 supersession mechanics.

## Drawbacks

- **New attacker-supplied parser on the highest-trust path.** Certificate parsing
  (nonce, principals, options, validity) runs pre-auth; it must be bounded and
  fuzzable, and it is net-new surface — in tension with commitment #4. Mitigated
  by choosing the smaller native format over X.509 and by an allow-listed,
  fail-closed critical-options handler.
- **KRL adds server-side state.** A revocation list is a new loaded, parsed,
  attacker-influenced input. Mitigated by making it opt-in and bounded, and by
  making short-lived certs the primary story so most deployments never load one.
- **CA-availability dependency.** Short-lived certs push a dependency onto an
  issuing CA and require break-glass planning. This is inherent to the model, not
  QuantumSSH-specific.
- **Betting the CA on a pre-adoption composite draft.** The composite CA inherits
  RFC-0006's gate risk; mitigated identically — the gates mean the composite CA
  is not implemented until its identifier is stable and deployed.

## Rationale and alternatives

- **Native OpenSSH cert + composite CA bound to RFC-0006 (this RFC).** Chosen:
  smallest pre-auth surface, aligned with the ADR-0020 client and the WG track,
  and it puts the highest-value key (the CA) on the strongest posture.
- **X.509 certificates (`x509v3-mldsa-*`, RFC 6187).** Rejected: the ASN.1 surface
  squarely contradicts commitment #4 and is heavier than the native format, for no
  offsetting benefit in QuantumSSH's deployment model.
- **Ed25519 CA, decided separately from RFC-0006.** Rejected as the *end state*
  (accepted only as a documented interim): leaving the highest-value key classical
  with no migration tether is the opposite of the posture RFC-0006 set for
  host keys, which are individually *lower* value.
- **KRL as the primary revocation mechanism.** Rejected as primary: it maximises
  server-side state and attacker-influenced input; short-lived certs achieve
  revocation with none. KRL remains available opt-in.

**Impact of not doing this:** #41 stays open, the §5.3.2 stolen-key mitigant stays
unbuilt, and certificate support added post-`0.1.0` becomes an unplanned breaking
change to wire, config, and audit schema.

## Prior art

- [`draft-ietf-sshm-cert`](https://datatracker.ietf.org/doc/draft-ietf-sshm-cert/)
  (WG-adopted; formerly `draft-miller-ssh-cert`) and OpenSSH `PROTOCOL.certkeys` —
  the native format.
- [`PROTOCOL.krl`](https://www.openssh.com/txt/PROTOCOL.krl) — the revocation-list
  format; SSHSIG-signed KRLs per OpenSSH ≥9.4.
- Short-lived-certificate practice: Teleport, HashiCorp Vault SSH secrets engine,
  step-ca — the "time replaces revocation" consensus.
- [RFC-0006](0006-post-quantum-host-key-signatures.md) (composite signature target
  the CA key inherits) and [RFC-0007](0007-cryptographic-primitive-migration-procedure.md)
  (the live-only exposure class the CA key falls in, and the supersession mechanics
  the audit-schema change follows).
- `draft-rpe-ssh-x509-mldsa` (the X.509 route this RFC rejects); RFC 6187
  (X.509 in SSH).

## Unresolved questions

- **User certificates only, or host certificates too?** Host certificates
  interact with RFC-0006's host-key posture and `known_hosts`; this RFC scopes
  **user** certificates and defers host certificates to a follow-up (they are a
  separable decision).
- **The config-file trust surface** (`TrustedUserCAKeys`-equivalent) — deferred to
  the Phase-2 config RFC; Phase-2 ships with `cert-authority`-in-`authorized_keys`
  only.
- **The superseding ADR-0024 fields** — exact names/shape for serial, key id, CA
  fingerprint, principal.
- **KRL scope** — whether it ships at all in the first cut or is purely a
  documented opt-in extension point.
- **User-authentication ML-DSA keys** (bare, not certificate) — RFC-0006
  §Future-possibilities names them; whether that is part of #41 or separate.

## Future possibilities

- **Host certificates**, removing TOFU for the host-key side.
- **The Phase-2 config RFC** adds the `TrustedUserCAKeys`-equivalent trust surface
  and any KRL configuration.
- **Certificate principals as the key→OS-user mapping** the Phase-3 privilege
  separation work ([#43](https://github.com/gonzafg2/quantumssh/issues/43)) needs.
