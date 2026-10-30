# ADR 0050: Accept OpenSSH user certificates from the CAs in `trusted_user_ca_keys`

- **Status:** Accepted
- **Date:** 2026-10-30 (accepted with the implementing PR [#237](https://github.com/gonzafg2/quantumssh/pull/237); drafted 2026-10-30)
- **Deciders:** Project lead
- **Related:** Implementing ADR of [RFC-0008](../rfcs/0008-ssh-certificate-authentication.md) (Accepted; [#41](https://github.com/gonzafg2/quantumssh/issues/41)). Its audit fields are [ADR-0051](0051-certificate-audit-fields.md). It adds the `[auth] trusted_user_ca_keys` key that [RFC-0010](../rfcs/0010-configuration-file.md) reserves and [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md) leaves to "each feature's implementing PR". [ADR-0040](0040-refuse-authorized-keys-options-until-enforced.md) stays in force. It maps the `permit-pty` extension onto the [ADR-0038](0038-phase-2-interactive-pty-sessions.md) §3 gate. Its CA algorithm follows the [RFC-0012](../rfcs/0012-composite-host-key-cutover.md) cut-over ([ADR-0035](0035-ml-dsa-crate-rustcrypto.md), [ADR-0047](0047-host-key-algorithm-ssh-mldsa44-ed25519.md)), and it adds checks to the [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) gate. Part of the Phase-2 milestone ([#109](https://github.com/gonzafg2/quantumssh/issues/109)). Implementation: the `auth` and `transport` modules of `quantumssh-core`, the binary's config loader, and `tests/interop/run_openssh_client.sh`.

## Context

RFC-0008 decided that QuantumSSH adopts certificate authentication in
Phase 2, before `0.1.0` freezes the authentication surface. It
recommended a shape (the native OpenSSH format, a CA key bound to
RFC-0006's composite, short-lived certificates over KRL) and left the
specifics to implementing ADRs. Five of its premises have moved since
2026-07-01:

- **The trust anchor.** RFC-0008 commits Phase 2 to the
  `cert-authority` marker in `authorized_keys`, and gives the reason:
  "that config file does not exist yet". The file now exists (RFC-0010,
  ADR-0029), and RFC-0010 reserves `[auth] trusted_user_ca_keys` for
  this anchor. ADR-0040 refuses every `authorized_keys` line with an
  options field, `cert-authority` included.
- **The CA algorithm.** RFC-0008 allows an Ed25519 CA as "a documented
  interim" until RFC-0006's gates fire. They have fired: RFC-0012 is
  Accepted and moves host authentication to `ssh-mldsa44-ed25519`
  before `0.1.0`. Its implementation waits for an `ml-dsa` release
  with RustCrypto/signatures#1386.
- **The audit fields.** RFC-0014 froze schema version 1, kept
  `authenticated_identity` as the fingerprint of the key whose
  possession was proven, and left the certificate fields additive, to
  be named in this lane (ADR-0051).
- **The format.** `draft-ietf-sshm-cert-01` (2026-06-15) names the type
  `ssh-ed25519-cert`, "equivalent to the vendor extension
  `ssh-ed25519-cert-v01@openssh.com`" (§2.1.4). OpenSSH 10.6p1
  registers only the vendor name (`ssh-ed25519.c:302`).
- **The PTY gate.** ADR-0038 §3 expects certificates to feed its gate
  through `permit-pty`, and leaves the mapping to this lane.

Today the server accepts only `ssh-ed25519` in `publickey` requests
and ignores the requested user name: every authenticated key runs as
the service account (ADR-0016).

## Decision

We will accept OpenSSH user certificates for Ed25519 keys, signed by a
CA listed in `[auth] trusted_user_ca_keys`, and carrying no critical
options.

### 1. Scope

- **User certificates only.** Host certificates stay deferred (RFC-0008
  §Unresolved questions).
- **Expiry is the only revocation.** No KRL, no
  `AuthorizedPrincipalsFile` equivalent, and no `cert-authority` in
  `authorized_keys`, which ADR-0040 keeps refusing.
- **The bare-key path does not change.**

### 2. Wire

- **Algorithm.** A `publickey` request may name
  `ssh-ed25519-cert-v01@openssh.com` as well as `ssh-ed25519`. The blob's
  key type must equal the request's algorithm field. The request
  signature is an `ssh-ed25519` signature by the certified key, checked
  with `verify_strict` as today.
- **No draft name.** `ssh-ed25519-cert` is not accepted, because no
  released client sends it. Adding it later is additive.
- **No profile change.** `server-sig-algs` stays `ssh-ed25519`, as
  ADR-0021 sets it. It lists signature algorithms, and sshd leaves
  certificate types out (`kex.c:332`, `sshkey_alg_list(0, 1, 1, ',')`,
  whose second argument drops certificates). The version-1 profile that
  RFC-0015 proposes ([#223](https://github.com/gonzafg2/quantumssh/pull/223),
  Draft) is unaffected too.

### 3. Trust anchor

- **The key.** `[auth] trusted_user_ca_keys` names a file of CA public
  keys, one per line, `keytype base64 [comment]`. It is optional.
  Without it, a certificate fails like an unknown key. It has no
  command-line flag (RFC-0010: "everything new lives only in the
  file"). ADR-0029 has each feature's implementing PR add its keys
  before the `0.1.0` freeze, so the key is part of schema version 1.
  RFC-0016 ([#224](https://github.com/gonzafg2/quantumssh/pull/224),
  Draft) would also count it as an additive change.
- **Loading.** The file is read once at startup under the
  `authorized_keys` rules: blank and `#` lines are skipped, an options
  field is refused (ADR-0040), a file without keys is refused, and
  ADR-0029's ownership and permission checks apply. A file that is read
  but cannot be loaded stops the server with `server.config_error` of
  the new class `invalid_trusted_user_ca_keys`. A new enumeration value
  is additive under RFC-0014 §5.
- **Matching.** A CA is trusted when its public key blob equals one in
  the file, byte for byte. A certificate key is never accepted as a CA
  (draft §2.1.1).

### 4. CA algorithm

- **Now: `ssh-ed25519` only**, RFC-0008's interim.
- **At the RFC-0012 implementation: `ssh-mldsa44-ed25519` only.** That
  PR flips the accepted CA algorithm in the same merge that makes
  ADR-0047 Accepted. From then on, an `ssh-ed25519` line in the CA file
  stops the server with `invalid_trusted_user_ca_keys`, so `0.1.0` ships
  with the composite CA only.
- **The certified key stays Ed25519.** Users keep their keys; only the
  CA signature changes.

### 5. Verification

Verification runs in the `Expect<UserAuth>` stage, with no new stage
and no accept-and-branch (RFC-0003). A certificate is accepted only if
every check passes, in this order:

1. **It parses within bounds.** The blob is at most 16 KiB; a composite
   CA brings it to about 4 KB (ADR-0047: a 1,344-byte key and a
   2,484-byte signature). It has at most 256 principals (OpenSSH's
   `SSHKEY_CERT_MAX_PRINCIPALS`) and a nonce of at least 16 bytes
   (draft §2.1.1). Its options and extensions parse as name and data
   string pairs. Every length is checked against what remains before
   anything is allocated.
2. **Its signature key is a trusted CA** of the accepted algorithm (§3,
   §4). This runs before the signature check, so an untrusted CA costs
   no verification.
3. **The CA signature verifies** over every field up to and including
   the signature key (draft §2.1.1), with `verify_strict` for Ed25519.
4. **The role is user.** A host certificate is refused.
5. **It is valid now:** `valid after <= now < valid before`, on the
   system clock, with no skew allowance (`sshkey.c:2454-2461`).
6. **The requested user name is a principal,** compared byte for byte,
   without patterns, as sshd does without `AuthorizedPrincipalsFile`
   (`auth2-pubkey.c:599`). An empty principal list is refused.
7. **There are no critical options.** Any critical option refuses the
   certificate, including the defined `force-command`, `source-address`
   and `verify-required`. The draft requires refusing an option the
   server does not support (§2.4), and ADR-0040's rule applies: accept
   an option only once it is enforced. Each option needs its own ADR.

The request then proceeds as for a bare key. A probe without a
signature gets `SSH_MSG_USERAUTH_PK_OK`, and a signed request is
verified against the certified key.

**Failure looks like an unknown key.** The server answers
`SSH_MSG_USERAUTH_FAILURE`, emits `auth.failed` and spends an attempt,
and the client learns no reason. A diagnostic record (not the audit
tier) gives one fixed reason: `malformed`, `untrusted_ca`,
`bad_ca_signature`, `not_user_certificate`, `not_yet_valid`, `expired`,
`principal_mismatch` or `critical_option`. No certificate string is
logged on failure, because nothing in it is authenticated before check
3 passes.

### 6. Extensions

- **`permit-pty` feeds the ADR-0038 §3 gate.** A session authenticated
  by a certificate without it gets no PTY. `ssh-keygen -s` includes it
  by default.
- **Every other extension is ignored**, as the draft requires
  (§2.1.1). The others OpenSSH defines (`permit-X11-forwarding`,
  `permit-agent-forwarding`, `permit-port-forwarding`,
  `permit-user-rc`, `no-touch-required`) govern capabilities the server
  does not have. The ADR that adds one maps its extension, and absence
  means denied.
- **The certificate is the only policy source** for its session. Bare
  keys carry no options (ADR-0040), so nothing is merged.

### 7. Identity

- **`authenticated_identity`** is the fingerprint of the certified key
  (RFC-0014 §6). ADR-0051 adds the certificate's own fields.
- **The executing UID does not change** (ADR-0016). A principal does
  not select an account. That mapping is Phase-3 work
  ([#43](https://github.com/gonzafg2/quantumssh/issues/43), RFC-0008
  §Future possibilities).
- **Only the certificate path reads the user name,** because only there
  has a CA bound it to the key.
- **The CA file is the access boundary.** Every session runs as the
  service account and the client chooses the user name, so the
  principal match fixes the name a certificate logs in under, not
  whether it gets in. Until Phase 3, every certificate a trusted CA
  issued, for any principal, authenticates. Operators should trust a CA
  dedicated to this server.

### 8. Interop gate

ADR-0020's driver gains hard checks, as ADR-0047 added its own.
`ssh-keygen -s` signs a user certificate with a principal and a
validity window, using a CA listed in `trusted_user_ca_keys`. The exec
round trip runs with that certificate. A certificate for another
principal, an expired certificate, and a certificate from a CA that is
not in `trusted_user_ca_keys` all fail to authenticate. With
the RFC-0012 implementation, the CA becomes `-t mldsa44-ed25519` on
ADR-0048's client.

## Consequences

### Positive

- The threat model's §5.3.2 mitigant exists. A stolen short-lived
  certificate expires on its own, and adding a user no longer means
  editing `authorized_keys` on every host.
- The CA, the highest-value key, is post-quantum at `0.1.0`.
- The negotiation profile does not change, and no dependency is added:
  Ed25519 and SHA-256 are already in use, and the composite verifier
  comes with ADR-0035.
- After the freeze, the config schema gains one optional key and the
  audit schema only additive fields. Both rules allow that.

### Negative

- New attacker-supplied parsing runs before authentication (threat
  model §4.1). It is bounded, written as a pure function over bytes so
  it can be fuzzed, and it stops before any signature work when the CA
  is untrusted.
- At `0.1.0`, only `ssh-keygen` from OpenSSH 10.6 or later can issue
  certificates. On 2026-10-30, no ML-DSA SSH CA support was found for
  Vault, step-ca or Teleport. The `step` CLI added ML-DSA keys in
  smallstep/cli#1698, which states that its SSH commands do not support
  them yet.
- Certificates that carry critical options are refused, including
  `source-address` and `force-command` set by an issuer's role.
- Without `-V`, `ssh-keygen -s` issues a certificate that never
  expires, and the server accepts it. Expiry is the only revocation, so
  the operator guide must require `-V`. A maximum-lifetime setting is
  left to a later ADR.
- Trusting a CA admits every certificate it issued, for any principal,
  until Phase 3 maps principals to accounts (§7). A CA shared with other
  hosts shares access to this one.

### Neutral

- `auth.failed` does not change. The failure reasons are diagnostic
  records, which RFC-0014 §5 lets change.
- `AuthError` and the userauth bounds change, which is acceptable
  before `0.1.0` (as for ADR-0040).
- The RFC-0012 implementation PR gains the CA flip of §4.

## Alternatives considered

### Alternative 1: `cert-authority` in `authorized_keys`

This is RFC-0008's literal Phase-2 surface. It would supersede ADR-0040
and bring back the option-grammar parser that ADR-0040 removed, plus
`principals=`. RFC-0008 chose it only because the config file did not
exist, and RFC-0010 then reserved `trusted_user_ca_keys`. Not chosen. A
later ADR can add it as a second anchor.

### Alternative 2: Enforce `source-address`, or `force-command` too

`source-address` binds a certificate to networks. `force-command`
replaces exec, shell and subsystem requests, and it needs a decision on
what `command` records in the audit log. Not chosen for the first cut,
because the default issuers emit no critical options and ADR-0040 admits
an option only together with its enforcement. Each can follow in its own
ADR.

### Alternative 3: Keep the Ed25519 CA at `0.1.0` next to the composite

This works with today's issuers. Rejected: RFC-0008 makes the Ed25519
CA an interim that is "not a standing exception to zero-legacy", and
its gates have fired. Dropping a CA algorithm after the tag would break
every configuration that uses it.

### Alternative 4: Accept any principal

This would match the bare-key path, which ignores the user name.
Rejected: RFC-0008 requires a principal match, and Phase 3 maps
principals to accounts
([#43](https://github.com/gonzafg2/quantumssh/issues/43)), so accepting any name now would make that
mapping a breaking change. Until then, the match fixes the name that a
certificate logs in under and that `cert_principal` records. It does
not limit who gets in (§7).

### Alternative 5: Also accept the draft name `ssh-ed25519-cert`

No released client sends it, so offering it now adds an untested
branch. It is an additive change once a client does.

## Links

- Decision source: [RFC-0008](../rfcs/0008-ssh-certificate-authentication.md).
- Trust surface: [RFC-0010](../rfcs/0010-configuration-file.md)
  (guide-level example), [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md)
  §Decision, RFC-0016 ([#224](https://github.com/gonzafg2/quantumssh/pull/224), Draft).
- Related ADRs: ADR-0016, ADR-0020, ADR-0021, ADR-0035, ADR-0038,
  ADR-0040, ADR-0047, ADR-0048, ADR-0051.
- Related RFCs: RFC-0003, RFC-0012, RFC-0014, RFC-0015
  ([#223](https://github.com/gonzafg2/quantumssh/pull/223), Draft).
- Threat model: §4.1, §5.3.2, §6.3.
- Standard: [`draft-ietf-sshm-cert`](https://datatracker.ietf.org/doc/draft-ietf-sshm-cert/)
  (`-01`, 2026-06-15).
- Prior art, OpenSSH at `V_10_6_P1`: `auth2-pubkey.c`
  (`user_cert_trusted_ca`), `sshkey.c` (`sshkey_cert_check_authority`),
  `auth-options.c` (`cert_option_list`), `kex.c` (`server-sig-algs`).
- Issues: [#41](https://github.com/gonzafg2/quantumssh/issues/41),
  [#109](https://github.com/gonzafg2/quantumssh/issues/109).
