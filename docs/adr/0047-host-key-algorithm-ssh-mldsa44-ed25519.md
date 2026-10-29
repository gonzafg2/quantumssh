# ADR 0047: Offer `ssh-mldsa44-ed25519` as the only server host key algorithm

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-29)
- **Deciders:** Project lead
- **Related:** Subsidiary ADR 2 ("the negotiation-profile entry") of [RFC-0012](../rfcs/0012-composite-host-key-cutover.md) §Subsidiary decisions. It supersedes slot 2 of [ADR-0021](0021-phase-1-negotiation-profile.md) (`server_host_key_algorithms`), under [RFC-0007](../rfcs/0007-cryptographic-primitive-migration-procedure.md) §2 ("Supersession mechanics"). Every other part of ADR-0021 stands. It moves together with [ADR-0048](0048-openssh-interop-client-on-debian-forky.md) (the interop client) and the [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) fixtures, and its signing code uses the crate [ADR-0035](0035-ml-dsa-crate-rustcrypto.md) selects. Implementation: the `kex` and `host_key` modules of `quantumssh-core`, and `tests/interop/run_openssh_client.sh`, in the RFC-0012 implementation PR.

## Context

RFC-0012 decided the cut-over: host authentication moves from
`ssh-ed25519` to the composite `ssh-mldsa44-ed25519`
(`draft-ietf-sshm-composite-sigs-00`), in one step before `0.1.0`, with
exactly one name in `server_host_key_algorithms`. It left the profile
entry to this ADR, because ADR-0021 is Accepted and its slot 2 changes
only by supersession.

RFC-0007 §2 adds a constraint: the ADR-0020 interop fixtures move
atomically with the ADR that supersedes a profile entry, or the gate
tests a profile the server no longer offers. RFC-0012 §Ordering
applies this to the whole cut-over. This ADR is therefore written as
`Proposed` and flips to `Accepted` in the implementation PR, with the
code, ADR-0048 and the fixtures. Until then, ADR-0021's slot 2
(`ssh-ed25519`) is what the server offers.

On 2026-10-29 the draft is still at `-00` (datatracker), and OpenSSH
10.6p1, the latest release, offers the composite by default, as the
last entry of `HostKeyAlgorithms` (`ssh -G` on the Debian
`1:10.6p1-1` client).

## Decision

We will offer exactly one server host key algorithm:

```
ssh-mldsa44-ed25519            # draft-ietf-sshm-composite-sigs-00 §4.1.1, §4.2.2.1
```

- **The slot holds one name.** `ssh-ed25519` is no longer offered as a
  host key algorithm, and no code path signs a host authentication with
  Ed25519 alone. Ed25519 stays compiled in as the composite's second
  half and for user authentication.
- **Not compiled in**, as RFC-0012 lists: `ssh-mldsa87-p384` (ECDSA
  P-384 is on the zero-legacy floor), the experimental
  `ssh-mldsa44-ed25519@openssh.com` name of OpenSSH 10.4 and 10.5, and
  `ssh-mldsa44-ed25519-cert`.
- **The host key file must hold a composite key.** A file of any other
  type, `ssh-ed25519` included, stops the server at startup with
  `server.config_error` of class `invalid_host_key` (RFC-0014), and the
  `error` field names `ssh-mldsa44-ed25519` as the required type.
- **Negotiation failure stays ADR-0021's.** A client that offers no
  common host key algorithm gets `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`
  (3), as for any empty required name-list. There is no fallback.
- **User authentication does not change.** `SSH_MSG_EXT_INFO` keeps
  `server-sig-algs = ssh-ed25519` (ADR-0021).
- **The ADR-0020 gate moves with this ADR.** `run_openssh_client.sh`
  generates its host key with `ssh-keygen -t mldsa44-ed25519` and adds
  two hard checks: `ssh -v` shows `ssh-mldsa44-ed25519` as the
  negotiated host key algorithm, and a client limited to
  `-o HostKeyAlgorithms=ssh-ed25519` fails to negotiate. These checks
  join the subset ADR-0020 makes hard. ADR-0048 provides the client
  that can run them.

## Consequences

### Positive

- Host authentication is post-quantum by default, and the classical
  path is closed, not only less preferred (RFC-0012 §Why exactly one
  algorithm).
- The profile `0.1.0` freezes has its long-term host key entry, so the
  tag carries no planned breaking change.
- Two new hard checks pin the cut-over, so a regression to an Ed25519
  host key fails the gate.

### Negative

- Every client needs OpenSSH 10.6 or another implementation of the
  draft's name. Older clients fail with "no matching host key type".
- Each handshake carries about 3.7 KB more: a 1,344-byte public key
  blob and a 2,484-byte signature, against 32 and 64 bytes for Ed25519.
- An unaudited ML-DSA implementation enters host authentication
  (ADR-0035). The composite contains the risk, because a forgery still
  needs a valid Ed25519 signature.
- The name rests on a `-00` draft. A change before `0.1.0` is absorbed
  by the implementation; after the tag it goes through RFC-0007.

### Neutral

- `kex.completed` and `rekey.completed` report
  `host_key_algorithm = ssh-mldsa44-ed25519` (RFC-0014). The field is a
  string, so the schema does not change.
- On acceptance, ADR-0021's Status line records that slot 2 is
  superseded by this ADR, as ADR-0020's records ADR-0034.

## Alternatives considered

### Alternative 1: Offer both algorithms for a migration window

Rejected by RFC-0012 (§Why exactly one algorithm). Stock clients would
keep negotiating `ssh-ed25519`, and an adversary able to forge Ed25519
would still be accepted by every client that trusts the old key.

### Alternative 2: Also accept the experimental `@openssh.com` name

It would let OpenSSH 10.4 and 10.5 clients connect after enabling the
algorithm by hand. Rejected: those releases have it off by default,
10.6 requires those keys to be regenerated, and `0.1.0` would freeze a
second, vendor-suffixed name into the profile.

### Alternative 3: Change the fixtures in a separate ADR-0020 supersession

Rejected: RFC-0007 §2 makes the fixtures part of the profile change.
Recording them here keeps the profile entry and its interop expectation
in one decision, which lands in one merge.

## Links

- Decision source: [RFC-0012](../rfcs/0012-composite-host-key-cutover.md)
  (§Negotiation, §Not compiled in, §Ordering).
- Superseded entry: [ADR-0021](0021-phase-1-negotiation-profile.md)
  §Decision 2.
- Moves with: [ADR-0048](0048-openssh-interop-client-on-debian-forky.md),
  [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) fixtures.
- Standard: [`draft-ietf-sshm-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-sshm-composite-sigs/)
  (`-00`, 2026-08-22).
- OpenSSH 10.6 release notes ("enable hybrid post-quantum
  ssh-mldsa44-ed25519 signature algorithm"):
  <https://www.openssh.org/releasenotes.html>.
