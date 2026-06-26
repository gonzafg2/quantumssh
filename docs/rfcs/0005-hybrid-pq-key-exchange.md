# RFC 0005: Hybrid post-quantum key exchange as the only KEX posture

- **Status:** Accepted (2026-06-26)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-06-25
- **Roadmap issue:** [`#9`](https://github.com/gonzafg2/quantumssh/issues/9) (Phase 1 / Hito 1)
- **Implementation PR:** TBD (lands with the Phase 1 `kex` module)

## Summary

QuantumSSH offers exactly one key exchange — `mlkem768x25519-sha256`, a
**hybrid** that combines ML-KEM-768 (a post-quantum KEM, FIPS 203) with
X25519 (classical ECDH). This RFC records the *posture* decision behind that
choice: the KEX is hybrid, not post-quantum-pure and not classical-only; it
is mandatory, not opt-in; and failure of **either** half aborts the
handshake with no fallback to the surviving half.

This RFC **ratifies and refines** an existing commitment; it does not put it
up for first-time adoption. The hybrid posture is already binding —
MANIFIESTO #2 states it, and [RFC-0003](0003-phase-1-ssh-stack-greenfield-vs-russh.md)
fixed "hybrid PQ KEX only" as part of the greenfield stack. This RFC neither
supersedes nor re-opens RFC-0003: it extracts the reasoning that was left
implicit there and assembled at the wire level in
[ADR-0021](../adr/0021-phase-1-negotiation-profile.md), and gives it one
owning document. What the comment period is invited to scrutinise is the
*articulation* — whether the rationale, the boundaries, and the prior-art
citations are sound — not *whether* QuantumSSH is post-quantum by default,
which is a foundational commitment and out of scope for revision here (a
challenge to that belongs in an RFC that amends MANIFIESTO #2 itself). The
exact algorithm strings, their order, and the wire failure codes remain
ADR-0021's; the threat model §6.1 and the README state the same posture in
their own registers.

## Motivation

MANIFIESTO commitment #2 ("post-quantum by default, not by opt-in") and the
README non-goal "if your client cannot speak modern, hybrid-PQ SSH, it does
not connect" both name the *hybrid* posture, but as assertions. The lane
rules ([README](README.md)) route "a change to default cryptographic
algorithms" and "anything that … refines a commitment in `README.md` or
`MANIFIESTO.es.md`" to the RFC process. Leaving the project's single most
load-bearing cryptographic posture resting on assertion alone — with the
*why* scattered across four documents and no document owning the
hybrid-vs-pure rationale — is the same gap RFC-0004 closed for the async
runtime. This RFC closes it for the KEX before the first crate lands.

The threat this posture answers is **Harvest Now, Decrypt Later** (HNDL):
an adversary records a classical SSH session today and decrypts it once a
cryptographically-relevant quantum computer exists (`docs/threat-model.md`
§5.2.1, §6.1). A classical-only KEX is fully exposed to HNDL. A
post-quantum-pure KEX answers HNDL but stakes the entire session on a
single, comparatively young primitive. The hybrid answers HNDL **and**
retains the decades of cryptanalysis behind X25519 as a floor.

## Guide-level explanation

An operator running QuantumSSH sees one key exchange offered in
`SSH_MSG_KEXINIT`: `mlkem768x25519-sha256`. There is no knob to disable the
post-quantum half, no knob to disable the classical half, and no second KEX
to fall back to. A peer that does not offer this exact hybrid is sent
`SSH_DISCONNECT_KEY_EXCHANGE_FAILED` and does not connect.

The guarantee an operator can rely on is **additive security**: an attacker
who breaks the session must break *both* ML-KEM-768 *and* X25519 for the
*same* handshake. A future quantum computer that fells X25519 still faces
ML-KEM; an as-yet-undiscovered flaw in ML-KEM (the younger primitive) still
faces X25519. The session is never weaker than the stronger of its two
halves, and the new post-quantum cryptography is purely additive — it can
never make QuantumSSH *less* safe than a classical SSH server.

This RFC governs the **key exchange** only. User and host authentication use
Ed25519 (classical) signatures by deliberate design; the post-quantum
signature target and the triggers that would adopt it are tracked in
[issue #42](https://github.com/gonzafg2/quantumssh/issues/42) and are out of
scope here (one decision per RFC). The boundary is principled, not
incidental — see *Reference-level explanation*.

## Reference-level explanation

**The construction.** `mlkem768x25519-sha256` is specified by
`draft-ietf-sshm-mlkem-hybrid-kex`. Both halves run for every handshake: an
X25519 ECDH and an ML-KEM-768 encapsulation. The shared secret is
`K = SHA-256(K_PQ || K_CL)` — the post-quantum and classical secrets, each
as a fixed-length byte array, concatenated post-quantum-first and hashed
(`draft-ietf-sshm-mlkem-hybrid-kex` §2.4). This order and encoding are
**mandated by the draft, not chosen here**; ADR-0021 and the `kex` module of
`quantumssh-core` (TBD — no code has landed yet) inherit them, and ADR-0021
fixes only what the draft leaves to the profile (the offered name-list, its
ordering, and the disconnect codes). Neither half's secret is usable on its
own; an attacker needs both.

**Fail closed, both halves.** Per `docs/threat-model.md` §5.2.1 and ADR-0021,
a failure of either half aborts the handshake — there is no fallback to the
surviving half, and no downgrade to any other KEX. This must be enforced
*explicitly*, because FIPS 203 decapsulation uses **implicit rejection**: a
malformed ML-KEM ciphertext does not raise an error, it returns a
deterministic pseudo-random shared secret. The implementation must therefore
treat a mismatched key confirmation as fatal rather than rely on
decapsulation to signal failure. This is a pre-authentication path concern
(threat model §4.1): the parsing and the both-halves enforcement sit on the
highest-trust surface and must be fuzzable.

**No downgrade path may exist.** A second, weaker KEX offered "for
compatibility" would reintroduce the Terrapin-class downgrade bug
(CVE-2023-48795) the project structurally forbids: the posture's value
depends on there being nothing to fall back *to*. Strict-kex
(`kex-strict-{c,s}-v00@openssh.com`) is required, not merely offered
(ADR-0021); the type-state transport (RFC-0003) makes "accept and branch on
a downgrade" structurally unrepresentable.

**Why the boundary at signatures is principled.** HNDL is a confidentiality
attack against *recorded* ciphertext: it is retroactive, so the KEX must
resist an adversary who does not yet exist at handshake time. An online
authentication signature has no equivalent retroactive exposure — a forged
handshake signature is only useful to an attacker who already possesses the
quantum capability *during* the live handshake, a strictly later threat than
HNDL. Spending post-quantum hardening first on the KEX, where the retroactive
exposure is, and tracking PQ signatures separately (issue #42), is the
posture, not an oversight. The same reasoning is visible in deployed systems
(see *Prior art*), which adopted hybrid PQ key establishment years before PQ
signatures.

## Drawbacks

- **Handshake size.** An ML-KEM-768 public key/ciphertext is ~1 KB versus
  X25519's 32 bytes, enlarging the first round-trip. For an
  interactive/administrative SSH server this is negligible; it is a real cost
  for very high connection-churn workloads. Accepted.
- **More pre-auth code than either pure option.** A hybrid runs two
  primitives plus a combiner, all on the highest-trust surface, where a
  classical-only or PQ-pure KEX would run one. More code is more attack
  surface and more to fuzz. This is the price of additive security and is
  judged worth paying; the surface is bounded by offering exactly one hybrid.
- **No algorithm agility.** Offering a single KEX means any future migration
  (ML-KEM-1024, a `-v01` construction) is a profile change that must supersede
  ADR-0021 and move the interop fixtures with it. This coupling is deliberate
  (the profile is security-load-bearing) but it is friction — already recorded
  as a negative consequence in ADR-0021.

## Rationale and alternatives

- **Post-quantum-pure KEX (drop X25519).** The smallest "post-quantum"
  surface. Rejected: it stakes every session on ML-KEM alone — a primitive
  standardised in 2024 with far less sustained cryptanalysis than X25519. A
  design or implementation flaw in ML-KEM would be total, with no classical
  floor beneath it. The hybrid's entire point is to not take that bet while
  HNDL forces us off classical-only.
- **Classical-only KEX (X25519 / the SSH status quo).** Rejected outright: it
  is fully exposed to HNDL, which is the project's reason to exist. This is the
  non-goal the README states.
- **Hybrid, but opt-in (offer a classical KEX too).** Rejected: it violates
  MANIFIESTO #2 and reintroduces a downgrade path — the very Terrapin-class bug
  the type-state transport and strict-kex exist to eliminate. "Post-quantum by
  default" with a classical fallback is post-quantum by *opt-in*, the thing #2
  forbids.
- **Multiple hybrids / algorithm agility now (e.g. also offer
  `mlkem1024nistp384-sha384`).** Rejected for Phase 1: a second hybrid pulls
  NIST P-384 (another ECDH primitive and curve) onto the pre-auth path,
  contradicting MANIFIESTO #4, and the threat model §8.7 scopes CNSA-2.0/NSS
  out. Tracked as an additive, RFC-gated change in issue #42, not a Phase 1
  default. ADR-0021 Alternative 3 records the same call at the wire level.

The impact of *not* doing this RFC: the posture stays binding but its
reasoning stays scattered across four documents, so anyone weighing a future
*additive* change (a second hybrid, an ML-KEM-1024 profile — issue #42) must
reconstruct the original rationale from prose rather than read it in one
owning document. The decision itself is not in question; its discoverability
is — exactly the reconstruct-from-prose cost the RFC process exists to
prevent.

## Prior art

- **`draft-ietf-sshm-mlkem-hybrid-kex`** — the IETF draft registering
  `mlkem768x25519-sha256`; QuantumSSH implements its construction rather than
  inventing one.
- **OpenSSH 10.x** — ships `mlkem768x25519-sha256` as its *default* KEX.
  QuantumSSH offers the same hybrid as its *only* KEX; interop holds because
  OpenSSH's broad offer intersects QuantumSSH's narrow one (ADR-0021).
- **Apple PQ3 (iMessage) and the `corecrypto` release.** The most relevant
  external validation of this exact posture. PQ3, deployed across ~2.5 billion
  devices since iOS 17.4, uses a **hybrid** design combining Elliptic Curve
  cryptography with ML-KEM, explicitly so that "PQ3 can never be less safe than
  the existing classical protocol" and "defeating PQ3 security requires
  defeating both" halves — the same additive-security and fail-closed reasoning
  as §*Reference-level explanation* here. PQ3 has independent formal-security
  analyses (Stebila, IACR ePrint [2024/357](https://eprint.iacr.org/2024/357);
  a TAMARIN machine-checked proof, USENIX Security 2025). Apple published its
  ML-KEM/ML-DSA `corecrypto` implementations and formal-verification tooling on
  2026-05-22 ([Apple Security Research](https://security.apple.com/blog/formal-verification-corecrypto/),
  [PQ3 design](https://security.apple.com/blog/imessage-pq3/)).
  Two qualifications matter for citing it accurately:
    1. **Layer.** `corecrypto` is a *primitives* library — it exposes ML-KEM
       and ECDH separately; the *hybrid composition* lives one layer up in the
       PQ3 protocol, not in that repository. QuantumSSH *is* the protocol, which
       is why its hybrid is explicit in the KEX name. Comparing the two compares
       a primitives library with a full SSH server.
    2. **Licence.** Despite wide "open source" reporting, `corecrypto`'s default
       licence is the evaluation-only corecrypto Internal Use License Agreement
       (non-redistributable; GitHub marks it `NOASSERTION`). Only the
       formal-verification tooling carries permissive per-subdirectory licences.
       It is source-available for evaluation plus open verification tooling — not
       OSI/Apache open source like QuantumSSH. It is cited here as external
       design corroboration, never as a reusable code source.
  Notably, PQ3 pairs its hybrid PQ **key exchange** with **classical** (ECDSA)
  authentication signatures — the same KEX-PQ-now / signatures-classical-now
  split this RFC takes — because its secure-enclave hardware did not yet support
  ML-DSA. This is independent confirmation that the signature boundary
  (issue #42) is a recognised engineering posture, not a QuantumSSH idiosyncrasy.
- **Signal PQXDH** and **TLS `X25519MLKEM768`** (deployed by major browsers/CDNs)
  — the same X25519+ML-KEM hybrid pattern in messaging and in TLS, evidence the
  construction is the cross-ecosystem consensus for PQ key establishment.
- **NIST FIPS 203 (ML-KEM)** — the standard the post-quantum half conforms to.

A deliberate divergence from Apple/PQ3 and the NIST-suite deployments:
QuantumSSH uses **X25519** for the classical half, not NIST **P-256/P-384**.
MANIFIESTO #3 excludes NIST elliptic curves from the *signature* surface
(it names ECDSA-NIST); it does not, by its letter, govern the ECDH half. This
RFC **extends that same principle** to the classical-ECDH half as a reasoned
choice — a stricter, non-NIST-curve posture, not a direct mandate of #3. The
wire-level form of this call is ADR-0021 Alternative 3, which rejects a
P-384-bearing hybrid.

## Unresolved questions

- **Post-quantum signatures** (host/user auth) — deliberately out of scope;
  owned by issue #42. This RFC fixes only that the *KEX* is hybrid-PQ and the
  *signatures* remain classical for Phase 1, not when or how PQ signatures land.
- **An ML-KEM-1024 profile** for CNSA-2.0-adjacent operators — additive and
  RFC-gated if pursued; tracked by issue #42, not decided here.

## Future possibilities

- An additive `mlkem1024…` hybrid profile, RFC-gated, if real demand appears
  (issue #42).
- Post-quantum authentication signatures once the target primitive and its
  triggers are decided (issue #42), at which point the signature half of the
  posture catches up to the KEX half documented here.
- If a future construction supersedes `mlkem768x25519-sha256`, a superseding
  RFC owns that migration and links back to this one; accepted RFCs are not
  edited in place.
