# RFC 0006: Post-quantum host key signatures — the ML-DSA composite migration target

- **Status:** Accepted (2026-06-30)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-06-30
- **Roadmap issue:** [`#40`](https://github.com/gonzafg2/quantumssh/issues/40)
- **Implementation PR:** TBD — **gated**; no implementation lands until both adoption gates in [§Reference-level explanation](#reference-level-explanation) fire.

## Summary

QuantumSSH authenticates the host with a **classical** `ssh-ed25519`
key ([ADR-0021](../adr/0021-phase-1-negotiation-profile.md)). That is a
deliberate, documented choice, not an oversight
([`threat-model.md`](../threat-model.md) §6.1/§7): a host-key signature
need only be unforgeable *at connection time*, so it carries no
harvest-now-decrypt-later exposure the way session confidentiality does —
and when Phase 1 shipped, no post-quantum signature type was deployable
in the SSH ecosystem.

This RFC records the **exit path** from classical signatures without
implementing it yet. It fixes the migration target as
`ssh-mldsa44-ed25519@openssh.com` — a **composite** ML-DSA-44 + Ed25519
signature ([draft-miller-sshm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-mldsa44-ed25519-composite-sigs-00)),
**hybrid-only, never pure ML-DSA**; defines the two adoption gates that
must *both* fire before a line of implementation is written; and commits
to completing the migration before the NIST IR 8547 deprecation window
(2030–2035). It resolves [#40](https://github.com/gonzafg2/quantumssh/issues/40)
by removing the ambiguity of *whether, how, and when* — not by adding
ML-DSA today.

## Motivation

**The gap ([#40](https://github.com/gonzafg2/quantumssh/issues/40)).**
The threat model commits to "track NIST and IETF guidance and migrate
before deprecation deadlines" (§8.10) and cites FIPS 204 (ML-DSA)
bibliographically (§9), but never *decides* anything about host-key
signatures. A project whose positioning is "SSH for the next 30 years"
has no written answer to "when do the host keys stop being classical?"
That absence — not any near-term weakness — is what this RFC closes.

**Why signatures are not as urgent as KEX — and why that is the whole
point.** [RFC-0005](0005-hybrid-pq-key-exchange.md) made the *key
exchange* hybrid post-quantum and mandatory because confidentiality is
exposed to **harvest-now-decrypt-later**: traffic recorded today is
broken the day a CRQC exists. A **signature has no such exposure** — a
forged host-key signature is only useful *live*, as an active
man-in-the-middle at connection time. The migration is therefore gated
on *when a CRQC can forge Ed25519 in real time*, not on when one can be
built at all. This asymmetry is why Ed25519 host keys remain the correct
shippable posture now, and why the KEX could not wait but the signature
can — briefly, and on a defined trigger.

**Why decide now, in Phase 2.** Phase 2 introduces the configuration
file and the first public release (`0.1.0`). That is when the host-key
algorithm becomes part of the project's **public interface** — wire
format, `known_hosts` shape, and config surface. Introducing ML-DSA
*after* `0.1.0` without a pre-existing design is a breaking change to all
three. The decision must exist before the interface freezes, even though
the code will not.

## Guide-level explanation

Today, a QuantumSSH host key is a single `ssh-ed25519` key, and the
server offers exactly that one host-key algorithm (ADR-0021). Nothing an
operator does changes with this RFC — Ed25519 remains the shipped
posture until the gates below fire.

When they do, the host key becomes a **composite**:
`ssh-mldsa44-ed25519@openssh.com`. A composite key is *one* SSH key type
that carries **two** underlying public keys — an ML-DSA-44 key (FIPS 204,
lattice-based, post-quantum) and an Ed25519 key (classical) — and every
host authentication produces **two** signatures that a client must
*both* verify. It is the exact analogue, for signatures, of what
`mlkem768x25519-sha256` is for key exchange: neither half alone is
trusted, and a break of either one alone does not break host
authentication.

Why not just switch to pure ML-DSA? Because ML-DSA is young in
*implementation*, not just in standardisation.
[Bernstein's June 2026 analysis](https://postquantum.com/security-pqc/bernstein-exploiting-mldsa-bugs/)
of ML-DSA implementation-bug classes (sub-second key recovery from
faulty implementations; an estimate that ~25 % of ML-DSA libraries will
ship a severe vulnerability) makes betting host identity on ML-DSA alone
unacceptable. The classical Ed25519 half is the backstop that a
lattice-implementation catastrophe cannot defeat — and, symmetrically,
ML-DSA is the backstop against a CRQC breaking Ed25519. **Zero legacy
(MANIFIESTO #3) forbids classical-*only*; it does not forbid
classical-*plus*-PQ, which is exactly the hybrid posture the project
already takes for KEX.**

**Operator-visible impact when it lands** (informative — resolved in the
implementation RFC):

- Handshakes carry ~2.4 KB more per connection (an ML-DSA-44 signature is
  2420 bytes vs Ed25519's 64), paid once at connect time.
- `known_hosts` entries and any `SSHFP` DNS records become larger and
  carry a new key-type identifier.
- A client that does not understand `ssh-mldsa44-ed25519@openssh.com`
  cannot connect — which is precisely why "a stock OpenSSH release ships
  it" is a hard gate below.

## Reference-level explanation

**Target algorithm.** `ssh-mldsa44-ed25519@openssh.com`, per
[draft-miller-sshm-mldsa44-ed25519-composite-sigs](https://datatracker.ietf.org/doc/html/draft-miller-sshm-mldsa44-ed25519-composite-sigs-00)
(Damien Miller / OpenSSH, Standards Track). It supersedes the four older
competing composite drafts (rpe, sfluhrer, sun, josefsson), none
WG-adopted. The construction is LAMPS-aligned composite signing with
domain separation between the two component signatures.

**Sizes (FIPS 204 ML-DSA-44 + Ed25519), for interface planning.** Public
key: 1312 + 32 bytes. Signature: 2420 + 64 bytes. These drive the
handshake-size, `known_hosts`, and `SSHFP` implications above.

**The verification invariant (the security-critical rule).** A composite
verification MUST require **both** component signatures to be valid — a
logical AND. A permissive "either-or" verification would re-introduce the
exact single-algorithm failure the composite exists to prevent (a
forged-under-ML-DSA-bug signature would pass), collapsing the hedge.
Signing likewise produces both; a host that can produce only one
component is misconfigured, not degraded-mode.

**Parameter level.** ML-DSA-44 is NIST security category 2. The draft
names ML-DSA-44 as its baseline; an `mldsa65` (category 3) variant also
exists and would align more closely with `ml-kem-768`'s category-3 KEM.
Which parameter set to track is left to the WG's stabilisation (see
Unresolved questions) — this RFC fixes the *shape* (composite,
hybrid-only, `@openssh.com` draft-miller lineage), not the final digit.

**The two adoption gates — both REQUIRED before any implementation.**

1. **Identifier stability: SSHM WG adoption of the draft.** The parameter
   set already flipped 65→44 in April 2026; a `-00` individual draft is a
   moving target. Implementing against it now would bake in an identifier
   the ecosystem may still change, guaranteeing churn and interop breaks.
2. **A stock OpenSSH release shipping it.** The
   [ADR-0020](../adr/0020-phase-1-ci-openssh-interop-gate.md) interop gate
   *defines* QuantumSSH's client population. A host-key algorithm with no
   deployed client population buys zero real-world host authentication
   while breaking every existing client — a strictly negative trade until
   a client exists.

Until **both** gates fire, classical Ed25519 with the documented limit
(threat model §6.1/§7) remains the correct, shipped posture. When they
fire, a separate **implementation RFC** specifies the wire encoding,
`known_hosts`/`SSHFP` formats, the primitive crate (paralleling
[ADR-0019](../adr/0019-phase-1-ml-kem-crate-rustcrypto.md) for ML-KEM),
and the transition mechanics. That RFC will also require a **superseding
ADR** for the host-key entry that
[ADR-0021](../adr/0021-phase-1-negotiation-profile.md) currently fixes to
`ssh-ed25519` only — the negotiation profile is Accepted and immutable
except by a superseding decision.

**Deprecation backstop.** NIST IR 8547 deprecates quantum-vulnerable
signatures (including all elliptic-curve signatures) across 2030–2035
(disallow at the end of the window). This RFC commits to completing the
migration **before** that window closes regardless of gate timing: if the
gates have not fired by then, that itself becomes an escalation, not a
reason to remain classical past a NIST disallow date.

## Drawbacks

- **Handshake bloat.** ~2.4 KB extra per connection. Paid once per
  connection, not per packet; negligible against a full hybrid KEX. But
  it is real, and it grows `known_hosts` and `SSHFP` records
  permanently.
- **Two signature stacks to maintain.** A composite means carrying an
  ML-DSA implementation *and* Ed25519 forever, with the AND-verification
  discipline as a sharp edge (an accidental OR silently guts the
  security). This is the cost of the hedge — the same cost the hybrid KEX
  already pays.
- **Betting on a pre-adoption draft.** The target is an individual
  Standards-Track draft, not yet WG-adopted; its identifier and parameter
  set can still move. This RFC absorbs that risk by *not implementing* —
  the gates exist precisely so the risk never reaches code.
- **A future new dependency.** Implementation will add an `ml-dsa`
  primitive crate, expanding the audited-primitive trust base (MANIFIESTO
  #4). Deferred to the implementation RFC, which must justify the crate as
  ADR-0019 did for `ml-kem`.

## Rationale and alternatives

**Why composite hybrid, gated, over the alternatives:**

- **Pure ML-DSA (no Ed25519 half).** Rejected: Bernstein's
  implementation-bug analysis makes ML-DSA-alone an unacceptable single
  point of failure for host identity. The classical half is cheap
  insurance against a lattice-implementation catastrophe.
- **Implement the `-00` draft now.** Rejected: the identifier is a moving
  target (65→44 in April 2026) and no client population exists (gate 2).
  Because signatures have no harvest-now exposure (see Motivation), there
  is no urgency that outweighs shipping against an unstable identifier.
- **Never migrate — Ed25519 forever.** Rejected: NIST IR 8547 disallows
  elliptic-curve signatures by 2035, and a live-MITM forgery becomes
  possible once a CRQC can break Ed25519. "SSH for the next 30 years"
  cannot rest on a signature NIST will have disallowed.
- **Track a different composite draft** (rpe / sfluhrer / sun /
  josefsson). Rejected: none is WG-adopted, and draft-miller (OpenSSH
  authorship, aligned with the interop-gate client) supersedes them.
- **A registered pure-PQ *plus separate* classical negotiation** (two
  host-key types offered side by side) instead of a single composite.
  Rejected: it re-opens the downgrade surface the composite closes by
  construction, and contradicts the single-posture discipline the KEX
  profile (ADR-0021) already established.

**Impact of not doing this:** [#40](https://github.com/gonzafg2/quantumssh/issues/40)
stays open, the interface freezes at `0.1.0` with no migration design,
and adding ML-DSA later becomes an unplanned breaking change to the wire
format, `known_hosts`, and config surface simultaneously.

## Prior art

- [draft-miller-sshm-mldsa44-ed25519-composite-sigs](https://datatracker.ietf.org/doc/html/draft-miller-sshm-mldsa44-ed25519-composite-sigs-00)
  (OpenSSH, 2026-06-02) — the target construction.
- [OpenSSH PQ posture](https://www.openssh.com/pq.html) — the reference
  for how the ecosystem is sequencing PQ (KEX first, signatures gated on
  standardisation).
- NIST **FIPS 204** (ML-DSA) — the signature standard; **NIST IR 8547** —
  the deprecation/disallow timeline this RFC's backstop tracks.
- IETF **LAMPS** composite signatures — the domain-separation lineage the
  draft aligns to.
- [RFC-0005](0005-hybrid-pq-key-exchange.md) — the project's precedent
  for a hybrid PQ + classical posture as the *only* posture; this RFC is
  its signature-side counterpart.
- [Bernstein, "Exploiting ML-DSA bugs" (June 2026)](https://postquantum.com/security-pqc/bernstein-exploiting-mldsa-bugs/) —
  the evidence for hybrid-only.
- Recorded research: [issue #42](https://github.com/gonzafg2/quantumssh/issues/42)
  (June 2026 PQ headroom review), which this RFC formalises.

## Unresolved questions

- **ML-DSA-44 vs ML-DSA-65.** The draft baselines 44 (category 2); 65
  (category 3) aligns better with `ml-kem-768`. Resolve when the WG
  stabilises the parameter set — one of gate 1's outputs.
- **Transition mechanics.** Does the server offer the composite *and*
  `ssh-ed25519` during a migration window, or is it a flag-day cut-over?
  Zero-legacy argues against long coexistence; the implementation RFC
  decides, informed by the deployed-client reality at that time.
- **Primitive crate.** Whether a `RustCrypto/ml-dsa` (or equivalent)
  crate is audited and mature enough by gate time, paralleling the
  ADR-0019 decision for `ml-kem`. Deferred to implementation.
- **`known_hosts` / `SSHFP` encoding.** Exact on-disk and DNS formats for
  the composite key — deferred to implementation.

## Future possibilities

Not proposed here, only noted:

- **ML-DSA for user-authentication keys**, not only host keys — a
  separate decision with its own harvest/urgency profile.
- **Certificate authentication** ([#41](https://github.com/gonzafg2/quantumssh/issues/41))
  built on composite signatures once they exist.
- A general **cryptographic-primitive migration procedure**
  ([#42](https://github.com/gonzafg2/quantumssh/issues/42)) for which this
  RFC is the first worked instance.
