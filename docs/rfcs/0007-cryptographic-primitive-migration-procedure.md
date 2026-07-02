# RFC 0007: Cryptographic-primitive migration procedure

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-07-01
- **Roadmap issue:** [`#42`](https://github.com/gonzafg2/quantumssh/issues/42)
- **Implementation PR:** N/A — this RFC defines a *procedure* and amends MANIFIESTO #3; it changes no code.
- **Amends:** MANIFIESTO commitment #3 ("Cero legacy") — see §"Reference-level explanation".

## Summary

QuantumSSH has migrated a cryptographic primitive twice — the key exchange
([RFC-0005](0005-hybrid-pq-key-exchange.md), hybrid KEX as the only posture)
and the host-key signature ([RFC-0006](0006-post-quantum-host-key-signatures.md),
the composite ML-DSA+Ed25519 target). Both were "ratify a scattered posture"
RFCs written after the fact. This RFC extracts the **standing procedure** those
two instances proved, so a third migration does not re-derive the reasoning from
prose. It codifies three things: (1) a **retroactive-exposure decision tree**
that decides *whether and when* a primitive migrates; (2) the **supersession
mechanics** at the protocol and dependency layers; and (3) a **dynamic
definition of "legacy"** — anything past its NIST/IETF deprecation date, not a
frozen list of named algorithms — which **refines MANIFIESTO commitment #3** and
so travels the highest RFC lane. It deliberately does **not** design
config-layer migration (no config surface exists until Phase 2) and does not set
a uniform migration gate (RFC-0005 deliberately had none; a uniform rule would
contradict an Accepted, immutable RFC).

## Motivation

**The gap ([#42](https://github.com/gonzafg2/quantumssh/issues/42)).** The
threat model commits to "track NIST and IETF guidance and migrate before
deprecation deadlines" (§8.10) — a commitment with no mechanism. How a primitive
is actually replaced, across the protocol, dependency, and (eventually) config
layers, is undefined.

**The zero-legacy paradox.** MANIFIESTO #3 forbids legacy, but *today's modern
algorithm is tomorrow's legacy*: `mlkem768x25519-sha256` and `ssh-ed25519` are
current now and will be deprecated eventually. A commitment to "zero legacy"
stated as a **frozen blocklist** (no SSH-1, no RSA, no DSA…) cannot express this
— it goes stale the moment NIST disallows something not on the list. The
paradox is only resolved by defining "legacy" as a **moving frontier** the
standards bodies set.

**The cost already paid twice.** RFC-0005 and RFC-0006 both exist to stop
reconstructing a scattered posture from ADR-0021's drawbacks, threat-model
§6.1/§8.10, and commit messages. A third migration (ML-KEM-768→1024 when CNSA
2.0 bites, or an HQC hybrid, or the signature gates firing) should inherit a
written procedure, not repeat the archaeology. The June-2026 headroom review
recorded in #42 already enumerates the concrete triggers; this RFC gives them a
procedure to flow into.

## Guide-level explanation

When NIST or IETF deprecates a primitive QuantumSSH uses — or standardises a
replacement — a maintainer follows this procedure instead of improvising.

**Step 1 — classify the primitive's exposure.** The urgency of a migration is
set by *when* a break hurts you:

- **Retroactive (harvest-now-decrypt-later).** Confidentiality: recorded
  ciphertext is broken retroactively the day the primitive falls. The key
  exchange is here. → **Migrate as soon as an interoperable standard exists, with
  no adoption gate.** This is exactly what RFC-0005 did: the hybrid KEX was made
  mandatory immediately, no waiting.
- **Live-only.** A signature (host key, and by RFC-0006's reasoning a
  certificate CA key) is only forgeable *at connection time* — there is no
  recording to break later. → **Migration may wait behind adoption gates** (WG
  adoption for identifier stability + a stock OpenSSH release for a client
  population), **with a NIST-IR-8547-disallow backstop** so the gates can never
  become permanent deferral. This is exactly what RFC-0006 did.

**Step 2 — execute the supersession** at each layer that the primitive touches
(protocol / dependency; config is deferred, see below), following the mechanics
in the reference section — always by *superseding* an Accepted ADR, never by
editing it.

**Step 3 — the definition of "legacy" is not yours to set.** A primitive is
"legacy" when NIST/IETF says so (a deprecation/disallow date), not when the
project feels like it. MANIFIESTO #3's blocklist is the *floor* (those are
already disallowed); the frontier moves forward on the standards bodies'
schedule, and §8.10's migrate-before-deadlines commitment tracks it.

Nothing about this procedure licenses *crypto-agility* in the pejorative sense:
adding or swapping an algorithm is still an RFC-gated, one-primitive-at-a-time
decision (MANIFIESTO #4). The procedure makes migrations *disciplined and
pre-reasoned*, not *easy or frequent*.

## Reference-level explanation

### 1. The retroactive-exposure decision tree (normative)

For a primitive `P` facing deprecation, or a candidate replacement `P'`:

1. **Does a compromise of `P` expose past sessions?** (Can an adversary who
   records traffic today break it retroactively once `P` falls?)
   - **Yes → retroactive class.** Migrate to the hybrid/replacement posture as
     soon as an *interoperable standard* exists. **No adoption gate.** Failure of
     either hybrid half must abort, never fall back (MANIFIESTO #2). *Precedent:
     RFC-0005 (KEX).* 
   - **No (compromise only enables a live attack at connection time) →
     live-only class.** Migration MAY wait behind **both**: (a) WG adoption of
     the replacement's identifier (stability), and (b) a stock release of the
     [ADR-0020](../adr/0020-phase-1-ci-openssh-interop-gate.md) reference client
     shipping it (a real client population). A **NIST IR 8547 disallow-date
     backstop** overrides the gates: migrate before that date regardless.
     *Precedent: RFC-0006 (host-key signatures).*

This asymmetry — no gate for retroactive, gated for live-only — **is** the
generalizable core. A single uniform gate is explicitly rejected because it
would contradict RFC-0005, which is Accepted and immutable and deliberately had
none.

### 2. Supersession mechanics (normative)

The negotiation profile is **not** carried in an in-band version field; it *is*
whatever [ADR-0021](../adr/0021-phase-1-negotiation-profile.md) currently says.
"Versioning the profile" therefore means **superseding ADR-0021** (per
[ADR-0015](../adr/0015-permit-annotated-errata-in-adrs.md): change a decision by
writing a superseding ADR, never by editing the Accepted one). A migration:

- **Protocol layer.** A superseding ADR replaces the relevant name-list entry in
  the ADR-0021 profile. The [ADR-0020](../adr/0020-phase-1-ci-openssh-interop-gate.md)
  interop fixtures MUST move **atomically** with that superseding ADR — the gate
  defines the client population the profile targets, so a profile change and its
  interop expectation land together or the gate lies.
- **Dependency layer.** A new primitive means a new audited primitive crate,
  introduced by a **crate-selection ADR paralleling
  [ADR-0019](../adr/0019-phase-1-ml-kem-crate-rustcrypto.md)** (ml-kem) and
  passing `cargo deny`. RFC-0006 already promises an `ml-dsa` ADR of this shape.
- **Config layer.** **Deferred.** No configuration surface exists in Phase 1
  (CLAUDE.md: no config file); designing config-layer migration now is
  speculative (MANIFIESTO #4 / YAGNI). The Phase-2 configuration RFC owns it, and
  this procedure will be extended then.

### 3. The definition of "legacy" — amendment to MANIFIESTO #3 (normative)

MANIFIESTO commitment #3 ("Cero legacy") today reads as a fixed blocklist (no
SSH-1, no RSA, no DSA, no CBC, no `diffie-hellman-group1-sha1`, no password
auth). This RFC **refines** it: the blocklist is the permanent **floor**, and
"legacy" additionally means **any primitive past its NIST or IETF
deprecation/disallow date**. Zero-legacy = the deprecated is never compiled in
(the blocklist floor), and §8.10's migrate-before-deadlines commitment is the
moving frontier above it.

The external precedent that "legacy" is a standards-body-maintained moving
target — not a project opinion — is **[RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html)**
(the IETF's maintained SSH key-exchange guidance with its MUST-NOT / SHOULD-NOT
lists), already cited in threat-model §6.1. The MANIFIESTO edit adds one
sentence to commitment #3 to this effect; because it refines a MANIFIESTO
commitment, this RFC travels the highest lane per the RFC process (and per the
precedent RFC-0005 set: a challenge to a MANIFIESTO commitment belongs in an RFC
that amends it).

## Drawbacks

- **Generalizing over two instances (rule-of-three).** Only KEX and signatures
  have been migrated; a procedure abstracted from two cases risks over-fitting.
  Mitigated by keeping the RFC *scoped* — it codifies only the spine both
  instances actually share (the exposure decision tree, the supersession
  mechanics) and explicitly defers what neither has exercised (config layer,
  cadence).
- **Reads as licensing crypto-agility.** A written migration procedure could be
  misread as endorsing frequent algorithm churn, which contradicts MANIFIESTO #4
  (small surface). Guarded explicitly: every migration remains RFC-gated and
  one-primitive-at-a-time; the procedure disciplines migrations, it does not
  cheapen them.
- **Amending MANIFIESTO is heavy.** Touching a founding commitment is not
  routine. Justified: the paradox is real (a frozen blocklist cannot stay
  zero-legacy over 30 years), and the amendment is a one-sentence refinement that
  *strengthens* the commitment, not a retreat from it.
- **The procedure is a skeleton, not a full generalization.** No config-layer
  design and no named watch-trigger cadence/owner. Accepted: those depend on
  artifacts (the config file) and governance (a cadence owner) that do not exist
  yet; designing them now would be vaporware.

## Rationale and alternatives

- **Option A — a full standing-procedure RFC now** (all three layers + trigger
  governance + cadence). Rejected: it designs config-layer migration against a
  config surface that does not exist (YAGNI), over-generalizes from two
  instances, and risks stating a uniform gate that contradicts the immutable
  RFC-0005.
- **Option B — a scoped procedure RFC (this one).** Chosen: codifies exactly the
  spine two instances proved, owns the reasoning in one discoverable place, and
  defers the unproven parts. Cleanest fit with YAGNI and one-decision-per-RFC.
- **Option C — do not RFC; keep #42 as a living research log + per-decision
  RFCs.** Rejected: it leaves "how is the profile versioned" and "what is legacy"
  answered only implicitly, scattered across ADR-0021 / RFC-0005 / threat-model —
  the reconstruct-from-prose cost the project has already paid to fix twice.

**Impact of not doing this:** the next migration re-derives the exposure logic
and supersession mechanics from scratch, and the zero-legacy paradox stays
unresolved — MANIFIESTO #3 keeps reading as a list that will go stale.

## Prior art

- [RFC-0005](0005-hybrid-pq-key-exchange.md) (KEX) and
  [RFC-0006](0006-post-quantum-host-key-signatures.md) (signatures) — the two
  worked instances this procedure generalizes; RFC-0006 §Future-possibilities
  explicitly names #42 as "the general procedure for which this RFC is the first
  worked instance."
- [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html) — the IETF's maintained
  SSH KEX guidance; the precedent that "legacy" is a standards-maintained moving
  target.
- **NIST IR 8547** (deprecation/disallow timeline for quantum-vulnerable
  algorithms) — the backstop dates; **CNSA 2.0** — the ML-KEM-1024/NSS pressure
  that is a live future trigger (threat-model §8.7).
- The June-2026 PQ headroom review recorded in
  [issue #42](https://github.com/gonzafg2/quantumssh/issues/42) — the enumerated
  concrete triggers (HQC, sntrup761, ML-KEM-1024, BSI TR-02102-4) this procedure
  routes.
- [ADR-0015](../adr/0015-permit-annotated-errata-in-adrs.md) (supersession
  discipline), [ADR-0019](../adr/0019-phase-1-ml-kem-crate-rustcrypto.md)
  (dependency-layer template), [ADR-0020](../adr/0020-phase-1-ci-openssh-interop-gate.md)
  (client population), [ADR-0021](../adr/0021-phase-1-negotiation-profile.md)
  (the profile being versioned).

## Unresolved questions

- **Config-layer migration.** Deferred to the Phase-2 configuration RFC — no
  surface exists to design against now.
- **Watch-trigger cadence and owner.** A standing procedure implies someone
  reviews NIST/IETF movement on a cadence; today the headroom review was a
  one-off. Who owns it and how often is left to `GOVERNANCE.md` (the single-
  maintainer residual in threat-model §7 is the relevant constraint).
- **Whether the amendment wording belongs in MANIFIESTO's commitment #3 prose or
  a linked clarification.** This RFC proposes the one-sentence refinement inline;
  the lead may prefer a footnote.

## Future possibilities

- The **Phase-2 configuration RFC** extends this procedure with the config layer
  (operator-visible algorithm selection, if any, and its migration).
- A **third migration instance** (ML-KEM-768→1024, an HQC cross-family hedge, or
  the RFC-0006 signature gates firing) is the rule-of-three that would justify
  promoting this scoped procedure to Option A's fuller generalization.
