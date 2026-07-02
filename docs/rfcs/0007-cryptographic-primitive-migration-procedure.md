# RFC 0007: Cryptographic-primitive migration procedure

- **Status:** Accepted (2026-07-01)
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-07-01
- **Roadmap issue:** [`#42`](https://github.com/gonzafg2/quantumssh/issues/42)
- **Implementation PR:** N/A — this RFC defines a *procedure*; it changes no code.

## Summary

QuantumSSH has taken a primitive-migration decision twice — the key exchange
([RFC-0005](0005-hybrid-pq-key-exchange.md) made the hybrid KEX the only posture,
already implemented) and the host-key signature
([RFC-0006](0006-post-quantum-host-key-signatures.md) fixed the composite
ML-DSA+Ed25519 target, gated and not yet implemented). Both RFCs ratified a
posture that was otherwise scattered across ADRs and prose. This RFC extracts the
**standing procedure** those two instances proved, so a third migration does not re-derive the reasoning from
prose. It codifies two things: (1) a **retroactive-exposure decision tree**
that decides *whether and when* a primitive migrates; and (2) the **supersession
mechanics** at the protocol and dependency layers. It also describes, without
formalising, how the procedure treats **"legacy" as a moving frontier** (anything
past its NIST/IETF disallow date) — the formal refinement of MANIFIESTO
commitment #3 to that effect is **out of scope here and deferred to a dedicated
RFC**, since amending a founding commitment deserves its own decision rather than
riding a procedure RFC. It deliberately does **not** design config-layer
migration (no config surface exists until Phase 2) and does not set a uniform
migration gate (RFC-0005 deliberately had none; a uniform rule would contradict
an Accepted, immutable RFC).

## Motivation

**The gap ([#42](https://github.com/gonzafg2/quantumssh/issues/42)).** The
threat model commits (§8.10) to tracking NIST and IETF guidance and migrating
before the applicable disallow dates — a commitment with no mechanism. How a
primitive
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
"legacy" when NIST/IETF **disallows** it, not when it is merely *deprecated* and
not when the project feels like it. The distinction is load-bearing:
**deprecation** (~2030 for elliptic curves, per NIST IR 8547) is the trigger that
*begins* a gated migration; **disallowance** (~2035) is the line past which a
primitive is legacy. A deprecated-but-not-disallowed primitive legitimately stays
compiled in under the decision tree above (and RFC-0006 keeps `ssh-ed25519` for
exactly this window). MANIFIESTO #3's blocklist is the *floor* (those are already
disallowed); the frontier moves forward on the standards bodies' schedule, and
§8.10's migrate-before-deadlines commitment tracks it.

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
     shipping it (a real client population). Two overrides collapse the wait:
     a **NIST IR 8547 disallow-date backstop** (migrate before that date
     regardless), and — taking priority over everything — an **emergency
     path**: if the primitive is *practically broken now* (a real
     cryptanalytic or implementation break, not a calendar date), the gates
     are void and migration is immediate, exactly as for the retroactive
     class. A gate is a schedule for an *orderly* migration, never a licence
     to keep using a broken primitive. *Precedent: RFC-0006 (host-key
     signatures).*

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

### 3. How the procedure treats "legacy" (descriptive; formal amendment deferred)

The decision tree above needs a working notion of when a primitive has become
*legacy* (must be gone) versus merely *deprecated* (migration has been
triggered). The procedure uses this frontier:

- A primitive is **legacy** once it is past its NIST/IETF **disallow** date, or
  it is on the project's standing blocklist. **Deprecation** (~2030 for elliptic
  curves per NIST IR 8547) is the *trigger* that begins a gated migration, not
  the legacy line itself — so a deprecated-but-not-disallowed primitive (e.g.
  `ssh-ed25519` in 2030–2035 under RFC-0006) is not yet legacy and legitimately
  stays compiled in.
- The classical half of an accepted **hybrid** (X25519 in the KEX, Ed25519 in
  the composite signature) is **not** legacy while the hybrid is the mechanism —
  zero-legacy forbids classical-*only*, not classical-*plus*-PQ.

The **standing blocklist** — the items that must never be compiled in — is the
one CLAUDE.md hard rule #3 already enumerates for reviewers (SSH-1, RSA, DSA,
**ECDSA-NIST**, CBC modes, `diffie-hellman-group1/14-sha1`, `ssh-rsa`, password
auth, compression); it is broader than the MANIFIESTO #3 prose, which is
illustrative. [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html) (the IETF's
maintained SSH-KEX MUST-NOT / SHOULD-NOT lists, already cited in threat-model
§6.1) is the external precedent that "legacy" is a standards-body-maintained
moving target, not a project opinion.

**This section is descriptive, not an amendment.** Formalising the moving-frontier
notion of "legacy" *into MANIFIESTO commitment #3* refines a founding commitment,
which is the highest RFC lane and deserves its own decision — it is **out of scope
here and deferred to a dedicated RFC** (see Future possibilities). Nothing in this
RFC edits `MANIFIESTO.es.md` or relocates authority: CLAUDE.md and the MANIFIESTO
remain what they are, and the RFCs remain authoritative over both.

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
- **The moving-frontier "legacy" notion is described here but not yet
  normative in MANIFIESTO.** §3 explains how the procedure treats legacy, but
  the manifesto prose still reads as a frozen list until a dedicated RFC amends
  commitment #3. Accepted deliberately: amending a founding commitment is the
  highest RFC lane and deserves its own decision, not a rider on a procedure RFC
  (this separation is itself the "one decision per RFC" discipline).
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
and supersession mechanics from scratch. (The zero-legacy paradox in the
MANIFIESTO prose stays open regardless — its formal resolution is the deferred
amendment RFC, not this one.)

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
- [ADR-0015](../adr/0015-permit-annotated-errata-in-adrs.md) (the errata /
  immutability rule that the supersede-don't-edit discipline rests on),
  [ADR-0019](../adr/0019-phase-1-ml-kem-crate-rustcrypto.md)
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
- **The formal amendment of MANIFIESTO commitment #3** (making the
  moving-frontier "legacy" notion normative) is deferred to a dedicated RFC; its
  exact wording and lane are that RFC's to settle, not this one's.

## Future possibilities

- A **dedicated RFC amending MANIFIESTO commitment #3** to make the
  moving-frontier definition of "legacy" (described in §3) normative — the
  highest-lane decision this procedure deliberately does not fold in.
- The **Phase-2 configuration RFC** extends this procedure with the config layer
  (operator-visible algorithm selection, if any, and its migration).
- A **third migration instance** (ML-KEM-768→1024, an HQC cross-family hedge, or
  the RFC-0006 signature gates firing) is the rule-of-three that would justify
  promoting this scoped procedure to Option A's fuller generalization.
