# RFC 0001: Threat model — add 'Project maintainer compromise' actor under §3.2

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-05-11
- **Tracking issue:** [#20](https://github.com/gonzafg2/quantumssh/issues/20)
- **Implementation PR:** TBD

## Summary

This RFC proposes adding a new in-scope threat actor — **§3.2.6 Project
maintainer compromise** — to `docs/threat-model.md`, refining the
supply-chain narrative in §5.5.2 so that *upstream-dependency maintainer
compromise* and *own-project maintainer compromise* are distinguishable,
and re-targeting the §6.4 mitigations (ADR-0006, ADR-0008, `deny.toml`,
the Phase 3 reproducible-builds and SBOM commitments) so each control
attaches to a named adversary with an explicit statement of what it
covers and what it does not.

The new actor sits at NIST SP 800-30 Rev.1 capability **Moderate – High**,
intent **Moderate – Very High**, targeting **High – Very High**.
Consistent with §1.1's framing — the threat model is not a risk
assessment and assigns no likelihoods — this RFC does not rate the
adversary's likelihood. The actor entry exists so that the controls
already in place or committed-to attach to a named threat rather
than to a vector alone.

The RFC also draws an explicit boundary: **repo-side** controls against
maintainer compromise are in scope (signed commits, branch protection,
reproducible builds, dependency discipline); **endpoint hardening of
the maintainer's workstation** is out of scope, parallel to how §5.5.4
declares operator-account compromise out of scope.

## Motivation

The multi-agent review of [PR #19](https://github.com/gonzafg2/quantumssh/pull/19),
which substantiated the threat model against NIST SP 800-30 Rev.1 and
the MITRE ATT&CK Enterprise matrix, surfaced an asymmetry that the
substantiation work did not resolve:

> §3.2 enumerates external actors only. §5.5.2 covers upstream
> supply-chain compromise, but the project's own maintainer compromise
> (commit-signing key theft, account takeover of a maintainer with merge
> rights) is not in the actor table. §3.2.5 alludes to "long-lived
> implants in the maintainer's development environment" but treats it as
> a nation-state technique rather than a distinct actor class.

The asymmetry has real consequences for how the document reads:

1. **Mitigations hang off the supply-chain narrative, not off a named
   adversary.** The §6.4 entries — ADR-0006 (signed commits),
   ADR-0008 (branch protection), `deny.toml`, reproducible builds and
   SBOM — are described as defending §5.5.2 "partially". A reader is
   left to infer who the actor is and to do the bridging themselves.
2. **The most consequential adversary for a single-maintainer project
   in the open-source ecosystem is buried.** The 2024 `xz-utils`
   incident (CVE-2024-3094) was not a registry attack; it was the
   long-game social engineering of a maintainer with merge rights into
   an OpenSSH-adjacent project. Treating that as a "nation-state
   technique" is technically correct but operationally misleading,
   because the *procedure* — exploit a tired solo maintainer's social
   surface to gain commit access — can be executed by adversaries
   below nation-state capability.
3. **The threat model's own maintenance clause forbids appending
   actors silently.** Lines 9–15 of `docs/threat-model.md` require an
   RFC for structural changes to the actor list. This RFC fulfils that
   requirement.

This is not a hypothetical concern for QuantumSSH. The project's
governance during Phases 0–2 is BDFL (`GOVERNANCE.md`, "Current model:
temporary BDFL"), branch protection on `main` is configured with **zero
required reviews** (ADR-0008), and the SSH signing key for commits is
the same key used for GitHub authentication (ADR-0006, "Negative":
*"Reusing the auth key for signing means a single compromise affects
both surfaces"*). The conditions that make project-maintainer compromise
a category-distinct threat are present in the project's documented
configuration, by design. The threat model should describe that
configuration honestly.

## Guide-level explanation

The change is best understood by reading the new §3.2.6 in the form it
would appear in the threat model, alongside the refinements to §5.5.2
and the mitigation re-targeting in §6.4.

### Proposed §3.2.6 (new actor)

> #### 3.2.6 Project maintainer compromise (Moderate – High)
>
> **Capability.** Spans two distinguishable tiers, each realisable
> through procedurally distinct paths.
>
> At the **Moderate** end (Table D-3, Moderate): *compromise of an
> existing maintainer* via credential phishing against developer-
> platform accounts (GitHub, package registries), theft of the
> maintainer's SSH signing key through opportunistic endpoint
> compromise, or registry-side account takeover via session-token
> reuse (procedure exemplars: `ua-parser-js` 2021, `eslint-scope`
> 2018).
>
> At the **High** end (Table D-3, High): persistent implants in the
> maintainer's development environment capable of injecting code at
> commit, build, or release time; or *infiltration to acquire merge
> rights legitimately*, sub-divided into (a) **co-maintainer
> addition** under social-engineering pressure on the original
> maintainer (procedure exemplar: `xz-utils` 2024 / CVE-2024-3094,
> against the OpenSSH authentication path) and (b) **handoff to a
> malicious successor** when the original maintainer steps away
> (procedure exemplar: `event-stream` 2018).
>
> **Intent.** Ranges from "obtain critical or sensitive information
> … by establishing a foothold" (Table D-4, Moderate) — when the
> compromised project is a stepping stone to downstream targets — to
> "undermine, severely impede, or destroy a core mission or business
> function" (Table D-4, Very High) — when the goal is to discredit
> the project itself or its users.
>
> **Targeting.** By definition deliberate against this specific
> project (Table D-5, High). Where the project is a supply-chain
> vector to higher-value downstream consumers, targeting matches the
> Very-High row's "supply chains and supporting personnel" language.
>
> **Typical techniques.** Credential phishing (`T1566`) and
> session-cookie theft (`T1539`) against the maintainer's platform
> accounts; theft of signing material from a compromised developer
> endpoint (`T1552.004` for private keys at rest); persistent
> implants on the maintainer's workstation enabling code injection at
> build time (`T1195.002` realised at the maintainer rather than at
> the dependency); long-game cultivation of a new contributor
> identity to acquire co-maintainer rights (`T1195.002`, procedure
> exemplar: `xz-utils` 2024 / CVE-2024-3094); maintainership handoff
> to a malicious successor (`T1195.002`, procedure exemplar:
> `event-stream` 2018); abuse of repository CI to introduce malicious
> code via workflow files (`T1195.002`); attempts to publish a
> malicious tag, release artefact, or container image under the
> project's name.
>
> ATT&CK does not cleanly map the social-engineering-of-maintainer
> path; `T1195.002` (Supply Chain Compromise: Compromise Software
> Supply Chain) is used here as the umbrella technique. This
> parallels the honest acknowledgment in §5.5.3 that not every
> threat in this model has a precise ATT&CK identifier.
>
> **Implication for design.** Repo-side controls must keep the
> authoritative source on `main` defensible even when one maintainer
> is the only human in the loop. Commit signing (ADR-0006) and branch
> protection (ADR-0008) constrain what an attacker can publish under
> the project's name; dependency discipline (`deny.toml`, cargo-deny
> in CI) bounds the surface that a compromised maintainer could
> silently widen. Reproducible builds and a published software
> bill-of-materials (Phase 3, RFC-gated) are the controls that allow
> *downstream consumers* to detect divergence between the source on
> `main` and the binaries they run, which is the only defence-in-depth
> that survives a maintainer who is fully compromised.

### Proposed refinement to §5.5.2

The current §5.5.2 conflates two sub-cases under one heading. The
refinement splits them while preserving the existing text. The new
structure:

> #### 5.5.2 Supply-chain compromise of dependencies and maintainership
>
> Supply-chain attacks against an SSH implementation come in two
> categorically distinct sub-cases, with overlapping mitigations but
> different actor mappings.
>
> **5.5.2.a Upstream dependency compromise.** [existing §5.5.2
> mechanism text, unchanged, with the xz-utils citation preserved]
>
> **5.5.2.b Project maintainer compromise.** A current QuantumSSH
> maintainer is compromised (credentials phished, signing key stolen,
> development environment implanted), or merge rights are acquired
> legitimately by a malicious newcomer (co-maintainer addition or
> full handoff). The attacker publishes malicious code under the
> project's name through paths the repository's controls treat as
> legitimate. Actor: §3.2.6. ATT&CK reference: `T1195.002` as the
> umbrella technique (`T1566`, `T1552.004`, `T1539` for the
> credential-compromise sub-cases); ATT&CK does not cleanly cover the
> infiltration sub-cases, see §3.2.6. Test handle: the §6.4 controls
> (signed commits, branch protection, reproducible builds, SBOM)
> collectively bound but do not eliminate this risk; see §7 for the
> residual.

### Proposed re-targeting of §6.4

Each entry in §6.4 today defends "§5.5.2 partially". The re-targeting
attaches each control to its actor and states explicitly what it does
*not* cover. The full mapping is in the reference-level section below;
the §6.4 text remains compact:

> - **Signed releases and signed commits on `main`** (ADR-0006).
>   Defends §3.2.6 against attackers who do not hold the maintainer's
>   signing key. Does not defend against use of the legitimate signing
>   key by a compromised maintainer.
> - **Branch protection on `main`** (ADR-0008). Defends §3.2.6 against
>   direct push, force-push, and the destruction of merge history.
>   With zero required reviews during single-maintainer phases, it
>   does not add a four-eyes constraint; that defence activates when
>   `GOVERNANCE.md`'s transition criteria are met.
> - **Dependency discipline** (`deny.toml`, cargo-deny in CI). Defends
>   §5.5.2.a against silent introduction of disallowed crates. Does not
>   defend against compromise of an already-allowlisted dependency or
>   against §5.5.2.b.
> - **Reproducible builds and SBOM** (Phase 3, RFC-gated). When
>   landed, defend §3.2.6 by enabling downstream detection of
>   binary/source divergence — the only control that retains value
>   against a fully-compromised maintainer.

### Proposed amendments elsewhere in `docs/threat-model.md`

The new actor ripples to three other places in the document. The
Implementation PR will apply each.

**§3.2 intro paragraph.** The current text (`docs/threat-model.md`,
the paragraph immediately before §3.2.1) says *"everything else
inherits the protections built for [the §3.2.5 HNDL] case"*. §3.2.6
does not inherit those protections — the post-quantum-by-default key
exchange does not defend against a compromised maintainer. The intro
paragraph gains a sentence noting that §3.2.6 sits structurally apart
as the one in-scope adversary operating *behind* the project's trust
boundary, with mitigations documented in §6.4 rather than §6.1.

**§7 (Residual risk).** A new entry captures the single-maintainer
gap explicitly:

> Until `GOVERNANCE.md`'s transition criteria are met (three regular
> contributors over six months plus a `0.1.0` release) and
> `required_approving_review_count` rises from 0 to 1, a maintainer
> whose credentials, signing key, and development endpoint are
> simultaneously compromised retains the ability to publish under
> the project's name through the normal PR flow. The bound on this
> residual is what controls outside the maintainer's trust boundary
> can detect after the fact — reproducible builds, SBOM, signed-tag
> verification by downstream consumers. The bound is not zero.

**§8 (Out of scope).** A new §8.11 entry, modelled on §8.1's format:

> #### 8.11 Hardening of the maintainer's personal endpoint
>
> Operating-system controls, MFA enforcement on personal platform
> accounts, and hardware-backed key storage on the maintainer's
> *personal* workstation are the maintainer's responsibility as an
> operator of their own development environment. QuantumSSH's
> controls cannot reach into that environment; the threat model
> describes what the project *can* enforce. Operators concerned
> about the strength of these endpoint defences must rely on the
> project's transparency posture (public source, signed commits,
> reproducible builds when landed) rather than on this document's
> coverage of the maintainer's endpoint.

## Reference-level explanation

### Position in §3.2

§3.2.6 takes the slot immediately after §3.2.5 (Nation-state with HNDL
capability). The ordering of §3.2 today is approximately by *capability
tier*: Very Low → Low → Moderate → High → Very High. §3.2.6 spans
Moderate–High and could in principle sit between §3.2.3 and §3.2.4.
The RFC proposes the §3.2.6 slot specifically because:

1. The actor is structurally distinct from the §3.2.1–§3.2.5 ladder
   (which moves from outside-in by capability), and trails the
   external-only enumeration as the one in-scope adversary that
   operates *behind* the project's trust boundary rather than across
   it.
2. The §3.2.5 paragraph today implicitly contains the "maintainer
   implant" thread; placing §3.2.6 immediately after makes the
   refinement of that paragraph (removal of the implant language)
   read as a direct continuation rather than a contradiction.

### Capability-tier rationale

The format used by §3.2.1, §3.2.2, and §3.2.3 already admits ranges
("Very Low – Low", "Low – Moderate", "Moderate – High"). The new entry
follows that convention. The two tiers represent qualitatively
different attack paths, both realistic:

- **Moderate**: realisable by a funded criminal group or a competent
  individual actor. Path: credential phishing, registry account
  takeover, theft of signing material at rest on an under-protected
  workstation. Capabilities sufficient to publish a malicious release
  but not to maintain persistence across credential rotation.
- **High**: realisable by a state-affiliated actor or a well-resourced
  intrusion set. Path: persistent implant on the maintainer's
  workstation, long-game social engineering for legitimate merge
  rights, maintainership handoff to a colluding identity. Capabilities
  sufficient to inject code that survives source-level review.

The High tier deliberately overlaps with §3.2.4 (Targeted intruder,
High) on capability and with §3.2.5 (Nation-state, Very High) on
*procedure* in the maintainer-implant case. This is intentional: §3.2.6
is the *vector* axis, not the *capability* axis, and the existing actors
remain valid descriptions of the same actor in their other operational
modes.

### Intent and targeting

Per NIST SP 800-30 Rev.1, Table D-4 ("Adversary Intent") and Table D-5
("Adversary Targeting"):

- **Intent: Moderate – Very High.** A criminal actor monetising
  compromised releases (cryptominers, credential stealers) sits at
  Moderate. An actor using the project as a vector to a downstream
  high-value consumer sits at High. A nation-state actor for whom
  destroying credibility of a post-quantum SSH implementation is itself
  the goal sits at Very High.
- **Targeting: High – Very High.** Compromising *this* project is
  necessarily deliberate; the lowest cell ("may or may not target any
  specific organisations") does not apply. Where the project is the
  pivot for a Very-High-targeting nation-state operation against
  downstream supply chains, Table D-5's "supply chains and supporting
  personnel" language describes the case directly.

### Mapping to mitigations (full)

| Control | ADR / source | What it covers under §3.2.6 | What it does **not** cover |
|---|---|---|---|
| SSH commit signing on `main` | ADR-0006 | Commits authored by an attacker who does not hold the maintainer's SSH signing key (e.g. registry-side merge, malicious co-maintainer pre-handoff). | An attacker who has stolen the SSH signing key — which is the same key as the maintainer's GitHub auth key (ADR-0006 "Negative"), and therefore a single compromise affects both surfaces. |
| Branch protection on `main` | ADR-0008 | Direct push, force-push, branch deletion, unsigned commits, bypassing required CI checks. Enforced on admins, so the maintainer is not exempt. | Four-eyes review — branch protection has `required_approving_review_count = 0` during single-maintainer phases. A comprehensively compromised maintainer merging through the normal PR flow defeats the control. The count rises to one on `GOVERNANCE.md`'s transition. |
| Dependency discipline | `deny.toml`, cargo-deny in CI | Silent introduction of new crates outside the allowlist, banned licences, banned advisories. Defends §5.5.2.a. | Compromise of an already-allowlisted upstream (a different §5.5.2.a path). Does not defend §5.5.2.b at all — `deny.toml` is enforced *by* the maintainer, so a compromised maintainer can edit it. |
| PGP key two-year expiry | ADR-0005 | Bounds blast radius of project-PGP-key compromise on the embargoed-disclosure path. Tangential to §3.2.6's primary paths but relevant for the disclosure trust anchor. | The signing-key path (ADR-0006), which is on a separate keypair. |
| Reproducible builds | Phase 3, RFC-gated (not yet landed) | Will enable third parties to detect divergence between published source on `main` and binaries distributed under the project's name. The only control that retains value against a fully-compromised maintainer, because verification occurs *outside* the maintainer's trust boundary. | An attacker who has compromised both the source and the build environment in coordinated fashion. |
| Software bill of materials | Phase 3, RFC-gated (not yet landed) | Will reduce dwell time post-discovery by enabling consumers to enumerate exactly which versions of which dependencies their build contains. | Active compromise detection — SBOM is a forensic and impact-scoping tool, not a real-time control. |
| `GOVERNANCE.md` transition to multi-maintainer | `GOVERNANCE.md`, "Transition to a maintainer team" | When the criteria are met (3 regular contributors over 6 months and `0.1.0` shipped), `required_approving_review_count` rises to 1, activating the four-eyes constraint. | The transition is not automatic; this RFC notes the dependency without proposing to alter the criteria. |

### Boundary with §5.5.4 (Operator-account compromise, out of scope)

§5.5.4 of the current threat model declares operator-account compromise
**out of scope** on the grounds that the operator is, by the project's
posture, not the adversary. The new §3.2.6 follows a parallel logic
with a different conclusion:

- **In scope**: the controls the project applies *to its own repository
  and release artefacts* — signing, branch protection, dependency
  discipline, reproducibility, SBOM, governance transitions.
- **Out of scope**: hardening of the maintainer's personal endpoint
  (operating-system controls, MFA enforcement on platform accounts,
  hardware-backed signing keys for the maintainer's *personal*
  workstation). These are the maintainer's responsibility as an
  operator of their own development environment, not requirements
  this project's controls can enforce on itself.

The RFC proposes that §3.2.6 reproduce this boundary explicitly, with
language modelled on the §5.5.4 disposition paragraph.

### Honest acknowledgment: the single-maintainer gap

ADR-0008 records, by design, that branch protection on `main` requires
zero approving reviews during single-maintainer phases. The RFC does
not propose to alter ADR-0008. It does propose that §3.2.6 — and the
re-targeted §6.4 entry on branch protection — state explicitly that
*while the project operates with a single maintainer*, the four-eyes
component of branch protection is not active, and the residual risk of
a comprehensively compromised maintainer is bounded only by the
controls that operate outside the maintainer's trust boundary
(reproducible builds, SBOM, downstream verification of signed releases
against a published expected-fingerprint set).

This is not a flaw in the threat model; it is a fact about the project's
current scale. The threat model's job is to describe that fact
accurately rather than to imply protections the configuration does
not deliver.

## Drawbacks

1. **Risk of duplication with §5.5.2.** The proposed refinement
   distinguishes 5.5.2.a (upstream) from 5.5.2.b (own-project), but the
   *new* §3.2.6 also describes the own-project case. Readers may find
   the two descriptions overlap. Mitigation: §5.5.2.b is deliberately
   short and points at §3.2.6 as the authoritative actor description;
   §3.2.6 is deliberately long and points at §5.5.2.b as the
   vector-side mapping. The pattern is the same one §3.2.4 and §5.5.1
   already use.
2. **Risk of implying ADR-0006 and ADR-0008 are inadequate.** The
   honest mitigation table above states what each control does not
   cover. A reader unfamiliar with the project's posture might read the
   acknowledgment as a criticism of the ADRs themselves. Mitigation:
   the §6.4 re-targeting language explicitly attributes the residual to
   the project's single-maintainer scale, not to a defect in the
   controls.
3. **Capability range overlaps with existing actors.** §3.2.6 at the
   High tier overlaps with §3.2.4 (Targeted intruder, High) and at the
   procedure level with §3.2.5 (Nation-state, Very High). A reviewer
   could reasonably argue this makes the actor table less orthogonal.
   Mitigation: the RFC documents the overlap explicitly and frames
   §3.2.6 as a *vector axis* rather than a capability axis; this is the
   same logic that justifies §3.2.3 (Network-positioned, Moderate–High)
   coexisting with §3.2.4 (Targeted intruder, High) despite overlapping
   capability.
4. **Premature documentation of an adversary unlikely to materialise
   today.** A reviewer could argue a project with no users is not a
   plausible maintainer-compromise target, and the entry is therefore
   premature. Mitigation: the Motivation argues that the controls
   being re-targeted (ADR-0006, ADR-0008, and the Phase 3
   deliverables) already exist or are committed-to, and the threat
   model is more useful when it names the adversary those controls
   respond to than when it leaves them floating. §1.1's stance that
   the document does not rate likelihoods is preserved; the entry's
   inclusion is justified by the existence of its mitigations, not by
   a probability claim.

## Rationale and alternatives

### Why a new actor in §3.2 (rather than only refining §5.5.2)

§5.5.2 today is a vector description. Vectors describe what happens
*to* assets; actors describe *who* makes it happen. The threat model's
own structure separates the two (§3 actors → §5 vectors). Refining
§5.5.2 alone would leave §6.4 mitigations attached to a vector with no
named actor at the same level of abstraction as §3.2.1–§3.2.5, which is
the precise asymmetry the PR #19 review surfaced. A new §3.2.6 is the
structural fix that the existing layout invites.

### Why also refine §5.5.2 (rather than only adding §3.2.6)

§5.5.2 today conflates two cases the rest of the document treats
separately: upstream-dependency compromise and own-project maintainer
compromise. Once §3.2.6 exists, §5.5.2's text about "maintainer
compromise" becomes ambiguous as to which maintainer. Splitting into
5.5.2.a/5.5.2.b is the minimum edit that resolves the ambiguity
without rewriting the section.

### Why not a new §5.5.5 'Project maintainer compromise' (alternative)

A dedicated §5.5.5 was considered. Rejected because it would duplicate
the procedural narrative the new §3.2.6 already carries, and because
the supply-chain framing — *what crosses the trust boundary into the
build* — applies equally to upstream-dependency compromise and to
own-project maintainer compromise. Keeping them under one §5.5.2
heading with two clearly-marked sub-cases preserves the categorical
relationship while resolving the ambiguity.

### Why Moderate–High capability (rather than Low, or Very High)

- **Low** was suggested in the PR #19 review on the basis of low
  expected activity against QuantumSSH today. The threat model does
  not rate likelihood (§1.1), so that consideration does not enter
  the capability tier. Capability is rated by what the adversary
  *can* do, independent of how often QuantumSSH expects to encounter
  them; the §3.2.5 entry follows the same logic when it notes the
  HNDL adversary is Very High in capability "but *nothing* about
  QuantumSSH's defence requires the adversary to be a nation-state
  in practice".
- **Very High** was considered for the implant case but rejected
  because the resources required for maintainer-targeted social
  engineering (the `xz-utils` model) are demonstrably below
  nation-state scale — the operation was sustained for two years by
  what appears to have been a small set of identities. Reserving Very
  High for the *cryptanalytic* capability concentrated in §3.2.5 keeps
  the tiers distinguishable.

### Why declare endpoint hardening out of scope

Parallel to §5.5.4 (operator-account compromise). Both rest on the same
principle: the threat model describes what the project's controls *can*
enforce, not what its participants' personal-device hygiene should be.
Including endpoint hardening would either (a) commit the project to
controls it does not in fact apply, or (b) lower the bar for what
"in-scope" means to the point that the term loses force.

## Prior art

- **NIST SP 800-30 Rev.1**, Guide for Conducting Risk Assessments,
  September 2012. Appendix D, Tables D-3 (Capability), D-4 (Intent),
  D-5 (Targeting). Used throughout §3 of the current threat model;
  this RFC continues that convention.
- **MITRE ATT&CK Enterprise**, v19 (April 2026). Techniques cited for
  the new actor: `T1195.002` (Supply Chain Compromise: Compromise
  Software Supply Chain) as the umbrella; `T1566` (Phishing),
  `T1552.004` (Unsecured Credentials: Private Keys), `T1539` (Steal
  Web Session Cookie) for the credential-compromise sub-cases. ATT&CK
  does not provide a clean technique for the infiltration sub-cases
  (legitimate acquisition of merge rights by a malicious newcomer);
  the RFC notes this gap rather than forcing a poor-fit mapping.
- **`xz-utils` operation, 2024** (CVE-2024-3094). Long-game cultivation
  of a new contributor identity ('Jia Tan'), supported by associated
  personas pressuring xz's overwhelmed sole maintainer to add a co-
  maintainer; once merge rights were obtained, introduction of a
  payload disguised inside test fixtures and activated through the
  build's m4 macros, hooking `RSA_public_decrypt` via IFUNC resolution
  on systems where `liblzma` is in `sshd`'s dependency chain through
  `libsystemd`. Primary public references: Red Hat RHSB-2024-001;
  NIST NVD entry for CVE-2024-3094; Andres Freund's 2024-03-29
  oss-security disclosure.
- **`event-stream` npm incident, 2018**. Maintainership handoff of the
  `event-stream` npm package to a malicious successor, who introduced
  a dependency (`flatmap-stream`) containing payload code targeting
  the `copay` Bitcoin wallet. Shares with `xz-utils` the pattern of
  legitimate acquisition of merge rights by a malicious newcomer,
  differing in sub-case: `event-stream` was full handoff (the
  original maintainer stepped away), `xz-utils` was co-maintainer
  addition alongside an active original maintainer. Both are
  categorically distinct from credential compromise of an existing
  maintainer (see `ua-parser-js`, below). Primary public reference:
  GitHub issue `dominictarr/event-stream#116`.
- **`ua-parser-js` npm incident, 2021**. Credential compromise of the
  package's sole maintainer led to publication of malicious versions
  injecting a cryptominer and credential stealer on Linux and Windows
  clients. Procedure exemplar for *compromise of an existing
  maintainer* (as distinct from the *infiltration* pattern of
  `event-stream` / `xz-utils`). Primary public reference: GitHub
  issue `faisalman/ua-parser-js#536` and the maintainer's post-
  incident statement.
- **OpenSSF SLSA framework** (v1.0, current). Provides a vocabulary
  for supply-chain integrity controls (signed build provenance,
  hermetic builds, source-track requirements including two-party
  review) that map directly onto the §6.4 re-targeting proposed here.
  The RFC does not commit to a specific SLSA Build Level; the Phase 3
  reproducible-builds and SBOM deliverables sit within the territory
  addressed by SLSA's higher build-track and source-track levels.
- **Rust `cargo-vet`** and **`cargo-crev`**, third-party-audit
  systems for the Cargo ecosystem. Out of scope for this RFC but noted
  in *Future possibilities* as a possible defence-in-depth against the
  upstream-dependency half of §5.5.2.a, distinct from the
  own-project-maintainer half §3.2.6 addresses.
- **NIST SP 800-218** (Secure Software Development Framework, SSDF)
  v1.1, practices PS.1 (Protect All Forms of Code from Unauthorized
  Access and Tampering), PS.2 (Provide a Mechanism for Verifying
  Software Release Integrity), and PW.4 (Reuse Existing, Well-Secured
  Software When Feasible). Provides a normative framing for the
  controls this RFC re-targets.

## Unresolved questions

1. **§5.5.2 split layout.** Should the refinement use a/b sub-headings
   (5.5.2.a, 5.5.2.b) as proposed, or should it instead break out into
   two parallel sections (§5.5.2 *Upstream dependency compromise*,
   §5.5.5 *Project maintainer compromise*)? The RFC proposes a/b for
   the reasons in *Rationale and alternatives*, but the alternative is
   defensible and would surface more cleanly in the table of contents.
2. **Whether §3.2 should ever carry likelihood ratings.** §1.1
   declares the document is not a risk assessment and assigns no
   likelihoods. An earlier draft of this RFC carried a likelihood
   paragraph for §3.2.6; it was removed in response to review feedback
   to preserve consistency with §1.1. A future structural revision
   could opt to convert the threat model into a full risk assessment
   (with likelihood and impact ratings across all actors and vectors),
   but that is a substantially larger change and would require its own
   RFC. This RFC takes no position on that direction.
3. **Hardware-backed signing key as a future ADR.** ADR-0006 today
   accepts the single-compromise-affects-both-surfaces trade-off for
   the SSH signing key. A subsequent ADR could record a decision to
   move the maintainer's signing key into a hardware token (FIDO2 /
   smartcard) once one is available. This RFC notes the possibility
   without proposing the decision; it is properly its own ADR.
4. **Reproducible-builds RFC scope.** The §6.4 entry on reproducible
   builds points at a Phase 3 deliverable that is not yet RFC-gated in
   detail. The exact form (bit-reproducible source-to-binary, or
   reproducible-with-known-divergences in dependency versions, or
   SLSA-compatible build provenance) is a decision deferred to its own
   RFC. This RFC commits only to the *direction*.

## Future possibilities

- **Third-party-audit systems for the dependency graph.**
  `cargo-vet`, `cargo-crev`, or a `crev` proof set published under the
  project's name would add a layer of defence to §5.5.2.a that is
  independent of `deny.toml`. A subsequent RFC could evaluate the
  cost-benefit for QuantumSSH specifically.
- **Two-party release process.** When the maintainer team grows past
  one (per `GOVERNANCE.md`'s transition criteria), the release process
  can require co-signature from a second maintainer on the release tag.
  This is a procedural control that closes part of the §3.2.6 residual
  without changing any code; it is naturally a follow-up to the
  governance transition rather than an action this RFC commits to.
- **Detached, externally-witnessed release signatures.** A future
  control could publish release signatures to a public transparency
  log (analogous to Sigstore's `rekor`), making a silently-revoked or
  back-dated release detectable to clients. Distinct from
  reproducible builds, and complementary to it.
- **Maintainer-credential rotation cadence as an ADR.** The project
  could record an ADR committing to periodic rotation of the SSH
  signing key (independent of compromise indication), bounding the
  validity window of any silently-stolen key. Parallel to the
  reasoning in ADR-0005 for the PGP key.
- **Independent monitoring of `main` integrity.** A separate service
  (operated by the maintainer or a third party) could periodically
  fetch `main`'s tip, verify the signing chain against an
  out-of-repository expected-fingerprint set, and emit a public alert
  on divergence. ADR-0008's force-push prohibition prevents history
  rewriting on the canonical remote, but does not detect attacks
  where clients are redirected to a substitute remote, or where the
  canonical remote itself is compromised through admin-level override
  of branch protection.

None of the items above is being proposed by this RFC. They are noted
so that the §3.2.6 entry, once accepted, has a visible trajectory of
possible future strengthening.
