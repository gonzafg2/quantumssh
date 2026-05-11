# ADR 0015: Permit annotated post-acceptance errata edits in ADRs

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** Project lead
- **Related:** Updates [`docs/adr/README.md`](README.md) (the ADR process). Retroactively legitimises the in-place edits applied to [ADR-0003](0003-hsts-preload-deferred.md), [ADR-0011](0011-ci-guards-workspace-state.md), and [ADR-0013](0013-dmarc-tightened-to-p-reject.md) in this and prior PRs, each of which now carries the annotation that this ADR formalises.

## Context

The ADR process introduced in [PR #12](https://github.com/gonzafg2/quantumssh/pull/12), via [`docs/adr/README.md`](README.md), declares accepted ADRs immutable after merge with one narrow exception: the Status field, which may be updated when the ADR is superseded or deprecated. All other change paths funnel through writing a new ADR that supersedes the previous one.

Two subsequent PRs ran into the limits of that rule. In [PR #13](https://github.com/gonzafg2/quantumssh/pull/13), the project corrected factual errors in already-accepted ADR-0003 (an internally-inconsistent claim about HSTS preload eligibility) and ADR-0011 (an inaccurate description of the CI guard predicate split). Both corrections were applied **in place**, against the strict reading of the process. Copilot's automated review of [PR #13](https://github.com/gonzafg2/quantumssh/pull/13) raised the violation explicitly:

> "This ADR is marked Accepted but is being edited in place. `docs/adr/README.md` states that accepted ADRs are never edited after acceptance (except Status updates when superseded/deprecated). If the goal is to correct the historical record, consider adding a new ADR that supersedes ADR-0003 (or introducing an errata process)…"

The substance of the edits was correct in each case — the ADRs contained factual errors that needed correction. The problem was that the process had no mechanism for that scenario. The two pragmatic responses are:

1. Write a brand-new ADR every time a factual error needs correction, even for a paragraph-level fix.
2. Permit in-place edits explicitly, with annotation, so the change is auditable from the file itself.

The first response generates ADR proliferation for trivial fixes; the second introduces a small risk that decision-level changes could be smuggled in under the heading of "errata". The right answer for a project of this size is the second, with a constrained definition of errata and an explicit annotation requirement.

## Decision

We will amend the ADR lifecycle in [`docs/adr/README.md`](README.md) to permit a second kind of in-place edit on accepted ADRs:

- **Factual errata.** Corrections to factual claims that were wrong at the time of acceptance — typographical, numerical, descriptive, or logical errors. Errata edits **must** add (or extend, if already present) a `Post-acceptance errata` banner near the top of the ADR, documenting:
  1. The date of the edit.
  2. The PR or CHANGELOG entry that records it.
  3. A short description of what was corrected.

The full pre-edit wording remains discoverable in git history. The banner makes the editing event discoverable from the file itself, so a reader does not need to `git blame` to know an ADR has been corrected.

What remains **not** permitted as in-place edits:

- **Decision changes.** Any change that revises the decision the ADR records, narrows it, broadens it, or reverses it. These still require a new ADR that supersedes the old one. Errata are for "we said X but X is incorrect"; supersession is for "we decided X, now we decide Y".

## Consequences

### Positive

- The process matches what the project has already done, instead of leaving the past two PRs in a quiet state of policy violation.
- Trivial factual corrections no longer require writing a new ADR. The ratio of ADR files to actual decisions stays sensible.
- The errata banner is a discoverability mechanism: readers see at the top of a corrected ADR that something was edited post-acceptance, and they can follow the PR/CHANGELOG pointer to read what changed and why.
- The git history remains the authoritative record of the original wording for forensic uses.

### Negative

- Errata edits create a small abuse vector. A maintainer could in principle frame a decision change as an "errata" and edit it in place. Mitigation: code review can challenge any in-place edit that revises the decision rather than correcting a factual error; the banner's "description of what was corrected" makes such drift visible.
- The Status field is now one of two acceptable in-place edits, not the only one. The README has to make the distinction precise to remain readable.

### Neutral

- This ADR retroactively recognises that the in-place edits in PR #13 were errata. Each affected ADR (0003 and 0011) is updated in this same PR to add the errata banner that this ADR formalises. The substance of those edits is not changed — only the meta-record of how they happened.

## Alternatives considered

### Alternative 1: Maintain strict immutability; write new ADRs for every factual fix

The original rule. Rejected because a one-paragraph factual correction does not warrant a full ADR, complete with Context / Decision / Consequences / Alternatives sections. The ratio of process overhead to substance becomes absurd.

### Alternative 2: Permit unannotated in-place edits

Would match the way many smaller projects actually treat their decision records. Rejected because it discards the auditability the ADR system is supposed to provide. Without the annotation, a reader has no signal that an ADR was modified post-acceptance, and the project's claim that ADRs are a "permanent record of the decision" becomes false in a way the reader cannot detect.

### Alternative 3: Externalise the errata mechanism — keep a separate errata log file

Would preserve strict immutability of ADR bodies. Rejected because it splits the record across files. A reader looking at ADR-0003 should see in ADR-0003 that it was corrected, not have to know to also consult `docs/adr/ERRATA.md`. The cost of the cognitive split outweighs the benefit of strict immutability.

## Links

- The updated process is documented in [`docs/adr/README.md`](README.md) (this PR also updates that file).
- The annotation pattern is applied retroactively in this PR to:
  - [ADR-0003](0003-hsts-preload-deferred.md) — re-annotates the PR #13 correction of the HSTS preload-eligibility wording.
  - [ADR-0011](0011-ci-guards-workspace-state.md) — re-annotates the PR #13 correction of the two-predicate description, plus a small further correction in this PR about when `Cargo.lock` appears at the repo root.
  - [ADR-0013](0013-dmarc-tightened-to-p-reject.md) — annotates this PR's correction of overstated "Receivers reject" wording.
- This PR closes the open Copilot finding from PR #13 review: "introducing an errata process".
