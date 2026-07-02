# ADR 0027: `docs/plans/` is a fourth, mutable, non-authoritative doc category

- **Status:** Accepted
- **Date:** 2026-07-01
- **Deciders:** Project lead
- **Related:** Resolves [issue #79](https://github.com/gonzafg2/quantumssh/issues/79); builds on the governance contract in [`CLAUDE.md`](../../CLAUDE.md) (RFC / ADR / plain-PR lanes) and the errata-banner mechanism of [ADR-0015](0015-permit-annotated-errata-in-adrs.md); the [`docs/rfcs/README.md`](../rfcs/README.md) "one decision per RFC" discipline informs the anti-split rule below.

## Context

`docs/plans/` holds pre-implementation design documents — `m4-authentication.md`, `m5-channels.md`, and the pattern will continue (M6 landed with a plan in the session record; future milestones will produce more). These are working documents: pseudocode, sequencing, rationale, and decisions-in-flight captured *before* the code exists.

`CLAUDE.md` defines exactly three document categories, each with a governance contract:

- **RFC** ([`docs/rfcs/`](../rfcs/)) — shape-determining, immutable after approval.
- **ADR** ([`docs/adr/`](../adr/)) — locked-in operational decisions, immutable except Status/errata ([ADR-0015](0015-permit-annotated-errata-in-adrs.md)).
- **plain PR / issue** — ephemeral, tied to one change.

`docs/plans/` fits none: it is committed to `main` (so not ephemeral like a PR body), but it is neither shape-determining nor immutable. It has no stated authority, no review contract, and — the concrete risk — nothing stops a plan from becoming the *sole* record of a decision that ought to live in an ADR. The M4 plan already drifted from the code it described (an attempt-count mismatch), which is exactly the failure mode of an unstated, mutable document being read as authoritative. The two existing plans carry a provisional banner deferring to this issue.

## Decision

`docs/plans/` is a **fourth document category**: **mutable, non-authoritative design notes**. These are either *milestone plans* that accompany an implementation (the M4/M5 plans) or *pre-implementation scoping notes* that capture the constraint set and options for future work before it is scheduled (e.g. a Phase-3 privilege-separation scoping note; issue #79 asked whether the lane covers such non-milestone notes — it does). Its contract:

1. **Non-authoritative after merge.** A note guides the work while it is written and merged alongside it, but once the work lands the *code, ADRs, and RFCs* are authoritative — not the note. A scoping note for not-yet-scheduled work is non-authoritative from the start: it records a constraint set and options, never a decision. A note is retained for its design rationale, not as a source of truth for what the system does.

2. **A mandatory, dated `Governance status` banner** heads every file in `docs/plans/`, in the same spirit as ADR-0015's errata banners. It states: the date, that the file is non-authoritative, what it guides or scopes, and **which ADRs/RFCs (and/or tracking issue) hold the authoritative decisions**. Template:

   ```
   <!--
     Governance status (YYYY-MM-DD):
     Non-authoritative design note (ADR-0027). <Guided <milestone> (PR #NN)
     | Scopes <future work>; tracked in #NN>.
     Authoritative decisions live in ADRs/RFCs: <list, or "none yet">.
     This file is retained for rationale and is not a source of truth.
   -->
   ```

3. **Anti-split rule (the load-bearing guard).** A plan must **never be the sole record of a locked-in decision.** Any decision that determines behaviour, an interface, or a security property is recorded in an ADR (or an RFC if shape-determining); the plan may reference it but never replace it. This preserves the RFC/ADR "single discoverable source of reasoning" property the RFC process exists for.

4. **Mutability without ceremony.** Plans may be edited freely (unlike ADRs/RFCs) — they carry no immutability guarantee and need no superseding document. They are not required for any change; they are a convenience for milestones large enough to benefit from a written plan.

5. **No new review gate.** A plan rides its milestone's PR review; it does not get its own approval process. It is not a decision-making lane — it is a working note.

## Consequences

### Positive

- Closes the governance gap #79 names: `docs/plans/` now has a stated contract, so a reader knows exactly how much authority a plan carries (none, post-merge).
- The anti-split rule prevents the drift failure mode: a locked decision can never hide only in a mutable plan.
- Formalises what the repository already does de facto (both existing plans carry a proto-banner), so no existing artifact is invalidated — only regularised.
- Keeps plans cheap: no immutability, no separate review, no superseding overhead. Milestones that want a plan pay nothing extra.

### Negative

- A fourth category is more governance surface than three. Mitigated by the category being deliberately the *weakest* (non-authoritative, mutable) — it adds a lane, not a process.
- The banner is a small per-plan tax and can go stale if unmaintained. Mitigated by it being short, dated, and required only to point at the authoritative ADRs/RFCs, not to restate them.

### Neutral

- Option 1 (migrate every locked decision to ADRs, then **delete** the plan) is largely satisfied already — each plan's locked decisions are already in ADRs (M4: 0021/0023/0024; M5: 0016/0020/0023/0024), as its banner records. This ADR declines only the *deletion* half: deleting a merged plan destroys retained rationale for no governance gain, and the M4 deletion was already declined once.

## Alternatives considered

### Alternative 1: Migrate decisions to ADRs and delete the plan post-merge

Extract every locked decision into ADRs, then remove the plan. **Rejected** for the deletion step only: the extraction is already the anti-split rule (Decision §3), but deleting the merged plan throws away design rationale (the "why we considered and rejected X" that never reaches an ADR) for no benefit. Retaining a clearly-marked non-authoritative note is strictly more informative.

### Alternative 2: Keep plans in the PR description only, never on `main`

**Rejected**: it splits the record — the plan's rationale lives in a PR while the code lives on `main`, and PR bodies are not versioned with the tree, not greppable from a checkout, and rot as PRs are archived. This is the exact record-splitting the RFC README and ADR-0015 argue against.

### Alternative 3: Leave `docs/plans/` undefined

**Rejected**: this is the status quo #79 exists to end. An undefined, mutable, committed document is read as authoritative by default, which already caused one drift.

## Links

- Resolves [issue #79](https://github.com/gonzafg2/quantumssh/issues/79).
- Governed by / consistent with [ADR-0015](0015-permit-annotated-errata-in-adrs.md) (errata-banner mechanism) and the [`docs/rfcs/README.md`](../rfcs/README.md) anti-split reasoning.
- `CLAUDE.md` "RFC vs ADR vs plain PR" section (new Plan bullet) and the Repo-map table updated to name this fourth lane.
