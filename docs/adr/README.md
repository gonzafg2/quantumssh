# Architecture Decision Records (ADRs)

This directory holds the project's record of architectural and
operational decisions. Each ADR is a short, focused document that
captures one decision: what was chosen, why, what alternatives were
considered, and what the consequences are.

ADRs are a complement to RFCs ([`docs/rfcs/`](../rfcs/)), not a
replacement. The two serve different purposes:

| | RFC | ADR |
|---|---|---|
| **When** | Before — proposes a substantial design change | During or after — records a decision taken |
| **Weight** | Heavy: ~500–2000 lines, nine sections | Light: ~50–150 lines, six sections |
| **Audience** | Community discussion | Audit trail and onboarding |
| **State** | Draft → Accepted / Rejected / Postponed | Accepted (immutable) → Superseded by another ADR |
| **Examples** | "Adopt ML-KEM-768 + X25519 for the default key exchange", "SFTP subsystem design" | "We use Python `tomllib` in CI workspace-empty guards", "PGP key expires every two years" |

When a substantial proposal goes through the RFC process and is
accepted, the implementing decisions are recorded as one or more ADRs
that cite the RFC. Smaller decisions that do not warrant the RFC
process land directly as ADRs.

## When to write an ADR

Write one when a decision satisfies any of these:

- It is non-obvious — a reader would reasonably ask "why did you choose
  X instead of Y?" later.
- It involves trade-offs that future maintainers might want to
  reconsider.
- It locks in a constraint (a dependency, an algorithm, a policy) that
  is easier to record now than to reconstruct later.
- It records the operational state of a third-party service or a
  configuration whose presence in the code is not self-evident.

Do **not** write one for:

- Implementation details that are obvious from the code itself.
- Bug fixes (the commit message and the diff are sufficient).
- Decisions that already live in a more authoritative document
  (`SECURITY.md`, `GOVERNANCE.md`, `README.md`) — link to that document
  from the ADR instead of duplicating it.

When in doubt, write the ADR. It is cheap; not having it is expensive.

## Scope: one decision per ADR

An ADR records a single decision. When a substantial RFC is accepted,
the implementing decisions are split into separate ADRs, each citing
the RFC; they are not packaged into one ADR. This keeps the ADR catalog
navigable — a reader scanning filenames sees one decision per slug —
and lets each ADR be referenced, superseded, or annotated with errata
independently.

If you find yourself writing an ADR with two unrelated decisions in it,
split them. ADRs are cheap; the cost of an extra file is far below the
cost of having to disentangle two decisions when one of them is
superseded later.

## Numbering

ADRs are numbered sequentially starting from `0001`. The number is
permanent — once assigned, it never changes, even if the ADR is
superseded or deprecated. New ADRs claim the next free number on
merge.

The filename follows the pattern `NNNN-short-slug.md`, kebab-cased.

## Lifecycle

An ADR moves through three terminal states:

- **Accepted** — the decision is in effect. The ADR is now part of the
  project's authoritative record.
- **Superseded by ADR-NNNN** — a later ADR replaced this one. The
  original stays in the repository as historical record. The new ADR
  cites it.
- **Deprecated** — the decision is no longer relevant (e.g., the
  feature it governed was removed) but no new ADR replaced it.
  Recorded for posterity.

ADRs are **never edited in place** after acceptance, with two narrow
exceptions:

1. **The Status field**, when the ADR is superseded or deprecated.
2. **Factual errata** — corrections to factual claims that were wrong
   at the time of acceptance (typographical, numerical, descriptive,
   or logical errors). Errata edits **must** add a
   `Post-acceptance errata` banner near the top of the ADR documenting
   the date, the PR or CHANGELOG entry that records the edit, and a
   short description of what was corrected. The full pre-edit wording
   remains in git history; the banner is what makes the editing event
   discoverable from the file itself.

Errata are explicitly **not** a mechanism for decision changes. If
you want to change the decision the ADR records — revise it, narrow
it, broaden it, reverse it — write a new ADR that supersedes the old
one. Errata are for "we said X but X is incorrect"; supersession is
for "we decided X, now we decide Y".

The errata mechanism was introduced by [ADR-0015](0015-permit-annotated-errata-in-adrs.md);
that ADR is the authoritative reference for the rule and its rationale.

## Process

1. **Copy `0000-template.md`** to a new file with the next free number
   and a kebab-cased slug. (Number conflicts on simultaneous PRs are
   resolved by renaming on merge.)
2. **Fill it in.** Be specific: name the alternatives you considered,
   not just the one you chose.
3. **Open a pull request** that adds the file under `docs/adr/`. Tag
   it with the `documentation` label and, if applicable, the topical
   label (`security`, `rust`, etc.).
4. **Discussion happens on the PR.** Material objections must be
   resolved before merge; the ADR is then accepted by lazy consensus.
5. **On merge, the ADR is Accepted.** It is now load-bearing for the
   project.

For decisions that need broader discussion before a position is
formed, write the RFC first. Once the RFC is accepted, the
implementing decision(s) land as ADRs that cite it.

## Reading ADRs

A casual reader should be able to scan the directory listing and get a
sense of the project's shape. Each filename starts with a number and a
slug; the slug is the gist of the decision. Open an individual ADR for
context, alternatives, and consequences.

For the operational topology these ADRs collectively describe, see
[`../infrastructure.md`](../infrastructure.md), which uses these ADRs
as its primary references.
