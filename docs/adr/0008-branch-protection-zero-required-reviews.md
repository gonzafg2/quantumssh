# ADR 0008: Require PR + signed commits + linear history, with zero approving reviews

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** `GOVERNANCE.md`, [ADR-0006](0006-commit-signing-ssh-not-gpg.md) (signing back-end), `docs/infrastructure.md` § "Branch protection on `main`"

## Context

`GOVERNANCE.md` records that the project operates under a single
maintainer during Phases 0–2 of the roadmap, with a documented
transition to a maintainer team when the criteria (three regular
contributors over six months plus a `0.1.0` release) are met.

GitHub branch protection on `main` offers several mechanisms that
are useful independently:

- Require PRs (vs. direct push).
- Require approving reviews (count configurable).
- Require status checks to pass.
- Require signed commits.
- Require linear history.
- Enforce on admins.

The `required_approving_review_count` setting is normally the heart of
a code-review process. In a multi-maintainer project, requiring at
least one approving review is the default healthy posture. In a
single-maintainer project, the same requirement either (a) blocks the
project entirely, or (b) forces the maintainer to invent fictional
reviewers, neither of which is honest.

## Decision

We will configure branch protection on `main` to require:

- Pull requests for all changes (no direct push).
- Signed commits.
- Linear history.
- All three CI status checks passing
  (`build (ubuntu-latest)`, `build (macos-latest)`, `cargo deny`).
- Enforce-on-admins (the maintainer is not exempt).
- Required conversation resolution.
- **Zero** approving reviews.

Force pushes and branch deletion are disallowed.

The required-review count will rise to one when the maintainer team
grows past one person, per the transition criteria in `GOVERNANCE.md`.

## Consequences

### Positive

- Every change passes through a PR, a CI gate, and a signed commit —
  the audit trail and the protection against malicious push are
  preserved.
- The configuration is honest about the project's current size; the
  bar to merge matches the bar a single maintainer can meet.
- When the maintainer team grows, raising the count is a one-line
  configuration change, not a rethink.

### Negative

- The optics are unusual. A reader unfamiliar with the project's
  governance might assume "zero required reviews" means the project
  has weak hygiene. Mitigation: this ADR exists to make the
  configuration legible.
- A solo maintainer cannot benefit from a second pair of eyes
  enforced by tooling. Mitigation: the maintainer can request
  external review on individual PRs (e.g., from auditors or
  cryptography reviewers) without that review being a merge-gate.

### Neutral

- "Enforce on admins" means the maintainer cannot bypass branch
  protection either; this is deliberate.

## Alternatives considered

### Alternative 1: Require one approving review

Default healthy posture. Rejected because for a single maintainer this
either blocks the project or forces fake reviewers.

### Alternative 2: Allow direct push to `main` for the maintainer

Some projects exempt admins or use a less-strict configuration for
solo maintainers. Rejected because the audit trail through PRs is
itself valuable (PR descriptions, automated reviews, conversation
resolution) regardless of the review count.

### Alternative 3: Require a CODEOWNERS approval

Would require the maintainer to set themselves as CODEOWNER and
approve their own PRs, which GitHub refuses to allow. Rejected as
operationally impossible.

## Links

- Read the current configuration:
  `gh api repos/gonzafg2/quantumssh/branches/main/protection --jq '{...}'`
  (full invocation in `docs/operations.md`)
- Governance transition criteria: `GOVERNANCE.md`
