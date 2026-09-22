# ADR 0031: Require `commit-lint` and `openssh-interop` as status checks on `main`

- **Status:** Accepted
- **Date:** 2026-09-22 (accepted on merge of [#155](https://github.com/gonzafg2/quantumssh/pull/155))
- **Deciders:** Project lead
- **Related:** Amends the required-status-checks bullet of [ADR-0008](0008-branch-protection-zero-required-reviews.md) §Decision (every other bullet of ADR-0008 stands); implements the "required check" bullet of [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) §Decision; leaves [ADR-0030](0030-codex-third-automated-reviewer.md) §Decision ("not a merge gate") unchanged; the `commit-lint` job was introduced by [PR #67](https://github.com/gonzafg2/quantumssh/pull/67). Documented state: `docs/infrastructure.md` §"Required status checks", `docs/operations.md` §"Branch protection on `main`".

## Context

[ADR-0008](0008-branch-protection-zero-required-reviews.md) (2026-05-10)
fixed the branch-protection rule on `main` and enumerated the CI
contexts that existed on that day as the required status checks:
`build (ubuntu-latest)`, `build (macos-latest)` and `cargo deny`.

Two more jobs have run on every pull request since then, without being
added to the rule:

- **`commit-lint`** (`.github/workflows/ci.yml`, [PR #67](https://github.com/gonzafg2/quantumssh/pull/67),
  2026-06-13) rejects any commit subject in the PR that does not follow
  Conventional Commits, the convention `CONTRIBUTING.md` and `CLAUDE.md`
  require. Merge and revert commits are exempt.
- **`openssh-interop`** (`.github/workflows/interop.yml`, [PR #84](https://github.com/gonzafg2/quantumssh/pull/84),
  2026-06-26) drives a real OpenSSH 10.x client through connect →
  publickey auth → exec → close against the release binary.
  [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) (accepted
  2026-07-01) states in its Decision that this job *is a required check
  for merge into `main`*.

Because neither job was in the rule, a PR with a red interop gate or a
non-conforming commit subject could be merged: ADR-0020's central
property — an interop failure blocks the merge — was documented but not
enforced. On 2026-09-22 the rule was extended to the five contexts.

ADR-0008's list was correct when it was accepted, so this is not an
erratum under [ADR-0015](0015-permit-annotated-errata-in-adrs.md); it is
a broadening of a recorded decision, which the ADR lifecycle requires to
be recorded in a new ADR. This ADR is that record.

## Decision

We will require five status checks to pass before a pull request can
merge into `main`:

- `build (ubuntu-latest)` and `build (macos-latest)` — format, lint,
  tests and release build (unchanged from ADR-0008).
- `cargo deny` — licences, advisories, sources and bans (unchanged from
  ADR-0008).
- `commit-lint` — every commit subject in the PR follows Conventional
  Commits. The convention is project policy; a check that only reports
  is enforced by nobody, and the subject of the squash commit that lands
  on `main` is taken from the PR title or the commit messages.
- `openssh-interop` — the OpenSSH interop gate, as ADR-0020 decides.

Further points:

- The membership of this list is a decision, not a setting: adding or
  removing a required check is recorded in an ADR that supersedes this
  one.
- The automated reviewers (`claude-review`, `opencode`, `codex`) and
  CodeQL remain advisory, per ADR-0008 and ADR-0030; they are not
  required checks.
- "Require branches to be up to date before merging" (`strict`) stays
  enabled, as it was under ADR-0008.
- Every other bullet of ADR-0008 — pull requests for all changes, signed
  commits, linear history, enforce-on-admins, required conversation
  resolution, zero approving reviews — stands unchanged.

## Consequences

### Positive

- The property ADR-0020 promises is now enforced: a PR whose OpenSSH
  gate fails cannot merge.
- The enforced state and the documented state (`docs/infrastructure.md`,
  `docs/operations.md`) agree, and this ADR is their authoritative
  reference.
- Conventional Commits is enforced at the merge gate instead of being
  checked after the fact.

### Negative

- A red `openssh-interop` blocks every open PR, and ADR-0008's
  enforce-on-admins leaves no bypass. The block is recoverable without
  touching the protection rule: `pull_request` workflows run against
  the merge result, so a PR that fixes `interop.yml` runs its own
  corrected gate.
- The gate depends on `deb.debian.org` being reachable during
  `apt-get`. ADR-0020's package-version pin from a frozen source, which
  would remove that dependency, is not implemented in `interop.yml`
  ([PR #98](https://github.com/gonzafg2/quantumssh/pull/98) was closed
  without merging); that gap is a separate decision and is not resolved
  by this ADR.
- A merge waits for the slowest required check (`openssh-interop`,
  about a minute, versus about 35 seconds for `build`).

### Neutral

- Dependabot PRs already run both jobs (neither has an author gate), so
  nothing changes for bot-authored PRs.
- `strict` already forced open PRs to re-run their checks after `main`
  moved; two more required contexts do not add CI runs, they only add
  to what must be green.

## Alternatives considered

### Alternative 1: Annotate ADR-0008 with an erratum

Rejected. ADR-0015 reserves errata for claims that were wrong at the
time of acceptance; ADR-0008's list was accurate on 2026-05-10.
Changing the list is "we decided X, now we decide Y", which the ADR
lifecycle routes through a new ADR.

### Alternative 2: Require only `openssh-interop`

ADR-0020 already decides it, so the rule could have been extended by
that one check with no new ADR. Rejected because `commit-lint` had been
green on every PR since #67, including Dependabot's, at no additional
cost, and leaving a policy check advisory means the policy is not
enforced anywhere.

### Alternative 3: Also require CodeQL and the automated reviewers

Rejected. ADR-0008 and ADR-0030 keep automated review advisory. CodeQL
default setup cannot be pinned or reproduced the way the other gates
are, and its alerts need human triage: the eight `hard-coded-cryptographic-value`
alerts of 2026-09 were known-answer test vectors inside `#[cfg(test)]`
raised by CodeQL engine upgrades, not by code changes.

## Links

- Configuration that implements this decision: the branch-protection
  rule on `main` (read it with the recipe in `docs/operations.md`
  §"Branch protection on `main`"); job names in
  `.github/workflows/ci.yml` (`commit-lint`, `build (…)`),
  `.github/workflows/deny.yml` (`cargo deny`),
  `.github/workflows/interop.yml` (`openssh-interop`).
- Related ADRs: [ADR-0008](0008-branch-protection-zero-required-reviews.md)
  (amended), [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md)
  (implemented), [ADR-0030](0030-codex-third-automated-reviewer.md)
  (unchanged).
- Discussion: [PR #155](https://github.com/gonzafg2/quantumssh/pull/155).
