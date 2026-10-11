# ADR 0037: Run the Codex reviewer through the Codex cloud GitHub App, not an API key

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-11)
- **Deciders:** Project lead
- **Related:** Supersedes [ADR-0030](0030-codex-third-automated-reviewer.md) (Codex through `openai/codex-action` with an API key) and the Codex bullet of [ADR-0033](0033-proof-of-review-for-every-automated-reviewer.md) §Decision. Keeps [ADR-0008](0008-branch-protection-zero-required-reviews.md) (automated reviews are advisory, never a merge gate). Implementation: deletes `.github/workflows/codex.yml` and adds a `## Code Review Rules` section to `AGENTS.md`, in the same PR.

## Context

ADR-0030 added Codex as the third automated reviewer and weighed two
shapes. The first was the **Codex cloud GitHub App**, which runs under the
maintainer's ChatGPT plan, reviews on `@codex review` or automatically,
and posts as `chatgpt-codex-connector`. The second was
**`openai/codex-action`** with an `OPENAI_API_KEY` repository secret. ADR-0030 chose the
second, for three reasons:
1. The App's configuration lives in personal ChatGPT settings, where it
   cannot be pinned, diffed or reviewed.
2. Its report follows Codex's P0/P1 format, not `.github/REVIEW-FORMAT.md`.
3. It holds push permission for `@codex fix`.

ADR-0030 also left the door open: "Nothing in this ADR prevents
revisiting that if the App gains repository-controlled, PR-reviewable
configuration."

Two facts changed:

- **The API-key path stopped reviewing.** Since 2026-10-11 16:08 UTC
  every Codex run has failed with `You have no credits remaining` from the
  OpenAI API. An API key is billed against prepaid platform credits,
  separately from a ChatGPT subscription. The maintainer reviews with a
  ChatGPT plan and does not want metered API billing for this reviewer.
  The `codex-action` (v1.12) authenticates only with an API key, and its
  documented inputs offer no ChatGPT sign-in.
- **The review rules are now repository-controlled.** OpenAI's Codex
  GitHub documentation has the reviewer read `AGENTS.md`, with a
  `## Code Review Rules` section in the file closest to the code it
  governs. What Codex checks therefore lives in a versioned file, changed
  by PR like everything else. Only the on/off switch and the repository
  selection remain in ChatGPT settings.

ADR-0030 already records that the App is installed on the maintainer's
account. It lacked an environment for this repository, so `@codex`
answered with a set-up prompt.

## Decision

We will run the Codex reviewer through the **Codex cloud GitHub App**,
under the maintainer's ChatGPT plan, and remove the API-key workflow.

- **Configuration, outside the repository.** Three settings, and this
  ADR is their only record:
  - `gonzafg2/quantumssh` is connected as a Codex environment.
  - **Automatic review** is on for it in Codex's code-review settings.
  - **Review trigger** is **On every push**. That keeps the cadence of
    the workflow it replaces, which ran on `synchronize`, so every push
    to a PR is reviewed. "On PR open" and "Smart" would review fewer
    pushes, and are not used.

  `@codex review` on a PR still requests a review on demand.
- **Review rules, inside the repository.** A `## Code Review Rules`
  section in `AGENTS.md` points Codex at the authoritative criteria in
  `CLAUDE.md` and `docs/threat-model.md`, so they are not restated, and
  sets the house rule that Codex never pushes. Changing what Codex checks
  is a PR to that section.
- **Report format.** Codex posts its own native review: inline comments,
  scoped to P0/P1. `.github/REVIEW-FORMAT.md` now binds only the two
  workflow reviewers, opencode and Claude Code Review.
- **Proof of review.** There is no workflow, so there is no check. This
  supersedes ADR-0033's Codex bullet. A Codex review is a GitHub review
  by `chatgpt-codex-connector` on the PR, and its absence is visible
  there. The reviewers stay advisory (ADR-0008, ADR-0031): none is a
  required check.
- **No writes from the App.** `@codex fix` and Codex cloud tasks are not
  used on this repository, and the `AGENTS.md` rules tell Codex not to
  push. The structural guard is unchanged: branch protection on `main`
  (ADR-0008, no bypass) means nothing reaches `main` except through a PR
  the maintainer merges. A squash merge takes every commit on the branch,
  so before merging the maintainer checks that the PR head carries no
  commit by `chatgpt-codex-connector`. Such a commit would also lack the
  DCO sign-off every commit requires.
- **Credential removal.** `.github/workflows/codex.yml` is deleted in
  this PR. After merge, the maintainer deletes the `OPENAI_API_KEY`
  repository secret and revokes the key in its OpenAI project.

**Why an ADR, not an RFC.** `CLAUDE.md` sends "a dependency that
materially expands the trust base" to an RFC. This change is recorded as
an ADR, the same lane ADR-0025 and ADR-0030 used for the two previous
reviewer changes, for three reasons:

1. It adds no dependency to the server, and it removes one from CI
   (`codex-action` and its pinned CLI).
2. It changes how an already-accepted third reviewer authenticates. It
   does not change whether the project sends PRs to an external
   inference provider; ADR-0025 and ADR-0030 settled that class of trust.
3. The one new authority it grants, the App's write access to non-`main`
   branches, is bounded by branch protection. It is also reversible
   without a code change: narrow the App's repository selection or
   uninstall it.

The residual is stated here rather than argued away. A compromised App
could push to an open PR's branch, and the pre-merge check above is the
control.

**Acceptance test.** On 2026-10-11 the App reviewed this PR (head
`4d3d9bb`) after an `@codex review` comment, from the repository's
Codex environment. Its own footer confirms that reviews also run when a
PR is opened or marked ready.

## Consequences

### Positive

- No inference API key in the repository. This removes the exfiltration
  residual that ADR-0030 recorded for `OPENAI_API_KEY`: a same-repository
  PR rewriting `codex.yml` to read the secret.
- The third reviewer runs on the maintainer's existing plan, with no
  metered billing that can silently drain to zero.
- No workflow, no pinned action and no pinned CLI to maintain.
  Dependabot's `codex-action` bumps go away.
- The review uses GitHub's native review UI, with inline comments.

### Negative

- The on/off switch and repository selection live in personal ChatGPT
  settings. They cannot be diffed or reviewed, and a change there
  happens without a PR. This ADR records the intended state; the review
  rules themselves are versioned in `AGENTS.md`.
- **P0/P1 only.** Codex in GitHub reports only high-priority findings.
  Lower-severity coverage comes from the two workflow reviewers.
- **No check.** A missing Codex review shows as the absence of a review,
  not as a red status.
- Review volume is bounded by the ChatGPT plan's usage limits.
- The App holds repository write permission, which it needs for
  features this project does not use. That is a new principal able to
  push to PR branches, which the API-key workflow never had. It is
  mitigated by the no-push policy, branch protection on `main`, and the
  pre-merge check for commits by `chatgpt-codex-connector`, and it is
  reversible by uninstalling the App.

### Neutral

- Every place that named the `codex` workflow is updated in this PR:
  - `CLAUDE.md`, both the contribution conventions and the repo map;
  - `AGENTS.md`, both the Git workflow and Key files sections;
  - the header of `.github/REVIEW-FORMAT.md`;
  - `.github/PULL_REQUEST_TEMPLATE.md`;
  - the comments in `claude-code-review.yml` and `opencode.yml` that
    referred to `codex.yml`.
- ADR-0030's Status becomes "Superseded by ADR-0037". ADR-0033's Status
  records that its Codex bullet is superseded, as ADR-0020's Status does
  for the bullet ADR-0034 replaced. Only Status fields change (ADR-0015).

## Alternatives considered

### Alternative 1: Keep `codex-action` and buy API credits

Rejected. The maintainer does not want metered API billing for a
reviewer the plan already covers. It also keeps an inference key
reachable by any same-repository PR that edits the workflow.

### Alternative 2: Feed a ChatGPT session (`auth.json`) to `codex-action`

Rejected. The action documents only API-key authentication, and the
approach would store a personal session credential as a repository
secret, with the same exfiltration exposure and a broader blast radius.

### Alternative 3: Drop Codex and stay at two reviewers

Rejected for the reason ADR-0030 gave: provider diversity is the point
of a third reviewer.

## Links

- OpenAI, [Review GitHub pull requests with Codex](https://learn.chatgpt.com/docs/third-party/github): automatic review and `@codex review`, `## Code Review Rules` in `AGENTS.md`, the P0/P1 scope, and the `chatgpt-codex-connector` identity.
- [`openai/codex-action`](https://github.com/openai/codex-action): API-key authentication only (`openai-api-key` input).
- Superseded: [ADR-0030](0030-codex-third-automated-reviewer.md); the Codex bullet of [ADR-0033](0033-proof-of-review-for-every-automated-reviewer.md).
- Removed: `.github/workflows/codex.yml`. Added: the `## Code Review Rules` section in `AGENTS.md`.
