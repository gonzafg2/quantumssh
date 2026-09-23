# ADR 0033: A green reviewer check requires a review-shaped report on the PR

- **Status:** Proposed
- **Date:** 2026-09-22 (drafted; becomes the acceptance date on merge)
- **Deciders:** Project lead
- **Related:** Generalises the proof-of-review bullet of [ADR-0032](0032-opencode-reviewer-provider-model-variable-and-proof-of-review.md) §Decision (opencode) to the Claude reviewer; the Codex reviewer already satisfies it by construction ([ADR-0030](0030-codex-third-automated-reviewer.md) §Decision, "Posting"). Adds to the Claude workflow the same-repository-head gate ADR-0030 and ADR-0032 apply. Leaves [ADR-0008](0008-branch-protection-zero-required-reviews.md) and [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md) unchanged: the reviewers stay advisory. Implementation: `.github/workflows/claude-code-review.yml` (lands in the same PR).

## Context

The three automated reviewers post their reports as PR comments, and
`.github/REVIEW-FORMAT.md` tells maintainers to read those reports before
merging. A reviewer's check turning green was taken to mean a report
existed. For the Claude reviewer that was never guaranteed: the action
exits 0 when the agent's turn ends, whether or not the agent posted
anything.

On 2026-09-22 that produced three green checks with no report, for three
different reasons:

- On a **draft** PR (#155), the `code-review` plugin stops by design and
  posts nothing.
- On a PR it had **already reviewed** (#157, later pushes), the plugin
  finds its own earlier general comment and stops — it does not review
  every push.
- On #158 the agent **ended its turn early**: after 56 seconds its last
  message was "Both agents are running. I'll wait for them to complete",
  its subagents were still running, and the workflow reported success.

The first two are the plugin's design; the third is the failure this ADR
exists for, and nothing in the workflow could tell it apart from the
other two. A fourth case surfaced while landing this ADR: the action
refuses to run a workflow file that differs from the one on the default
branch ("Skipping action due to workflow validation") and exits 0
without a transcript — its guard against a PR rewriting the workflow,
which means a PR that edits `claude-code-review.yml` cannot receive a
Claude review before it merges. [ADR-0032](0032-opencode-reviewer-provider-model-variable-and-proof-of-review.md)
already closed the equivalent gap for opencode by counting the comments
the action posted before letting the check pass.

## Decision

We will make every automated reviewer's check green only when a
review-shaped report by that reviewer is on the PR:

- **Claude Code Review.** After the action succeeds, a step fails the job
  when the action left no transcript (it skipped itself; the message
  names the workflow-validation case), and otherwise fails the job unless
  the PR carries a review signal by `claude[bot]` (or
  `anthropic-code-agent[bot]`, the action's other posting identity):
  a top-level inline review comment — only this workflow mounts the
  inline-comment MCP tool; `claude.yml`'s answers to `@claude` inside a
  review thread are threaded replies, which the count excludes — or a
  general comment or review whose body reads as a report ("PR Review"
  or "Code review"). The login alone is not the proof:
  `.github/workflows/claude.yml` answers `@claude` mentions under the
  same `claude[bot]` identity, and the review action posts its own error
  messages under it, so an identity-only count could go green on a reply
  or a failure. The exact `.github/REVIEW-FORMAT.md` heading is not
  required either: on real reviews the plugin has posted a different
  heading (`## Code review`, #156) or lost the `##` of its `PR Review:`
  line (#159), and a check that goes red on a posted review is as
  misleading as one that goes green on none. The residual — an `@claude`
  reply that happens to contain "code review" — is accepted and named
  here. Because the plugin stops when it finds its own general comment
  on the PR (its check reads general comments, so a first pass that left
  only inline comments is followed by a second one), the count covers
  the whole PR, not the current run: a green check
  means *a review-shaped claude[bot] comment or review is on this PR*,
  not *this push was reviewed*. That
  is what the plugin offers, and the workflow says so rather than
  pretending otherwise. The job no longer runs on draft PRs (the plugin
  would stop anyway; `ready_for_review` triggers it) nor on PRs whose head
  lives in a fork, the gate the other two reviewers already apply.
- **opencode.** ADR-0032's proof step stands: comments by
  `opencode-agent[bot]` since the run started that carry this run's URL.
- **Codex.** Under ADR-0030 the workflow's own `post` job publishes the
  assembled report; its check cannot be green without the post having
  succeeded. No change.
- The reviewers remain advisory (ADR-0008, ADR-0031): a red proof step
  blocks nothing; it tells the maintainer that a review they were counting
  on did not happen, so the fix is a re-run, not a merge on faith.

## Consequences

### Positive

- A run whose agent stops early is red, with an error message that names
  the transcript artifact to read and the remedy (re-run).
- The two reviewers that can fail silently now share one mechanism; the
  third is covered by its design.

### Negative

- For the Claude reviewer, later pushes to a reviewed PR inherit the first
  review's green. Re-reviewing every push is the plugin's call, not the
  workflow's; ADR-0030's Codex and ADR-0032's opencode do re-review each
  push, so a PR still gets two fresh reads per push.
- One more `gh api` step per run (three paginated reads, seconds).
- A PR that edits `claude-code-review.yml` shows a red `claude-review`
  by design: the action will not review it, and the step says why. The
  check is advisory (ADR-0031), so the PR merges on the other two
  reviewers; the PR that lands this ADR is the first example.

### Neutral

- Draft PRs stop producing a green `claude-review` check they never
  earned; the check appears once the PR is marked ready.

## Alternatives considered

### Alternative 1: Tell the agent in its prompt to always post

Rejected as the only measure: an instruction is not a guarantee, and the
#158 run had the instruction. Prompts keep it; the step enforces it.

### Alternative 2: Count only comments posted since the run started, as for opencode

Rejected for this reviewer: it would fail every run after the plugin
finds its own general comment on the PR and stops, which is its design.
The whole-PR count is the honest guarantee the plugin allows.

### Alternative 3: Make the reviewers required checks and rely on that

Rejected. ADR-0008 and ADR-0031 keep automated review advisory, and a
required check that goes green without a review is the problem, not the
solution.

## Links

- Implementation: `.github/workflows/claude-code-review.yml` (job gate and
  "Require proof that the review was posted"); `.github/workflows/opencode.yml`
  (ADR-0032); `.github/workflows/codex.yml` (`post` job, ADR-0030).
- Evidence: run 35789120850 on [#158](https://github.com/gonzafg2/quantumssh/pull/158)
  (green, no report, agent waiting for subagents); the draft and
  already-reviewed cases on [#155](https://github.com/gonzafg2/quantumssh/pull/155)
  and [#157](https://github.com/gonzafg2/quantumssh/pull/157).
- Related ADRs: [ADR-0025](0025-opencode-second-automated-reviewer.md),
  [ADR-0030](0030-codex-third-automated-reviewer.md),
  [ADR-0032](0032-opencode-reviewer-provider-model-variable-and-proof-of-review.md).
