# ADR 0030: Add Codex as a third automated PR reviewer

- **Status:** Proposed
- **Date:** 2026-09-08 (drafted; becomes the acceptance date on merge)
- **Deciders:** Project lead
- **Related:** Mirrors [ADR-0025](0025-opencode-second-automated-reviewer.md) (second reviewer, the precedent this decision extends); constrained by [ADR-0008](0008-branch-protection-zero-required-reviews.md) (automated reviews are advisory, never a merge gate); follows the commit-SHA pinning discipline of [PR #142](https://github.com/gonzafg2/quantumssh/pull/142); reports under the contract in [`.github/REVIEW-FORMAT.md`](../../.github/REVIEW-FORMAT.md); trust-base framing from [`docs/threat-model.md`](../threat-model.md) §5.5.2.a (upstream dependency compromise) and §3.2.6 (project maintainer compromise, via [RFC-0001](../rfcs/0001-threat-model-actor-project-maintainer-compromise.md)). Implementation: `.github/workflows/codex.yml` (implements this decision; lands in the same PR, as ADR-0025 did).

## Context

QuantumSSH runs two automated PR reviewers, both on every human-authored PR
and both bound to the same report contract (`.github/REVIEW-FORMAT.md`):

- **Claude Code Review** — `anthropics/claude-code-action`, Anthropic
  inference, posts inline comments as `claude[bot]`
  (`.github/workflows/claude-code-review.yml`).
- **opencode** — `anomalyco/opencode/github`, DeepSeek V4 Pro inference,
  posts as `opencode-agent[bot]`, also on demand via `/oc`
  (`.github/workflows/opencode.yml`, [ADR-0025](0025-opencode-second-automated-reviewer.md)).

A third reviewer runs outside this governance: **GitHub Copilot code
review**, requested through the maintainer's account — by hand or via
the account-level automatic setting — rather than through a repository
ruleset (the repository has none). Per GitHub's documentation it reads
`CLAUDE.md` and `AGENTS.md` on its own, but not
`.github/REVIEW-FORMAT.md`, so its reports do not follow the contract,
and no ADR records it. This ADR leaves Copilot as it is; it is mentioned
so the reviewer landscape is stated accurately.

ADR-0025's argument for a second reviewer — different model families
catch different classes of issues — applies unchanged to a third. OpenAI
Codex is the remaining major model family with a first-party code-review
product, and its review guidance is driven by `AGENTS.md`, which this
repository already maintains.

Two integration shapes exist, and they differ in who controls the
configuration:

1. **The Codex cloud GitHub App.** Enabled in OpenAI's Codex settings for
   a connected repository; reviews on `@codex review` or automatically on
   every new PR; posts a native GitHub review scoped to P0/P1 findings;
   `@codex fix` can push commits to the branch when the App has
   permission.
2. **`openai/codex-action` in GitHub Actions.** A pinned workflow step
   that runs `codex exec` on the runner with an API key from repository
   secrets; the workflow supplies the prompt and posts the result itself.

The questions this ADR answers: whether to add a third reviewer, which
shape, and — as in ADR-0025 — whether the change needs an RFC.

## Decision

We will add OpenAI Codex as a third automated PR reviewer, integrated
through `openai/codex-action` (the v1 line, pinned to a full commit SHA),
not through the Codex cloud GitHub App. It follows the shape of the two
existing reviewers, with one deliberate tightening:

- **Triggered on every PR** (`opened`, `synchronize`, `reopened`,
  `ready_for_review`) **from OWNER/MEMBER/COLLABORATOR** only, and on
  demand via a `/codex` comment on a PR from the same set of authors —
  the same two trigger paths as opencode. The slash form is deliberate:
  the Codex cloud App answers any `@codex` mention, so `/codex` cannot
  collide with it. The action's own actor check (write access required;
  `allow-bots` stays at its default `false`) is a second gate behind the
  workflow's `author_association` condition. Dependabot PRs are
  excluded, as for the other two reviewers.
- **Same-repository heads only.** Before anything is checked out, the
  workflow re-reads the PR from the API, re-checks the author's
  association (the comment path gates the commenter, not the PR) and
  refuses a head that lives in a fork — even a collaborator's. Vetting
  and checkout use the same API snapshot, so the SHA cannot move between
  them.
- **Pinned to a full commit SHA**, bumped by Dependabot's
  `github-actions` ecosystem like the other actions and reviewed against
  the pin comment before merge. The Codex CLI the action installs
  (`codex-version`) is pinned too, with a dated comment; Dependabot does
  not track that input, so it is bumped by hand.
- **Permissions, split on privilege.** Two jobs: `review` holds
  `contents: read` and `pull-requests: read` and is the only job that
  checks out PR code; `post` holds `pull-requests: write` and never
  touches a checkout — it downloads the assembled comment as an artifact
  and posts it. No `contents: write` anywhere. No `id-token: write` —
  unlike the other two reviewers, this action authenticates with an API
  key, not OIDC, so the OIDC permission is not needed and is not
  granted.
- **Credential:** an `OPENAI_API_KEY` repository secret, scoped to a
  dedicated OpenAI project with a hard monthly budget.
- **Execution posture (the tightening):** Codex runs without
  credentials of its own and without privilege. The workflow, not the
  model, gathers the review inputs: it checks out the PR and pre-fetches
  the existing PR comments (for the REVIEW-FORMAT step-1 iteration
  check) into the prompt before invoking Codex. The model never holds
  `GITHUB_TOKEN`. The action runs it under `safety-strategy: drop-sudo`
  — sudo, supplementary groups and capabilities removed, `no_new_privs`
  set — with the `:read-only` permission profile: the commands it runs
  can read the checkout but cannot write or reach the network. The API
  key lives in the action's local proxy process and is not exported to
  those commands. Prompt-injection through PR content therefore cannot
  turn into a push, a comment, or a network exfiltration. The residual
  channel is the review text itself, which the workflow posts verbatim:
  the model can print anything it can read — the public checkout, its
  own prompt, and the proxy's memory only if it defeated the same-user
  process isolation that `drop-sudo` leaves in place. The action
  documents `read-only` and `unsafe` as the strategies where that memory
  read is trivial because sudo is kept; neither is used.
  `unprivileged-user` (a separate UID for Codex) is the upgrade path if
  that residual ever matters.
- **Posting:** the separate, deterministic `post` job publishes the
  assembled report as **one** PR comment using its own `GITHUB_TOKEN`.
  The comment therefore appears as `github-actions[bot]`; its header
  identifies it as the Codex review so the other reviewers' iteration
  check can classify it. Inline comments are not required.
- **Prompt:** the same MANIFIESTO commitments, threat-model rules and
  `CLAUDE.md` classification the other reviewers receive, the same
  "absence of evidence in CI is not evidence of absence" rule, and the
  `.github/REVIEW-FORMAT.md` contract.
- **Model:** pinned explicitly in the workflow's `model` input with a
  dated comment, not fixed by this ADR. OpenAI's Codex documentation
  names no single default and rotates the recommended model; the pin is
  an operational detail, bumped deliberately like the action SHA.
- **Not a merge gate.** ADR-0008 stands: zero required approvals, and the
  Codex job is not added to the required status checks.

No RFC is required, for the reason ADR-0025 gave: the project already
sends the diffs of a public repository to two external inference APIs;
a third provider is an incremental expansion of an established posture,
not a new class of trust-base change. It touches no cryptographic,
protocol, or dependency surface of the server — it adds a third CI
review pass.

## Consequences

### Positive

- Three model families from three providers review every human PR; the
  catch profile widens exactly as ADR-0025 intended.
- Codex applies `AGENTS.md` review guidance natively, so the file the
  repository already maintains does double duty.
- The credential-free execution posture — no GitHub token in the
  model's hands, no network and no writes for its commands, no sudo — is
  stricter than the two existing reviewers on that axis. It is a bar
  they could adopt later; it is not a reason to loosen it here.
- The decision is recorded, so the next "why three reviewers?" question
  points at this ADR instead of being re-litigated.

### Negative

- A third per-PR inference cost. Controlled by the `author_association`
  gate, the action's write-access check, and the project-scoped key
  budget.
- A third external service receives PR content. The content is already
  public; the residual exposure is the API key itself, mitigated by
  scoping and budget, by `drop-sudo`, by the read-only profile, and by
  keeping the key in the proxy process rather than in the commands the
  model runs.
- A new third-party action runs in CI (threat model §5.5.2.a). Mitigated
  by the full-SHA pin, minimal permissions, and Dependabot-driven,
  reviewed bumps.
- The secret is reachable by a same-repository PR that edits this
  workflow: on `pull_request`, the workflow definition comes from the PR
  branch and repository secrets are available to it, so a compromised
  collaborator account (threat model §3.2.6) could rewrite `codex.yml`
  to exfiltrate `OPENAI_API_KEY` before any of its safeguards run. This
  is the same exposure the two existing reviewer secrets already carry;
  the project accepts it while it has a single maintainer (ADR-0008)
  and bounds it with a project-scoped, budgeted, rotatable key. Moving
  the reviewers to `pull_request_target` with the base-branch definition,
  or to an approval-gated environment for their secrets, is a decision
  for all three reviewers at once and belongs in its own ADR.
- No dedicated bot identity: the review posts as `github-actions[bot]`
  rather than a `codex[bot]`, so it is visually less distinct than the
  other two. Accepted; the fixed first line compensates.

### Neutral

- A third "voice" on every PR raises the maintainer's triage cost.
  Same trade-off as ADR-0025: three advisory opinions, one human decision.
- Every place that says "both reviewers" must say three: `CLAUDE.md`
  (contribution conventions), `AGENTS.md` (git workflow),
  `.github/REVIEW-FORMAT.md` (header) and
  `.github/PULL_REQUEST_TEMPLATE.md` (automated reviews). Done in the
  same PR.
- The two existing reviewers have not executed since 2026-07-27 — every
  run since has been skipped because only Dependabot PRs were opened.
  The PR that lands this ADR is the first live exercise of all three at
  once.
- The Codex cloud GitHub App is installed on the maintainer's account
  but has no environment for this repository: it answers an `@codex`
  mention with a set-up prompt and does nothing else. It stays
  unconfigured. Nothing in this ADR prevents revisiting that if the App
  gains repository-controlled, PR-reviewable configuration.

## Alternatives considered

### Alternative 1: The Codex cloud GitHub App

Zero workflow to maintain, native review UI with inline comments,
automatic reviews on open, `AGENTS.md` rules applied out of the box.
Rejected because the configuration lives in OpenAI's Codex settings,
tied to a personal ChatGPT account rather than to a repository secret:
it cannot be pinned, diffed, or reviewed by PR; the report follows
Codex's own P0/P1 format rather than `.github/REVIEW-FORMAT.md`; and the
App holds push permission for `@codex fix` tasks, which this project
does not want an external agent to have — only signed, signed-off
maintainer commits enter `main` (ADR-0008, threat model §3.2.6).

### Alternative 2: Require an RFC per CLAUDE.md governance

Rejected for the reason recorded in ADR-0025: an RFC with a 14-day
comment period would delay a CI-only operational change whose trust
model is a documented instance of the project's existing
external-inference-reviewer posture.

### Alternative 3: Stay at two reviewers

Cheaper, fewer trust relationships. Rejected because the marginal cost
is gated and bounded, and the third model family is the point: a class
of issue that two providers both miss is exactly what a third is for.

### Alternative 4: Replace opencode with Codex instead of adding it

Keeps the count at two. Rejected because provider diversity is the goal,
not the count; ADR-0025 stands and DeepSeek's catch profile is not
superseded by Codex's.

## Links

- Implementation: `.github/workflows/codex.yml`
- PR: [#151](https://github.com/gonzafg2/quantumssh/pull/151)
- Action: <https://github.com/openai/codex-action> (v1 line; `v1.12` at
  the time of writing — the workflow pins the SHA, not the tag)
- Codex code review in GitHub (the App alternative):
  <https://learn.chatgpt.com/docs/third-party/github>
- Custom review rules via `AGENTS.md`:
  <https://developers.openai.com/blog/custom-code-review-rules-for-codex>
- Copilot code review instruction files (for the Context section):
  <https://docs.github.com/en/copilot/how-tos/use-copilot-agents/request-a-code-review/use-code-review>
- Related ADRs: [ADR-0025](0025-opencode-second-automated-reviewer.md),
  [ADR-0008](0008-branch-protection-zero-required-reviews.md)
- Report contract: [`.github/REVIEW-FORMAT.md`](../../.github/REVIEW-FORMAT.md)
- Governance: [CLAUDE.md § RFC vs ADR vs plain PR](../../CLAUDE.md)
