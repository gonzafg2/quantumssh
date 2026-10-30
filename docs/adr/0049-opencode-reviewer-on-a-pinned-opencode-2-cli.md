# ADR 0049: Run the opencode reviewer on a pinned OpenCode 2 CLI, and post its report from the workflow

- **Status:** Accepted
- **Date:** 2026-10-30 (accepted with the implementing PR [#235](https://github.com/gonzafg2/quantumssh/pull/235))
- **Deciders:** Project lead
- **Related:** Supersedes, in [ADR-0025](0025-opencode-second-automated-reviewer.md) §Decision, the reviewer's integration (`anomalyco/opencode/github`, posting as `opencode-agent[bot]`) and its "Pinned to a full commit SHA" bullet. Supersedes, in [ADR-0032](0032-opencode-reviewer-provider-model-variable-and-proof-of-review.md) §Decision, the proof-of-review and permissions bullets, and the sentence of its same-repository bullet that says the action checks out the PR head. Supersedes the opencode bullet of [ADR-0033](0033-proof-of-review-for-every-automated-reviewer.md) §Decision. [ADR-0045](0045-opencode-automatic-review-behind-a-repository-variable.md) (the automatic-review switch) and everything else in those ADRs stand. Closes [#166](https://github.com/gonzafg2/quantumssh/issues/166). Implementation: `.github/workflows/opencode.yml` (lands in the same PR, as ADR-0045 did).

## Context

[#166](https://github.com/gonzafg2/quantumssh/issues/166) records two defects
of the opencode workflow. The pinned composite action looks up the latest
release with an anonymous `api.github.com` call, so a rate-limited runner
fails the job before the review starts. The action then installs whatever
CLI `https://opencode.ai/install` serves, so the SHA pin fixes the wrapper
and not the code that reviews. ADR-0032 recorded the second defect as an
accepted consequence.

Upstream has since removed the action. anomalyco/opencode#59032 deleted
it on 2026-10-25, and the v2.2.0 release notes say "The OpenCode GitHub
Action is no longer published. Remove it from your workflows." The
pinned commit still resolves, but the rest of the integration is going
too:

- `opencode github run`, which the action calls, exists only in OpenCode
  1. The OpenCode 2 CLI has no `github` command. The installer still
  serves OpenCode 1 (1.19.5 on 2026-10-30), because the `opencode-ai` npm
  package holds only OpenCode 1. That stops when it moves to 2.
- The token that lets the reviewer post as `opencode-agent[bot]` comes
  from an OIDC exchange with `api.opencode.ai`, inside that same v1
  command. The App's installation endpoint on that host already returns
  404 (anomalyco/opencode#59008).

The red runs since 2026-10-17 are a separate cause. DeepSeek's direct API
answers `402 Insufficient Balance` for the key in `DEEPSEEK_API_KEY`
(ADR-0045, Neutral). On 2026-10-30 `OPENCODE_MODEL` moved to
`opencode-go/deepseek-v4.1-flash`. That is a variable change under
ADR-0032 and needs no ADR.

OpenCode 2.2.3 was checked in a container before this decision:

- it reads `OPENCODE_CONFIG_CONTENT`, including the `external_directory`
  rules and the `opencode-go` key;
- `opencode run` exits 1 when the provider refuses the request;
- in a non-interactive run it rejects a permission request instead of
  waiting for an answer;
- `--format json` separates the final report from the text the agent
  writes between tool calls.

## Decision

1. **The CLI is OpenCode 2, pinned by version and digest.** The workflow
   downloads the release asset `opencode-linux-x64.tar.gz` of a fixed
   version from `github.com/anomalyco/opencode/releases/download/`, and
   checks it against the SHA-256 that GitHub publishes for the asset.
   Both values sit in the workflow, so a bump is a pull request. No
   installer script runs, and no `api.github.com` call happens before the
   review. This closes both halves of #166.
2. **The review runs `opencode run --standalone --format json`.** It
   takes the project prompt, which now starts with the PR number and the
   `gh` commands that read the PR. The job checks out the head commit
   that the fork-refusal step read from the API, so a push in between
   cannot swap the code under review. The permission configuration of
   ADR-0032 still travels in `OPENCODE_CONFIG_CONTENT`. The run has no
   `--auto`, so any request the configuration does not grant is rejected.
3. **Two jobs, split on privilege, as ADR-0030's Codex workflow was.**
   - `review` holds `contents: read`, `pull-requests: read` and
     `issues: read`, the provider secret and the model. It extracts the
     last text part that carries `## PR Review:`, and hands the comment
     to the next job as an artifact.
   - `post` holds `pull-requests: write`, has no checkout, no secret and
     no model, and posts the comment with `gh pr comment`.

   `id-token: write` is dropped.
4. **Reviews appear as `github-actions[bot]`.** A footer names the
   OpenCode version and the model, and links the run, as the action's
   footer did.
5. **Proof of review by construction.** `review` fails when opencode ends
   without a `## PR Review:` report, and `post` fails when the comment
   is not created. A green check therefore means the comment is on the PR.
   This is how ADR-0033 already treats ADR-0030's Codex workflow. The
   comment-count step goes.
6. **Unchanged:**
   - the triggers, the author gate and the ADR-0045 switch;
   - the fork refusal on both paths, the model variable, its validation
     and the two providers, and the 30-minute ceiling;
   - the concurrency rules;
   - the prompt and its `.github/REVIEW-FORMAT.md` contract.

   The prompt loses only its commit instructions, because nothing in the
   job can push. It also names the `subagent` tool, OpenCode 2's name for
   what OpenCode 1 called `task`. OpenCode 2's `run` has no share option,
   so ADR-0025's "No share" holds without a flag.

## Consequences

### Positive

- #166 is closed. A rate-limited `api.github.com` no longer fails the
  job, and the binary that reviews is the one this repository names.
- The model never holds a write-capable token. Under OpenCode 1 the CLI
  kept the App token as git's `extraheader` inside the process the agent
  drives. Now only `post`, which runs no model, can write.
- The reviewer no longer depends on the opencode-agent App or on
  `api.opencode.ai`, both of which upstream is retiring.

### Negative

- The comments come from `github-actions[bot]`, a login any workflow can
  post as. The `## PR Review:` heading and the footer identify them.
  `.github/REVIEW-FORMAT.md` reads earlier reviews from any author, so
  its iteration check is unaffected.
- Bumping the CLI is manual: Dependabot does not track a release asset.
  OpenCode 2 releases often (2.2.0 to 2.2.3 in three days), so the pin
  will lag. A lag only matters when a fix is needed.
- `/oc` asks for a review and nothing else. The comment's text does not
  reach the model, and OpenCode 1's reactions on the triggering comment
  are gone.

### Neutral

- The archive, about 120 MB, is downloaded on every run, with no cache.
- The check names become `review` and `post`. Neither is required
  ([ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md)).

## Alternatives considered

- **Keep the action, and re-run on the flake.** Rejected: upstream has
  removed it, its CLI is unpinned, and the CLI it installs goes away
  when the installer moves to OpenCode 2.
- **Pin OpenCode 1.19.5 and call `opencode github run` directly.** That
  would keep `opencode-agent[bot]`. Rejected: it ties the reviewer to
  the line upstream left, and to an App backend that is already being
  taken down.
- **Repeat the OIDC exchange in the workflow to keep the App identity.**
  Rejected for the same backend.
- **Retire opencode.** Rejected by the project lead, who keeps it under
  ADR-0045 and chose on 2026-10-30 to move it to OpenCode 2.

## Links

- Implementation: `.github/workflows/opencode.yml`.
- Issue: [#166](https://github.com/gonzafg2/quantumssh/issues/166).
- Upstream: anomalyco/opencode#59032 (action removed), the
  [v2.2.0 release notes](https://github.com/anomalyco/opencode/releases/tag/v2.2.0),
  anomalyco/opencode#59008 (App installation endpoint 404).
