# ADR 0032: Run the opencode reviewer through OpenCode Go, with the model in a repository variable and proof of review

- **Status:** Proposed
- **Date:** 2026-09-22 (drafted; becomes the acceptance date on merge)
- **Deciders:** Project lead
- **Related:** Supersedes, in [ADR-0025](0025-opencode-second-automated-reviewer.md) §Decision, the opening sentence (provider DeepSeek, model V4 Pro), the permissions bullet (`pull-requests: write`) and the "sent to DeepSeek" clause of the `No share` bullet; adds a proof-of-review requirement ADR-0025 does not have. The trigger/author-gate, SHA-pin, `share: false` and prompt bullets of ADR-0025 stand. [ADR-0030](0030-codex-third-automated-reviewer.md) (Codex) and [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md) (reviewers stay advisory) are unchanged. Trust-base framing: [`docs/threat-model.md`](../threat-model.md) §5.5.2.a. Implementation: `.github/workflows/opencode.yml` (lands in the same PR, as ADR-0025 and ADR-0030 did).

## Context

[ADR-0025](0025-opencode-second-automated-reviewer.md) added opencode as
the second automated reviewer with a fixed provider and model: DeepSeek's
direct API, `deepseek/deepseek-v4-pro`, written into the workflow. Three
things have changed since 2026-06-13.

1. **A model id on a vendor's direct API is a promise the vendor can
   revoke.** `deepseek-v4-flash` and `deepseek-v4-flash-vision-exp` are
   retired and their requests are served by DeepSeek V4.1 Flash
   (pricing page, note 1). The changelog entry of 2026-09-10 that
   released V4.1 Flash scheduled `deepseek-v4-pro` — the id ADR-0025
   fixed — for the same routing from 2026-09-14, and now records the
   reversal ("we have decided to continue providing API services for
   DeepSeek V4 Pro after September 14, 2026"). The reviewer kept running
   on V4 Pro; nothing in the repository would have said so either way.
2. **A green check has not meant a review.** The workflow passed when the
   action exited 0, whether or not a comment was posted. On 2026-09-22
   the Claude reviewer showed the failure mode on PR #155: two green runs,
   no report (the plugin skips draft PRs by design). Nothing in the
   opencode job would have caught the same thing.
3. **OpenCode Go** ([opencode.ai/docs/go](https://opencode.ai/docs/go/))
   is a fixed-price subscription by the action's own vendor (Anomaly Co.)
   that fronts several open-weight model families — DeepSeek, MiMo, Qwen,
   GLM, Kimi and others — behind one credential, with a per-model table
   of training use and data retention (the DeepSeek entries: not used for
   training, zero retention, agreement renewed monthly). Its provider id
   in opencode is `opencode-go`. It is also a new party in the path: the
   diff passes through Anomaly's proxy before the downstream provider,
   and Anomaly's own privacy policy is broader than the per-provider
   table ([anomalyco/opencode#35102](https://github.com/anomalyco/opencode/issues/35102)).

The repository already holds the credentials: the `OPENCODE_GO_API_KEY`
and `DEEPSEEK_API_KEY` secrets and the `OPENCODE_MODEL` variable.

## Decision

We will keep opencode as the second reviewer under ADR-0025 and change
how its provider, model and outcome are handled:

- **Provider: OpenCode Go (`opencode-go/<model>`)**, with DeepSeek's
  direct API (`deepseek/<model>`) retained as the fallback provider. The
  workflow supports exactly these two: it derives the provider from the
  model string, fails closed on any other value, and fails closed when
  the provider's secret is missing, naming the missing item and the
  command that adds it. Free tiers are refused by construction — the
  `opencode` free models train on what they receive, and `opencode` is
  not a supported provider. Adding or removing a provider is an ADR
  change; it is where the trust base moves. Within `opencode-go`, the
  boundary is Go's own per-model table: a model whose row reads "not
  used" for training and zero-day retention may be selected by variable
  alone, whatever company serves it behind Go; a model with training use
  or non-zero retention (the "Contributor" entries, for instance) is a
  trust-base change and needs an ADR.
- **The model is the repository variable `OPENCODE_MODEL`**, of the form
  `<provider>/<model>`, with no default in the workflow: a missing
  variable fails the job rather than reviewing on a model nobody chose.
  Changing the model is `gh variable set`, not a pull request; the model
  used is written to every run's job summary, so a verdict can always be
  matched to the model that wrote it. This is the opposite of ADR-0030's
  dated pin in the workflow file for Codex, and deliberately so: the
  Codex pin changes rarely, while this reviewer's vendor re-pointed two
  model ids and announced, then reversed, a third within one month.
- **Proof of review.** After the action succeeds, the job counts the
  comments `opencode-agent[bot]` posted on the PR since the run started
  (general and inline) and fails if there are none. A green `opencode`
  check now means a report was published.
- **Permissions drop to read.** `pull-requests: write` in ADR-0025 was
  recorded as required for posting; it is not — the App token the action
  obtains through OIDC posts the review. The job keeps `contents: read`,
  `pull-requests: read`, `issues: read` and `id-token: write`. The
  workflow token is passed to the agent read-only, for the
  REVIEW-FORMAT iteration check and the commit-verification lookup its
  prompt asks for (Codex, under ADR-0030, holds no token at all).
- **No hangs, no runaway cost.** opencode's default for a path outside
  the checkout is `ask`, which on a runner waits until the timeout; the
  workflow supplies a permission config that allows reading `/etc` (so
  the agent can check what the runner ships when it reviews CI changes)
  and denies everything else outside the repository. The config travels
  as an environment variable, not as a committed `opencode.json`, so it
  does not change the permissions of anyone running opencode locally.
  The job has a 30-minute ceiling (the same as the Codex job; a review
  with V4.1 Flash through Go and the fan-out prompt takes seven to ten
  minutes, against under two with V4 Pro on the direct API), and a new push
  cancels the running review of the same PR without a comment-triggered
  run being able to cancel the one that is publishing.
- **Same-repository heads only.** The action checks out the PR head
  itself — a fork head included — while the provider secret and the
  OIDC token are in the job. As ADR-0030 does for Codex, the job skips a
  `pull_request` whose head lives in a fork, and on both paths a step
  reads the PR from the API and refuses a fork head before any secret is
  exposed. ADR-0030's remark that the `/oc` path "never checks out the
  PR head" was true of `actions/checkout` only; this closes the gap it
  left.
- **Everything else in ADR-0025 stands:** the triggers and author gate,
  the `/oc` on-demand path, the commit-SHA pin, `share: false` (the
  diffs now go to the provider `OPENCODE_MODEL` names, not to DeepSeek
  as that bullet says), the project prompt and the
  `.github/REVIEW-FORMAT.md` contract.

No RFC, on ADR-0025's and ADR-0030's reasoning: the project already
sends the diffs of a public repository to three external inference APIs.
The new element is the intermediary, and it is accepted on the strength
of the published per-model zero-retention / no-training table and the
fact that everything sent is public. If that table changes for the model
in use, the fallback is one `gh variable set` away.

## Consequences

### Positive

- The model actually reviewing is recorded per run and can be changed in
  minutes when a vendor re-points an id or a better open-weight model
  appears; the repository no longer claims a model it is not using.
- A green check is evidence of a review, not of an exit code.
- Cost is a fixed monthly subscription with a per-model quota instead of
  per-token billing; a runaway review is bounded by the timeout.
- Least privilege: the only write in the job is the App's, scoped by the
  App's own installation.

### Negative

- A fourth party (Anomaly Co.) sees the diffs. Mitigated as above; not
  eliminated. Its policy is theirs to change.
- The reviewer is a Flash-class model. Its verdicts, not the check,
  are what to watch: generic findings or missing `path:line` anchors are
  the signal to move `OPENCODE_MODEL` to a Pro-class entry on Go.
- The pinned action SHA pins a thin composite: at run time it installs
  the opencode CLI from upstream's latest release (`curl … | bash`), so
  the code that configures git, talks to the provider and posts the
  comment is not fixed by the pin. ADR-0025 already accepted this
  action; this ADR records the shape of the pin honestly rather than
  changing it.
- A change of provider set, unlike a change of model, needs an ADR.

### Neutral

- Reviews still appear as `opencode-agent[bot]`; the other reviewers'
  iteration check is unaffected.
- The `deepseek` fallback keeps the direct-API path from ADR-0025
  available without a workflow change.

## Alternatives considered

### Alternative 1: Keep DeepSeek's direct API and update the model id

Set `deepseek/deepseek-flash` and leave the rest. Rejected because it
repeats the failure: the id is still the vendor's to re-point, the model
would still be fixed in an ADR, and it adds no proof of review.

### Alternative 2: Pin the model in the workflow with a dated comment, as ADR-0030 does for Codex

Rejected for this reviewer only. Every model change would be a PR
through three automated reviewers for a one-line edit, and the record of
which model reviewed a given PR would live in git history instead of in
the run. ADR-0030's pin stands for Codex, whose vendor rotates models
rarely.

### Alternative 3: OpenCode Go's free models or the free `opencode` provider

Rejected: their published terms allow training on submitted prompts
during the free period. The validation step refuses the provider.

### Alternative 4: Fail the job on a missing comment only as a warning

Rejected. A warning on a green check is exactly the condition this ADR
fixes — nobody reads it.

## Links

- Implementation: `.github/workflows/opencode.yml`; repository variable
  `OPENCODE_MODEL`; secrets `OPENCODE_GO_API_KEY`, `DEEPSEEK_API_KEY`.
- OpenCode Go: <https://opencode.ai/docs/go/> (per-model training and
  retention table); DeepSeek API changelog
  (<https://api-docs.deepseek.com/updates/>, entry of 2026-09-10) and
  pricing page (<https://api-docs.deepseek.com/quick_start/pricing>,
  note 1).
- Related ADRs: [ADR-0025](0025-opencode-second-automated-reviewer.md)
  (amended), [ADR-0030](0030-codex-third-automated-reviewer.md),
  [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md).
