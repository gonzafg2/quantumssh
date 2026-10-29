# ADR 0045: Switch opencode's automatic review with a repository variable, and keep `/oc` on demand

- **Status:** Accepted
- **Date:** 2026-10-28 (accepted with the implementing PR [#217](https://github.com/gonzafg2/quantumssh/pull/217))
- **Deciders:** Project lead
- **Related:** Supersedes, in [ADR-0025](0025-opencode-second-automated-reviewer.md) §Decision, the "Triggered on every PR" part of the trigger bullet. The `/oc` and `/opencode` comment trigger, the author gate and every other bullet stand, as amended by [ADR-0032](0032-opencode-reviewer-provider-model-variable-and-proof-of-review.md). It follows ADR-0032's pattern of keeping an operational choice in a repository variable.

## Context

ADR-0025 runs opencode on every pull request from an authorised author
(`opened`, `synchronize`, `reopened`, `ready_for_review`), and on `/oc` or
`/opencode` comments. Under ADR-0032 the model sits in the
`OPENCODE_MODEL` variable, and the job fails unless a review is posted.

Runs began failing with `APIError: Insufficient Balance` on 2026-10-13.
The last successful review was on 2026-10-17, and every run since has
failed. The variable points at DeepSeek's direct, metered API
(`deepseek/deepseek-flash`), and the account has run out of credit. Every human PR therefore carries a red `opencode` check
and an error comment on each push. The check is not required, but the
noise hides real failures and costs a run per push.

The project lead wants opencode **kept, but not run automatically**:
reviews come from Claude and Codex, and opencode runs only when someone
asks for it. ADR-0025 fixes the automatic trigger in the decision itself,
so turning it off is a change to an accepted decision.

## Decision

1. **The automatic path runs only when the repository variable
   `OPENCODE_AUTO_REVIEW` is `true`.** The `pull_request` branch of the
   job's `if` gains `vars.OPENCODE_AUTO_REVIEW == 'true'`. Unset or any
   other value means off. On a pull request the job is then skipped:
   the check shows as skipped, not failed, and nothing is posted.
2. **The comment path is unchanged.** `/oc` and `/opencode` from an
   authorised author on a pull request still run a review, whatever the
   variable says. It is the on-demand path, and running it is a choice to
   spend a run.
3. **The variable starts unset, so automatic review is off.** Turning
   it back on is `gh variable set OPENCODE_AUTO_REVIEW --body true`, not
   a pull request, as with `OPENCODE_MODEL`.
4. **Everything else in ADR-0025 and ADR-0032 stands:** the author gate,
   the fork refusal, the pinned action, the permissions, the model
   variable and its validation, and the proof-of-review step. When
   opencode does run, a green check still means a review was posted.

## Consequences

### Positive

- Human PRs stop carrying a red `opencode` check and an error comment on
  every push while the provider has no credit.
- opencode stays one comment away for a second opinion, and one
  `gh variable set` away from automatic again, with no workflow edit.
- The switch follows ADR-0032's model variable, so the reviewer's two
  operational knobs (whether it runs, and on which model) live in the
  same place.

### Negative

- With the variable unset, a PR gets no opencode review unless someone
  asks for one. The automatic diversity ADR-0025 sought now rests on
  Claude and Codex alone.
- The variable is repository state, not code: `gh variable list` shows
  whether automatic review is on, and the workflow file does not.

### Neutral

- A `/oc` run with no provider credit still fails with the same
  `Insufficient Balance` error. Fixing the provider (credit, or moving
  `OPENCODE_MODEL` to `opencode-go/…`) is separate from this switch.

## Alternatives considered

- **`gh workflow disable opencode.yml`.** It needs no file change, but
  it also disables `/oc`, and the repository would no longer show why the
  reviewer is off. Rejected: the project lead wants it available on
  demand.
- **Remove the `pull_request` trigger outright.** Rejected: turning
  automatic review back on would take another pull request and another
  ADR, where a variable takes one command.
- **Remove opencode.** Rejected by the project lead: keep the reviewer
  and turn off only its automatic runs.

## Links

- Implementation: `.github/workflows/opencode.yml` (the job `if`).
- Superseded clause: [ADR-0025](0025-opencode-second-automated-reviewer.md)
  §Decision, "Triggered on every PR".
- Variable pattern: [ADR-0032](0032-opencode-reviewer-provider-model-variable-and-proof-of-review.md).
