# ADR 0025: Add opencode as a second automated PR reviewer

- **Status:** Accepted
- **Date:** 2026-06-13
- **Deciders:** Project lead
- **Related:** `.github/workflows/opencode.yml` (implements this decision); `.github/workflows/claude-code-review.yml` (existing reviewer this decision mirrors)

## Context

QuantumSSH already runs an automated PR reviewer via `anthropics/claude-code-action@v1` (Claude Code Review, `.github/workflows/claude-code-review.yml`). That reviewer sends PR diffs to Anthropic's inference API and posts findings as PR comments.

A second reviewer using a different model provider (`anomalyco/opencode` with DeepSeek V4 Pro) increases review diversity — different models catch different classes of issues. Both reviewers receive the same project-specific criteria (CLAUDE.md, the five MANIFIESTO commitments, the threat model) and apply the same security lens.

The question is whether this is a sufficiently material change to require an RFC (14-day comment period, CLAUDE.md governance lane). This ADR records the decision that it is not — and documents the operational choice to add a second reviewer — so the decision is explicit and linked from the PR that implements it.

## Decision

We will add `anomalyco/opencode/github` (DeepSeek V4 Pro) as a second automated PR reviewer, mirroring the existing Claude reviewer posture:

- **Triggered on every PR** (`opened`, `synchronize`, `reopened`, `ready_for_review`) **from OWNER/MEMBER/COLLABORATOR** only, and on `/oc` or `/opencode` comments on PRs from the same set of authorised users.
- **Pinned to a full commit SHA** (not `@latest`), same supply-chain standard as any third-party action with write permissions.
- **Permissions**: `contents: read`, `pull-requests: write`, `issues: write`. No `id-token`, no `contents: write`.
- **No `share`**: PR diffs are sent to DeepSeek for inference only; no external share link is published.
- **Project-specific prompt**: the same MANIFIESTO commitments, threat-model rules, and CLAUDE.md criteria that the Claude reviewer receives.

No RFC is required because this is an incremental operational change that mirrors an existing reviewer with the same trust model and security posture. It does not change the server's cryptographic surface, protocol surface, or dependency graph — it only adds a second CI lint pass.

## Consequences

### Positive

- Two reviewers with different models increase the probability of catching bugs and security issues before merge.
- The operational decision is now documented and linked, so future governance questions about AI reviewers can reference this ADR rather than re-litigate.

### Negative

- Doubles the per-PR inference API cost (DeepSeek in addition to Anthropic). Controlled by the `author_association` gate.
- Introduces a trust relationship with DeepSeek's API (PR diffs are transmitted to a second external service). Mitigated by: the Claude reviewer already does this with Anthropic; the action is pinned to a commit SHA; permissions are minimal; `share` is disabled.

### Neutral

- The opencode reviewer may flag issues the Claude reviewer does not, and vice versa. This creates a second "voice" on PRs that contributors need to evaluate — same as having two human reviewers with different perspectives.

## Alternatives considered

### Alternative 1: Require an RFC per CLAUDE.md governance

CLAUDE.md classifies "a dependency that materially expands the trust base" as requiring an RFC. Adding a second AI reviewer is a trust-base expansion (a new external service receives PR content), but it is *incremental* to the existing Anthropic reviewer — the project already sends PR diffs to an external inference API. Rejected because: an RFC with a 14-day comment period would delay a CI-only operational change that mirrors an existing, already-accepted reviewer with identical security constraints.

### Alternative 2: Reject the second reviewer entirely

Keep only the Claude reviewer. Simpler, cheaper, fewer trust relationships. Rejected because: the diversity benefit (different model, different catch profile) outweighs the incremental cost and trust expansion, given the existing Anthropic reviewer sets the precedent.

### Alternative 3: Use a local/open-weight reviewer (e.g. ollama + local model)

No external API, no trust expansion. Rejected as premature: Phase 1 has no infrastructure to host GPU runners, and a local reviewer would require CI self-hosted runners, which are out of scope.

## Links

- Implementation: `.github/workflows/opencode.yml`
- PR: [#66](https://github.com/gonzafg2/quantumssh/pull/66)
- Existing reviewer: `.github/workflows/claude-code-review.yml`
- Governance: [CLAUDE.md § RFC vs ADR vs plain PR](../../CLAUDE.md)
