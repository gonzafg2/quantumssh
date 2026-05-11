# ADR 0011: Implement workspace-empty CI guards with Python `tomllib`

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0009](0009-workspace-no-members-during-phase-0.md), `.github/workflows/{ci,audit,deny}.yml`

## Context

[ADR-0009](0009-workspace-no-members-during-phase-0.md) commits to a
virtual workspace with no member crates during Phase 0. The
consequence is that several Cargo subcommands (`cargo check`,
`cargo fmt`, `cargo clippy`, `cargo build`, `cargo-deny`,
`cargo-audit`) refuse to operate on an empty manifest.

The three CI workflows (`ci.yml`, `audit.yml`, `deny.yml`) need a
guard predicate that returns true while the workspace is empty and
false once a member crate exists. The predicate must:

- Be available on GitHub-hosted runners (Linux and macOS) without
  installation steps.
- Parse `Cargo.toml` correctly, not via fragile regex.
- Be readable in the workflow YAML — a future maintainer should be
  able to tell what the guard does without context.
- Disappear from the workflows automatically when the workspace has
  members, without requiring a workflow edit.

## Decision

We will implement the workspace-empty guard as a short Python script
using the standard-library `tomllib` module. The script reads
`Cargo.toml`, counts entries in `workspace.members`, and emits the
count to `GITHUB_OUTPUT`. Each cargo step is gated by the count being
non-zero.

The implementation lives inline in each of the three workflow files
(roughly five lines per workflow).

## Consequences

### Positive

- Zero install step: Python 3.11+ is preinstalled on all
  GitHub-hosted runners, and `tomllib` is part of the standard
  library from 3.11.
- The predicate is an exact-semantic read of `workspace.members`, not
  a regex over the file's text.
- The guard self-disables when the first crate lands: as soon as
  `workspace.members` has any entry, the predicate returns non-zero
  and the cargo steps run normally. No workflow edit is required at
  the Phase 0 → Phase 1 transition.
- The four-line Python script reads almost as plainly as English; a
  contributor unfamiliar with the project can understand it in
  seconds.

### Negative

- Adds a small dependency on the GitHub-hosted-runners image. If the
  project ever migrates to self-hosted runners or to a different CI
  provider, the runners must have Python 3.11+ available. Mitigation:
  the predicate is small enough to port to any TOML-aware tool.
- A reader expecting "all CI logic in shell" may be surprised to see
  Python. Mitigation: the inline comments in each workflow file
  explain the choice.

### Neutral

- The same predicate runs locally (the comment in each workflow
  includes the one-liner); the maintainer can verify locally what
  CI will do.

## Alternatives considered

### Alternative 1: Bash regex over `Cargo.toml`

`grep -c '^\s*"' Cargo.toml` or similar. Rejected because regex over
TOML is fragile: a comment containing the right pattern, a member
list using inline arrays vs. block arrays, or a future TOML feature
could fool the predicate silently.

### Alternative 2: Install `jq` and `tomlq` (yq-flavour for TOML)

Would give a proper TOML parser. Rejected because it adds an install
step to every CI run and brings in a dependency whose maintenance
posture (`yq` from a third party) the project has not audited.

### Alternative 3: Install `taplo` (a Rust TOML toolchain)

Same install-step cost as `tomlq`. Rejected for the same reason, plus
the irony of installing a Rust tool to work around the fact that
Cargo cannot be invoked yet.

### Alternative 4: Always run the cargo steps and accept the failures

Would let the CI workflow's `continue-on-error` carry the empty
state. Rejected because it makes the CI output noisy (failures are
expected) and trains readers to ignore failed steps, which is the
opposite of the discipline the project intends to cultivate.

## Links

- Workflows containing the predicate:
  `.github/workflows/ci.yml`,
  `.github/workflows/audit.yml`,
  `.github/workflows/deny.yml`
- Python `tomllib` standard-library documentation
