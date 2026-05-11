# ADR 0011: Gate CI workflows on workspace state with two narrow predicates

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0009](0009-workspace-no-members-during-phase-0.md), `.github/workflows/{ci,audit,deny}.yml`

> **Post-acceptance errata** (per [ADR-0015](0015-permit-annotated-errata-in-adrs.md)):
>
> - **2026-05-11** ([PR #13](https://github.com/gonzafg2/quantumssh/pull/13)):
>   Restructured the Context and Decision sections to describe the
>   two-predicate split accurately. The original wording claimed all
>   three CI workflows (`ci.yml`, `audit.yml`, `deny.yml`) skipped
>   their cargo invocations using a single shared `tomllib`/
>   `workspace.members` predicate. In reality, `audit.yml` is gated on
>   `Cargo.lock` presence (matching what `cargo-audit` actually needs),
>   while `ci.yml` and `deny.yml` are gated on the `tomllib` member
>   count. The ADR title was also adjusted from "Implement
>   workspace-empty CI guards with Python `tomllib`" to "Gate CI
>   workflows on workspace state with two narrow predicates" to match
>   the corrected scope, and an additional Alternative ("use the same
>   predicate everywhere") was added with its rejection rationale.
> - **2026-05-11** (this PR): Refined the description of when
>   `Cargo.lock` appears at the repo root. The previous wording ("the
>   lockfile only appears once a member crate has been built") was
>   imprecise: the workflow predicate checks for `Cargo.lock` in the
>   repository checkout, so the condition resolves only when a
>   lockfile-producing crate (typically a binary or application
>   crate) is added **and** its `Cargo.lock` is committed at the repo
>   root. The new wording makes the commit step explicit.
> - **2026-05-11** (this PR): The ADR file was renamed from
>   `0011-ci-guards-python-tomllib.md` to
>   `0011-ci-guards-workspace-state.md` so the filename slug reflects
>   the corrected scope (the decision is about workspace-state guards
>   in general, not specifically about the Python `tomllib`
>   predicate). All inbound links in the repository were updated in
>   the same commit.

## Context

[ADR-0009](0009-workspace-no-members-during-phase-0.md) commits to a
virtual workspace with no member crates during Phase 0. That creates
**two distinct** CI gating conditions, not one:

1. **No workspace members.** `cargo fmt`, `cargo clippy`, `cargo build`,
   `cargo test`, and `cargo-deny` all refuse to operate on a virtual
   manifest with `members = []`. This blocks `ci.yml` and `deny.yml`.
2. **No `Cargo.lock` in the repo.** `cargo-audit` scans a lockfile
   rather than the manifest. `Cargo.lock` appears at the repository
   root only when a lockfile-producing crate (typically a binary or
   application crate, per `cargo` convention) is added **and** the
   generated lockfile is committed alongside it. This blocks
   `audit.yml`.

The two conditions resolve on different events: the first lifts as
soon as a member is added to `Cargo.toml`; the second lifts when the
first crate that commits `Cargo.lock` to the repository root lands.
Both lifts happen during Phase 1, but not necessarily simultaneously
or in the same commit.

Each gating predicate must:

- Be available on GitHub-hosted runners (Linux and macOS) without
  installation steps.
- Read the relevant condition accurately, not via fragile regex.
- Be legible in the workflow YAML — a future maintainer should be
  able to tell what the guard does without context.
- Disappear from the workflows automatically when its condition lifts,
  without requiring a workflow edit.

## Decision

We will implement two narrow predicates rather than forcing a single
mechanism on both conditions:

- **`ci.yml` and `deny.yml`** — a four-line Python script using the
  standard-library `tomllib` module reads `Cargo.toml`, counts entries
  in `workspace.members`, and emits the count to `GITHUB_OUTPUT`. Each
  cargo step is gated by `steps.members.outputs.count != '0'`.

- **`audit.yml`** — a one-line bash test (`if [ -f Cargo.lock ]`)
  emits `present=1` or `present=0` to `GITHUB_OUTPUT`. Each cargo-audit
  step is gated by `steps.lockfile.outputs.present == '1'`.

Both predicates self-disable when their respective condition resolves.
Each lives inline in its workflow (roughly five lines).

## Consequences

### Positive

- Each predicate matches the actual failure mode of the cargo command
  it gates: members-count for the manifest-level operations,
  lockfile-presence for `cargo-audit`. A single shared predicate would
  have been a misleading abstraction.
- Zero install step on either predicate: Python 3.11+ and POSIX bash
  are both preinstalled on GitHub-hosted runners. `tomllib` is part of
  the Python standard library from 3.11.
- The Python predicate is an exact-semantic read of
  `workspace.members`, not a regex over the file's text.
- Each guard self-disables when its condition resolves: as soon as
  `workspace.members` has an entry, `ci.yml` and `deny.yml` run
  normally; as soon as `Cargo.lock` exists, `audit.yml` runs normally.
  No workflow edit is required at the Phase 0 → Phase 1 transition.
- Each predicate reads almost as plainly as English; a contributor
  unfamiliar with the project can understand them in seconds.

### Negative

- The CI surface now contains two small idioms instead of one. A
  reader expecting workflow uniformity may be surprised. Mitigation:
  the inline comments in each workflow file explain the choice, and
  this ADR is the canonical reference.
- The Python predicate adds a small dependency on the GitHub-hosted-
  runners image. If the project ever migrates to self-hosted runners
  or to a different CI provider, the runners must have Python 3.11+
  available. Mitigation: the predicate is small enough to port to any
  TOML-aware tool.

### Neutral

- Each predicate runs locally as well (the comment in the workflow
  includes the one-liner); the maintainer can verify locally what CI
  will do.
- A future Phase 1 design that always commits `Cargo.lock` from the
  first crate would collapse the two conditions back into one. This
  ADR does not pre-commit to that path.

## Alternatives considered

### Alternative 1: Use the Python `tomllib` predicate everywhere, including `audit.yml`

Would yield a single uniform predicate across all three workflows.
Rejected because it would gate `cargo-audit` on the wrong condition.
`cargo-audit` cares about whether a `Cargo.lock` exists to scan, not
whether the workspace has members. A member crate can exist for some
time before `Cargo.lock` is produced (e.g., library-only crates that
have not been built yet), and during that window a uniform
`members > 0` predicate would attempt `cargo-audit` and fail. The
two-predicate split is more accurate at small additional reading cost.

### Alternative 2: Bash regex over `Cargo.toml`

`grep -c '^\s*"' Cargo.toml` or similar. Rejected because regex over
TOML is fragile: a comment containing the right pattern, a member
list using inline arrays vs. block arrays, or a future TOML feature
could fool the predicate silently.

### Alternative 3: Install `jq` and `tomlq` (yq-flavour for TOML)

Would give a proper TOML parser. Rejected because it adds an install
step to every CI run and brings in a dependency whose maintenance
posture (`yq` from a third party) the project has not audited.

### Alternative 4: Install `taplo` (a Rust TOML toolchain)

Same install-step cost as `tomlq`. Rejected for the same reason, plus
the irony of installing a Rust tool to work around the fact that
Cargo cannot be invoked yet.

### Alternative 5: Always run the cargo steps and accept the failures

Would let the CI workflow's `continue-on-error` carry the empty
state. Rejected because it makes the CI output noisy (failures are
expected) and trains readers to ignore failed steps, which is the
opposite of the discipline the project intends to cultivate.

## Links

- Workflows with the `workspace.members` predicate:
  `.github/workflows/ci.yml`, `.github/workflows/deny.yml`
- Workflow with the `Cargo.lock` predicate: `.github/workflows/audit.yml`
- Python `tomllib` standard-library documentation
