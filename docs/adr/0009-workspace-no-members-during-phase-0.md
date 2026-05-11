# ADR 0009: Ship a virtual workspace with no member crates during Phase 0

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** `Cargo.toml`, [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) (toolchain pinning), [ADR-0011](0011-ci-guards-python-tomllib.md) (CI guards), `docs/infrastructure.md` § "Workspace topology"

## Context

Phase 0 of the roadmap delivers governance, license, CI/CD, and
infrastructure scaffolding. It deliberately does not deliver Rust
code; the first crate lands as part of Phase 1 / Hito 1.

The workspace manifest at the repository root has two main shapes
available:

1. A "real" workspace with at least one member crate from day one.
   This satisfies Cargo's expectations and lets every subcommand
   (`cargo check`, `cargo fmt`, `cargo clippy`, `cargo build`,
   `cargo audit`, `cargo-deny`) operate normally.
2. A virtual workspace with `members = []`. Cargo accepts the
   manifest as well-formed metadata but refuses to perform most
   subcommands until at least one crate exists.

Several structural decisions belong on the workspace manifest before
any crate exists: dependency resolver, language edition, lint profile,
MSRV, centralised dependency versions. Recording these in advance lets
Phase 1 inherit them rather than having to retrofit.

## Decision

We will ship Phase 0 with a virtual workspace (`members = []`) at the
repository root. All workspace-level configuration — resolver,
edition, lints, MSRV, centralised dependency versions — is committed
in the same `Cargo.toml`. CI workflows are guarded so they pass on
the empty workspace; the guards self-disable when the first crate
lands in Phase 1.

## Consequences

### Positive

- The workspace shape decisions ([ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md))
  are committed, reviewable, and immutable from day one.
- Phase 1 starts by adding a crate, not by reshaping the workspace.
- CI/CD that depends on workspace metadata (dependabot, deny.yml,
  audit.yml) is exercised in the empty state, surfacing any
  configuration errors before they can hide behind real code.

### Negative

- Several Cargo subcommands refuse to operate on an empty virtual
  manifest. The CI workflows must guard against this explicitly
  (see [ADR-0011](0011-ci-guards-python-tomllib.md)).
- A reader landing on the repo for the first time may be confused by
  a `Cargo.toml` with no source. Mitigation: the manifest's comments
  describe the situation, and `docs/infrastructure.md` documents the
  decision.

### Neutral

- The same workspace will continue to be valid once Phase 1 adds the
  first member; no Cargo.toml-level restructuring is anticipated.

## Alternatives considered

### Alternative 1: Add a placeholder member crate (e.g., `crates/sentinel/` with an empty `lib.rs`)

Would satisfy Cargo's expectations and let every subcommand work
normally. Rejected because the placeholder serves no purpose other
than to placate Cargo, would need to be deleted (or migrated) when
Phase 1 begins, and would carry a misleading suggestion that the
crate has architectural meaning.

### Alternative 2: Defer the workspace manifest until Phase 1

Would avoid the guard machinery entirely. Rejected because it would
postpone the toolchain and lint decisions until the first crate is
written, which is precisely the moment when those decisions become
hardest to make in isolation.

### Alternative 3: Set up the workspace with members and the first crate from Phase 0 commit zero

Would conflate scaffolding with code. Rejected because Phase 0 is
deliberately a documentation-and-scaffolding phase; mixing in real
code blurs the boundary that the roadmap intentionally draws.

## Links

- Workspace manifest: `Cargo.toml` (this repository)
- Workflow guards: `.github/workflows/{ci,audit,deny}.yml`
- Roadmap (Phase 0 / Phase 1 boundary): `README.md` § "Roadmap"
