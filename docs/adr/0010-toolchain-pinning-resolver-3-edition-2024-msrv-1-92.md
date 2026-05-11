# ADR 0010: Pin workspace to resolver 3, edition 2024, MSRV 1.92

- **Status:** Accepted
- **Date:** 2026-05-10
- **Deciders:** Project lead
- **Related:** [ADR-0009](0009-workspace-no-members-during-phase-0.md), `Cargo.toml`, `rust-toolchain.toml`, `clippy.toml`

## Context

The workspace manifest must declare a dependency resolver, a language
edition, and a minimum supported Rust version. Each is sticky: once a
project's downstream consumers depend on these values, raising or
lowering them is a coordinated change with breaking-compatibility
implications.

Phase 0 is the right time to set these values because the project has
no downstream consumers yet — no crate on crates.io, no users
embedding the binary. The values chosen here become the floor that
Phase 1+ inherits.

The relevant trade-offs:

- **Resolver:** Resolver 2 is the historical default for edition-2021
  workspaces. Resolver 3 is required for edition-2024 workspaces and
  improves duplicate-version detection.
- **Edition:** Edition 2021 is the established baseline. Edition 2024
  is the current edition at project start; it brings several syntax
  and semantic refinements and avoids a future migration.
- **MSRV:** Pinning to the latest stable maximises feature
  availability but constrains who can build the project on older
  toolchains. Pinning to an older stable widens compatibility but
  constrains feature use.

## Decision

We will pin:

- `resolver = "3"` in the workspace.
- `edition = "2024"` in `workspace.package`.
- `rust-version = "1.92"` in `workspace.package`.
- `channel = "stable"` (current stable) in `rust-toolchain.toml`,
  with `components = ["rustfmt", "clippy", "rust-src"]`.
- `msrv = "1.92"` in `clippy.toml` to enable Clippy's MSRV-aware lints.

## Consequences

### Positive

- The workspace is internally consistent: resolver 3 is required for
  edition 2024, edition 2024 is the right anchor for crypto code
  that will land in Phase 1+, MSRV 1.92 gives access to every
  stabilised feature the project expects to need.
- Future contributors do not have to guess what toolchain to install;
  `rust-toolchain.toml` is honoured automatically by rustup.
- Clippy's MSRV-aware lints prevent accidentally using a feature
  newer than the declared MSRV.

### Negative

- Contributors on toolchains older than 1.92 cannot build the
  project. Mitigation: 1.92 is current stable at the time of writing;
  this is not a real cost in 2026.
- Edition 2024 is relatively new; some third-party crates may not have
  migrated yet. Mitigation: the workspace currently has no member
  crates, so this risk materialises only at Phase 1 when concrete
  dependencies are chosen.

### Neutral

- The `unsafe_code = "deny"` workspace lint sits on top of these
  toolchain choices; it is not edition- or resolver-dependent.

## Alternatives considered

### Alternative 1: Resolver 2 + edition 2021

The conservative, well-established baseline. Rejected because the
project has no downstream consumers to negotiate with and would
otherwise have to migrate later. Starting at the current edition saves
that migration.

### Alternative 2: MSRV at a deliberately older stable (e.g., 1.85)

Would widen contributor compatibility. Rejected because the project's
target audience — infrastructure operators with current toolchains —
does not benefit from a backdated MSRV, and the cryptographic code
will benefit from stabilised features in 1.92.

### Alternative 3: Use nightly toolchain features

Tempting for some unstable rustfmt and clippy options. Rejected
because cryptographic infrastructure cannot depend on nightly. The
project uses unstable rustfmt options in `rustfmt.toml` as
intent-documentation (they take effect on nightly; stable rustfmt
emits a warning and ignores them), but no nightly-only feature gates
the build.

## Links

- Workspace manifest: `Cargo.toml` § `[workspace]` and `[workspace.package]`
- Toolchain pin: `rust-toolchain.toml`
- Clippy MSRV: `clippy.toml`
- Rust release notes for 1.92 and edition 2024 stabilisation
