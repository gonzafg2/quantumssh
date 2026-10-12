# ADR 0039: Pin the Rust toolchain to an exact release, named only in `rust-toolchain.toml`

- **Status:** Accepted
- **Date:** 2026-10-12 (accepted with the implementing PR [#181](https://github.com/gonzafg2/quantumssh/pull/181); drafted 2026-10-12)
- **Deciders:** Project lead
- **Related:** Supersedes the `channel = "stable"` part of the fourth bullet of [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md) §Decision; the `components` list in that bullet and every other bullet of ADR-0010 (resolver 3, edition 2024, MSRV 1.92, `clippy.toml` `msrv`) stand. Applies the pinning discipline of [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) and [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md) (a floating input that can turn an unrelated PR red is pinned and moved by a reviewed bump). The `build (…)` jobs it stabilises are required checks under [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md). Implementation: `rust-toolchain.toml`, `.github/workflows/{ci,interop,audit}.yml` and `.github/dependabot.yml`, in [#181](https://github.com/gonzafg2/quantumssh/pull/181).

## Context

ADR-0010 set `channel = "stable"` ("current stable") in
`rust-toolchain.toml` (ADR-0010 line 41, `rust-toolchain.toml` line 5).
Three CI jobs install Rust through `dtolnay/rust-toolchain` with
`toolchain: stable`: `build` in `ci.yml` (lines 89–94, Ubuntu and
macOS), `openssh-interop` in `interop.yml` (lines 96–99) and `audit` in
`audit.yml` (lines 36–40). The action runs `rustup toolchain install
stable` on every run, so CI moves to a new Rust release the day it
ships. The `cargo deny` job installs nothing itself: the container of
`cargo-deny-action` runs `rustup show || rustup toolchain install` in
the manifest directory (`entrypoint.sh` line 41 at the pinned
`3c63498`), which installs whatever `rust-toolchain.toml` names.

The compiler and Clippy that judge a PR are therefore whichever release
is newest that day, not one any PR chose. `build` runs `cargo clippy …
-- -D warnings` with `RUSTFLAGS: -D warnings` (`ci.yml` lines 16 and
106), so a new warn-by-default lint fails it.

That happened. Rust 1.99.0 reached the stable channel on 2026-10-01
(rustup in CI: "latest update on 2026-10-01 for version 1.99.0") with
the new lint `clippy::assert_is_empty`, which flagged four test
assertions. Every PR run of the CI workflow failed `build` from the
first one after the release (2026-10-05, run 37271047382; the previous
PR run, 2026-09-28, was green) to the last before the fix (2026-10-11
04:30 UTC, run 38111812201): six runs on three PRs, two Dependabot
action bumps (#170, #171) and the docs-only RFC-0012 PR (#172).
`build (ubuntu-latest)` and `build (macos-latest)` are required checks
with no bypass (ADR-0008, ADR-0031), so for almost six days no PR could
merge. [#173](https://github.com/gonzafg2/quantumssh/pull/173) fixed the
four assertions and named the floating channel as the root cause, left
for a superseding ADR. The exposure is not specific to that lint: any
release can add a lint, promote one to warn-by-default, or change the
compiler under every open PR. ADR-0020 rejected a floating OpenSSH
client for the same reason, and ADR-0034 finished that pin.

Facts that shape the design (checked on 2026-10-12):

- **The file already decides what runs.** rustup gives
  `rust-toolchain.toml` precedence over the default toolchain the action
  sets. The CI log of run 38184753507 records "the toolchain
  'stable-x86_64-unknown-linux-gnu' is currently in use (overridden by
  '…/rust-toolchain.toml')". Every `cargo` command in the checkout runs
  the file's toolchain. The action's `toolchain` input decides only what
  is installed first, and what the action prints. Pinning the file while
  the workflows keep `stable` would leave them out of step: each job
  would install the newest stable, then still need the pinned release.
- **`dtolnay/rust-toolchain` cannot read the file.** At the pinned
  commit `7e38f4b` its `toolchain` input is required (`action.yml`
  lines 9–11), and its only inputs are `toolchain`, `targets`/`target`
  and `components` (lines 8–20). Its README pairs an explicit
  `toolchain` input with a SHA or `@master` ref (lines 43–45), and
  requires a pinned SHA to be "within the history of the master branch"
  (lines 102–108). The version refs (`@1.99.0`) are master plus one
  commit, outside that history, so they cannot be SHA-pinned
  the way this repository pins every action.
- **Dependabot can bump the file, but is not configured to.** Dependabot
  has had a `rust-toolchain` package ecosystem since 2025-08-19. It
  updates `rust-toolchain.toml` versioned channels such as `1.xx.yy`,
  for version updates only. `.github/dependabot.yml` configures only
  `cargo` (line 4) and `github-actions` (line 42), so nothing proposes
  toolchain bumps today; under `stable` there was nothing to bump.

## Decision

We will pin the Rust toolchain to an exact stable release in
`rust-toolchain.toml`, name the version nowhere else, and move it only
through a reviewed bump PR.

- **Exact pin.** `channel = "1.99.0"`, the release CI ran on the day of
  drafting (`rustc 1.99.0 (b940084d7 2026-09-28)` in run 38184753507,
  the same build used locally). `components` and `profile` are
  unchanged. Minor and patch releases alike are bumps.
- **One source of truth.** No workflow names a Rust version. Each job
  that installs Rust (`build` on both OSes, `openssh-interop`, `audit`)
  reads `channel` from `rust-toolchain.toml` in a step before
  `dtolnay/rust-toolchain` and passes it as the action's `toolchain`
  input. The step fails the job unless the value is an exact
  `MAJOR.MINOR.PATCH` version, so a return to `stable` or to a two-part
  `1.99` fails CI instead of floating again silently. `cargo deny` needs
  no change: its action already installs what the file names.
- **Bump procedure.** A toolchain bump is one PR that changes `channel`
  and fixes whatever the new release flags, with CI green on the new
  version: `fmt`, `clippy -D warnings`, tests, the release build and the
  interop gate. New lints then turn one PR red, the bump, instead of
  every open PR. The trigger is Dependabot: a `rust-toolchain` entry in
  `.github/dependabot.yml`, on the same weekly schedule as the two
  existing entries, opens the bump PR after each release. The maintainer
  pushes any lint fixes onto it, or replaces it with a manual PR, and
  merges it like any other change. A release that fixes a security issue
  affecting the project is bumped without waiting for the weekly run.
- **Unchanged.** MSRV (`rust-version = "1.92"`, `clippy.toml`
  `msrv = "1.92"`), resolver, edition and the component list stay as
  ADR-0010 set them. Contributors still get the toolchain from rustup
  reading the file; it is now exactly the one CI uses.

**Why an ADR, not an RFC.** `docs/rfcs/README.md` sends a new
dependency that materially expands the trust base, a default users
would notice, or a refinement of a `README.md` / `MANIFIESTO.es.md`
commitment to an RFC. This is none of them:

1. No new dependency, action or host. The toolchain still comes from
   rustup's distribution through the same SHA-pinned action. Dependabot
   already runs on this repository for two ecosystems and gains a third
   with the same rights: it opens PRs and cannot merge them.
2. It removes a moving input from CI. The binary, its configuration
   and its defaults do not change.
3. It replaces one bullet of an ADR, which ADR-0015 says is done by a
   superseding ADR, the lane ADR-0034 used for ADR-0020.

## Consequences

### Positive

- A Rust release can no longer turn every open PR red. The failure of
  2026-10-05 to 2026-10-11 is confined to the bump PR.
- CI, local builds and Dependabot read one line of one file. A bump PR
  that touches only that line moves every job, so the workflows cannot
  drift from the file.
- Re-running CI on an old commit uses the toolchain that commit names.

### Negative

- Bumps are scheduled work: about one PR per six-week release, usually
  one line, sometimes with lint fixes. Before, the same work arrived
  unscheduled inside unrelated PRs.
- The project can trail the newest stable by up to a week plus review
  time. A security fix in `rustc` or `std` reaches CI and contributor
  builds only through the bump.
- Dependabot PRs get no workflow reviewer: opencode and Claude Code
  Review run only on human-authored PRs (`CLAUDE.md`). The bump diff is
  small, which keeps the manual review cheap.

### Neutral

- No CI job builds with the MSRV (1.92), before or after this ADR. An
  MSRV job (`cargo +1.92 check`) is a possible follow-up if a 1.92 break
  is ever reported; it is not added here.
- `Swatinem/rust-cache` already keys on the `rustc` version and on
  `rust-toolchain.toml` (run 38184753507), so a bump invalidates the
  cache with no workflow change.

## Alternatives considered

### Alternative 1: Keep `stable` and fix new lints when they appear

The state since ADR-0010. Rejected: it is what blocked every merge for
almost six days, and the fix had to come from outside the PRs it
blocked.

### Alternative 2: Pin the same literal in every workflow

`toolchain: 1.99.0` in three workflow files next to the file. Rejected:
four copies of one value, and Dependabot's `rust-toolchain` ecosystem
updates the toolchain file only, so its PRs would leave the workflows
behind.

### Alternative 3: Drop `dtolnay/rust-toolchain` and let rustup install from the file

`rustup toolchain install` with no argument installs the active
toolchain, which the file names, and the hosted runners ship rustup.
Rejected: the interop container (`debian:trixie-slim`) has no rustup,
so something must still install it, and the action also handles install
retries and sets `CARGO_INCREMENTAL=0`, which the workflows would have
to reproduce.

### Alternative 4: Stop failing on new lints

Drop `-D warnings`, or cap lints, so a new Clippy lint warns instead of
failing. Rejected: `-D warnings` is the project's lint gate (`CLAUDE.md`
"Key commands"). Loosening it to absorb toolchain drift trades a
scheduling problem for a quality one, and it does not cover compiler
changes.

### Alternative 5: Pin, with manual bumps only

Rejected: nothing would prompt a bump, and the pin would age silently.
The Dependabot PR is the reminder; merging it stays a reviewed decision.

## Links

- Implementation: `rust-toolchain.toml`; the "Read pinned toolchain"
  step and the `dtolnay/rust-toolchain` input in
  `.github/workflows/ci.yml`, `interop.yml` and `audit.yml`; the
  `rust-toolchain` entry in `.github/dependabot.yml`
  ([#181](https://github.com/gonzafg2/quantumssh/pull/181)).
- Incident: CI runs 37271047382 (first failure, 2026-10-05) and
  38111812201 (last, 2026-10-11); fix [#173](https://github.com/gonzafg2/quantumssh/pull/173).
- Upstream: [`dtolnay/rust-toolchain`](https://github.com/dtolnay/rust-toolchain/tree/7e38f4b43b4db5c8dd498af069a4f6196df1d067)
  (README and `action.yml` at the pinned commit);
  [`EmbarkStudios/cargo-deny-action` `entrypoint.sh`](https://github.com/EmbarkStudios/cargo-deny-action/blob/3c6349835b2b7b196a839186cb8b78e02f7b5f25/entrypoint.sh);
  [Dependabot now supports Rust toolchain updates](https://github.blog/changelog/2025-08-19-dependabot-now-supports-rust-toolchain-updates/)
  (GitHub changelog, 2025-08-19);
  [Dependabot options reference](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference)
  (`package-ecosystem: rust-toolchain`).
- Related ADRs: [ADR-0010](0010-toolchain-pinning-resolver-3-edition-2024-msrv-1-92.md)
  (partly superseded), [ADR-0015](0015-permit-annotated-errata-in-adrs.md),
  [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md),
  [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md),
  [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md).
