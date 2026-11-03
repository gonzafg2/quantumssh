# ADR 0053: Build releases in a tag-triggered workflow of least-privileged jobs, gated before anything is attested

- **Status:** Proposed
- **Date:** TBD (accepted with the implementing PR)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §2, §4 and §12 (Accepted 2026-11-03; [#247](https://github.com/gonzafg2/quantumssh/pull/247)).
  - Its integrity rules are [ADR-0054](0054-release-artifact-integrity.md), its gates are [ADR-0055](0055-interop-gate-on-published-artifacts.md), and its signing key is [ADR-0057](0057-release-signing-with-the-project-pgp-key.md).
  - Phase 3 roadmap: [#248](https://github.com/gonzafg2/quantumssh/issues/248).
  - Implementation: `.github/workflows/release.yml` (new) and the repository's tag ruleset.

## Context

RFC-0017 decided that releases ship prebuilt binaries for
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and
`aarch64-apple-darwin`, built from the signed tag on native runners. It
left the following to this ADR:

- the job layout and the permissions of each job;
- the order of gating and attesting;
- the static-link check;
- the tag rules;
- whether to move to SLSA Build Level 3.

Two of RFC-0017's review findings shape the layout:

- **A compromised build script.** Under threat model §5.5.2.a, such a
  script must not run in a job that can mint attestations or publish.
- **Unchecked bytes.** A gate must not execute bytes whose origin has not
  been checked.

## Decision

We will build releases in `.github/workflows/release.yml`, triggered by
`v*` and `rehearsal-*` tags. Its jobs each hold only the permissions
they need, and nothing is attested until every gate has passed on the
exact bytes being released.

### 1. Trigger and defaults

- `on: push: tags: ['v*', 'rehearsal-*']`. There are no other triggers.
- The workflow-level `permissions: {}` is empty, and every job declares
  its own permissions.
- No cache action runs in this workflow: no `Swatinem/rust-cache` and
  no `actions/cache`. A cache written by a pull-request run could
  otherwise feed the release build.
- Every action is pinned by commit SHA, as in the rest of
  `.github/workflows/`. The toolchain comes from `rust-toolchain.toml`.

### 2. Jobs, in order

| Job | Permissions | Does |
|---|---|---|
| `precheck` | `contents: read` | Checks out with `fetch-depth: 0` and `persist-credentials: false`. It fails unless the tagged commit is an ancestor of `origin/main`. For a `v*` tag, it also fails unless the tag is annotated and `git tag -v` verifies it against the `keys/security.asc` read from `origin/main`, never from the tag's own tree. |
| `build` (matrix of three) | `contents: read` | `rustup target add <t>`, then `cargo build --release --locked -p quantumssh --target <t>`. Runs the static-link check (§3), assembles the tarball (RFC-0017 §3), and generates the SBOM on the `x86_64` leg only (ADR-0054). Uploads them as workflow artifacts. |
| gates (ADR-0055) | `contents: read` | Interop on the three binaries, and the systemd reference unit on `x86_64`. Each gate records the SHA-256 of the tarball it ran. |
| `attest` | `contents: read`, `id-token: write`, `attestations: write` | Downloads the build artifacts and the gates' digest records. It fails unless every tarball's digest equals what each gate recorded. Then it attests the tarballs and the SBOM (ADR-0054). It runs no project code and installs no tool. |
| `publish` | `contents: write` | Writes `SHA256SUMS` (ADR-0054) and creates the **draft** release with `gh release create --draft --verify-tag`. It uploads the assets and does nothing else. |

- **Runners.**
  - `ubuntu-24.04` for `x86_64` Linux;
  - `ubuntu-24.04-arm` for `aarch64` Linux;
  - a versioned arm64 macOS label for `aarch64-apple-darwin`.

  The build never uses `*-latest`, so the runner image cannot change
  under a release. The label is the newest one available when the
  workflow is written.
- **No target is cross-compiled.**
- **`needs:` encodes the order.** A failure anywhere stops the jobs
  after it.

### 3. Static-link check (fail closed)

- **Linux.**
  - `readelf -d` shows no `NEEDED` entry, and `readelf -l` shows no
    `INTERP` program header.
  - The binary prints `quantumssh 0.x.y` for `--version` inside an
    Alpine container pinned by digest, with the binary mounted read-only.
- **macOS.** `otool -L` lists only libraries under `/usr/lib`.
- **The binary must report the tag's version.** `--version` must print
  the version the tag names, after the `v`. A `rehearsal-*` tag skips
  only this comparison.
- **Allocator.** The musl allocator stays the default. The workflow
  carries `ponytail: musl allocator contends under many connections;
  bounded by ADR-0028's caps; upgrade path a global allocator such as
  mimalloc, behind its own ADR`.

### 4. Tags

- **Ruleset on `refs/tags/v*`:**
  - creation is restricted to the repository administrator;
  - update and deletion are blocked for everyone, with no bypass.
- **A failed release consumes its version** (RFC-0017 §4). The draft is
  deleted, the tag stays, and the next attempt is the next patch version.
- **`rehearsal-*` tags are outside the ruleset.** They run the whole
  workflow, publish step included, as a draft named `Rehearsal …`. The
  draft and the tag are deleted afterwards. The rehearsal attestations
  name a `rehearsal-*` ref, so the user verification of ADR-0054, which
  pins `refs/tags/vX.Y.Z`, rejects them.

### 5. SLSA level

- **The workflow targets SLSA v1.0 Build Level 2** (GitHub-hosted
  attestation of a hosted build).
- **Level 3 is deferred.** It needs the build in a reusable workflow
  that the caller cannot influence, which is a second layer of workflow
  for one maintainer.
- **Revisit at Phase 3's reproducible-builds work.** That work changes
  the build anyway.

## Consequences

### Positive

- A compromised build script runs in a job that can read the repository
  and nothing else. It cannot mint an attestation, upload an asset or
  push.
- Only bytes that passed every gate are attested, and the attest job
  checks that they are the same bytes.
- The early `precheck` catches a tag on an unreviewed commit or an
  unsigned tag before any build. It is a tripwire, not the guarantee.
  The guarantee is the maintainer's check in ADR-0054.

### Negative

- Without caches, release builds start cold, which takes minutes per
  target.
- Five job kinds and artifact hand-offs make the workflow longer than a
  single job would be.
- A failed release burns a version number.

### Neutral

- The PR-time CI (`ci.yml`, `interop.yml`) does not change and keeps its
  caches. Only `release.yml` forgoes them.

## Alternatives considered

### Alternative 1: one job that builds, gates, attests and publishes

This is the simplest option. Every step would then run with
`id-token: write` and `contents: write`, including `cargo build` and the
gates that execute the binary. Rejected for threat model §5.5.2.a.

### Alternative 2: attest at build time and have the gates verify the attestation

RFC-0017 §4 allows this as the fallback order. It attests bytes that
might still fail a gate. Gating the workflow artifacts first is simpler
and attests only what passed.

### Alternative 3: build before tagging, and tag only the gated commit

This would avoid burning a version on failure. The attestations would
then name a branch ref, and the user check that pins
`--source-ref refs/tags/vX.Y.Z` could not pass.

### Alternative 4: a reusable workflow now, for SLSA Build Level 3

Deferred under §5.

## Links

- [RFC-0017](../rfcs/0017-alpha-distribution.md) §2, §4, §11
- [Threat model](../threat-model.md) §5.5.2, §6.4
- [ADR-0028](0028-phase-2-concurrent-connections-limits-graceful-shutdown.md) (the admission caps that bound the allocator's ceiling)
- GitHub Docs: artifact attestations, SLSA build levels
