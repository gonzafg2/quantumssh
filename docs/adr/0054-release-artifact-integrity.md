# ADR 0054: Release artifacts carry provenance attestations, a CycloneDX SBOM and a maintainer-signed `SHA256SUMS`, and releases are immutable

- **Status:** Proposed
- **Date:** TBD (accepted with the implementing PR)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §3, §4 step 4, §5 and §11 (Accepted 2026-11-03).
  - The workflow that produces the artifacts is [ADR-0053](0053-release-workflow.md). The key that signs is [ADR-0057](0057-release-signing-with-the-project-pgp-key.md).
  - Implementation: `release.yml`, `scripts/verify-release.sh` (new), the `immutable-releases` repository setting, `docs/deployment.md` and `SECURITY.md`.

## Context

RFC-0017 §11 adds a "Release provenance" control to threat model §6.4.
It rests on three things:

- attestations that bind each tarball and the SBOM to the release
  workflow and the tag;
- a `SHA256SUMS` that the maintainer recomputes and signs;
- immutable releases.

The RFC left the SBOM tool, the file formats and the verification
procedure to this ADR.

## Decision

We will attest every tarball and the SBOM with
`actions/attest-build-provenance`, publish a CycloneDX SBOM made by
`cargo-cyclonedx`, and have the maintainer sign a locally recomputed
`SHA256SUMS` after `scripts/verify-release.sh` passes. Releases are
immutable from `0.2.0` on.

### 1. Assets

| Asset | Made by | Attested |
|---|---|---|
| `quantumssh-<v>-<target>.tar.gz` (×3) | `build` | Yes |
| `quantumssh-<v>.cdx.json` | `build` (`x86_64` leg) | Yes |
| `SHA256SUMS` | `publish` | No. The maintainer recomputes it |
| `SHA256SUMS.asc` | The maintainer, locally | No. It is the PGP signature |

### 2. SBOM

- **Tool.** `cargo-cyclonedx`, installed in the `build` job with
  `cargo install --locked` at a pinned version, from the CycloneDX
  project and licensed Apache-2.0.
- **Output.** It reads `cargo metadata` and runs no build script. It
  writes CycloneDX JSON for the `quantumssh` package's dependency graph
  with default features.
- **Where it runs.** In the `build` job, which has no write permission
  (ADR-0053). The attest job never runs it.
- **`cargo auditable` is not adopted.** Embedding the dependency list in
  the binary duplicates the SBOM and adds a build wrapper (YAGNI).

### 3. `SHA256SUMS`

- **Format.** GNU `sha256sum` format, one `<hex>  <filename>` line per
  tarball and for the SBOM, sorted by filename, LF line endings and no
  other content.
- **Checking it.** `sha256sum --ignore-missing -c SHA256SUMS` checks a
  partial download.

### 4. Maintainer verification: `scripts/verify-release.sh vX.Y.Z`

The script is run in the maintainer's terminal before signing. It
stops at the first failure.

1. `git tag -v vX.Y.Z` against `keys/security.asc`, then
   `git merge-base --is-ancestor <tag commit> origin/main`.
2. `gh release download` of the draft's assets into an empty directory.
3. For each tarball and the SBOM:
   - run `gh attestation verify` with `-R gonzafg2/quantumssh`,
     `--signer-workflow gonzafg2/quantumssh/.github/workflows/release.yml`,
     `--source-ref refs/tags/vX.Y.Z` and `--deny-self-hosted-runners`;
   - check that the commit in the attestation's
     `resolvedDependencies` is the tag's commit.
4. Recompute `SHA256SUMS` from those files. It must be byte-identical to
   the draft's copy.
5. `gh run download` the gates' digest records from the release run.
   Every tarball line must equal them.
6. Print `ready to sign` and the exact commands that follow.

The maintainer then:

1. runs `gpg --armor --detach-sign -u 9A8DFF06AFD25B24` on the local
   `SHA256SUMS`;
2. runs `gpg --verify`;
3. runs `gh release upload` of `SHA256SUMS.asc`;
4. publishes the draft.

If any asset changes after the gates ran, the workflow is re-run from a
new tag (ADR-0053 §4).

### 5. Immutable releases

- **The setting.** The repository's `immutable-releases` setting is
  turned on before `0.2.0`; on 2026-11-03 it is off. A published
  release's tag and assets are then locked, and GitHub attaches a
  release attestation (`gh release verify`).
- **Releases already published.** `v0.1.0`, published before the
  setting, stays mutable. It has no binary assets.

### 6. User verification recipe

`docs/deployment.md` and `SECURITY.md` document, in this order:

1. Import the project key, and check its fingerprint offline, as
   `SECURITY.md` already shows.
2. `gpg --verify SHA256SUMS.asc SHA256SUMS`.
3. `sha256sum --ignore-missing -c SHA256SUMS`.
4. `gh attestation verify <tarball>` with the four pins of §4 step 3.

Step 4 is recommended, and steps 1 to 3 are the minimum. A user who
skips the PGP signature and checks only attestations gets no tag
signature check (RFC-0017 §11).

## Consequences

### Positive

- Each link in the chain is checked in one place, by one script, before
  the signature:
  - the tag signature;
  - its ancestry;
  - the workflow identity;
  - the commit;
  - the bytes;
  - the gates.
- The SBOM is produced where it can do no harm, and is itself attested.

### Negative

- Signing needs the maintainer's terminal, because the key's passphrase
  needs a TTY. Releases are cut from a workstation, not from CI.
- The SBOM tool is a new piece of build tooling. It is pinned, but it is
  not covered by `cargo deny`, which audits only the workspace's
  dependencies.

### Neutral

- `SHA256SUMS` is not attested. Its authority is the maintainer's
  signature over a file the maintainer recomputed.

## Alternatives considered

### Alternative 1: sign `SHA256SUMS` in CI with a key held as a secret

This removes the TTY step. It also puts a long-lived release key in a
place that RFC-0017 §5 excludes: "The PGP private key is never given to
CI".

### Alternative 2: Sigstore cosign signatures instead of PGP

This adds a second identity for users to learn. RFC-0017
Alternative 7 rejected it.

### Alternative 3: attest `SHA256SUMS` as well

This is harmless but redundant. The maintainer recomputes the file and
never trusts CI's copy.

## Links

- [RFC-0017](../rfcs/0017-alpha-distribution.md) §3, §4, §11
- [ADR-0053](0053-release-workflow.md), [ADR-0057](0057-release-signing-with-the-project-pgp-key.md)
- `actions/attest-build-provenance`; `cargo-cyclonedx` (CycloneDX); GitHub Docs: immutable releases
