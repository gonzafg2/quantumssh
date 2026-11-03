# ADR 0054: Release artifacts carry provenance attestations, a CycloneDX SBOM and a maintainer-signed `SHA256SUMS`, and releases are immutable

- **Status:** Proposed
- **Date:** TBD (accepted with the implementing PR)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §3, §4 step 4, §5 and §11 (Accepted 2026-11-03).
  - The workflow that produces the artifacts is [ADR-0053](0053-release-workflow.md). The key that signs is [ADR-0057](0057-release-signing-with-the-project-pgp-key.md).
  - Implementation: `docs/deployment.md`, `SECURITY.md` and the `immutable-releases` repository setting. Two files are new, created by the implementing PRs: `.github/workflows/release.yml` (ADR-0053) and `scripts/verify-release.sh`.

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
| `quantumssh-<v>.cdx.json` | `sbom` | Yes |
| `SHA256SUMS` | `publish` | No. The maintainer recomputes it |
| `SHA256SUMS.asc` | The maintainer, locally | No. It is the PGP signature |

### 2. SBOM

- **Tool.** `cargo-cyclonedx`, installed with `cargo install --locked`
  at a pinned version, from the CycloneDX project and licensed
  Apache-2.0.
- **Output.** It reads `cargo metadata` and runs no build script. It
  writes CycloneDX JSON for the `quantumssh` package's dependency graph
  with default features.
- **Where it runs.** In its own `sbom` job, with `contents: read`, on a
  runner that never holds a release tarball (ADR-0053 §2). Installing the
  tool compiles third-party code that can write anywhere on its runner.
  Keeping it away from the `build` job means a compromised tool cannot
  rewrite a tarball before it is uploaded. Neither `build` nor `attest`
  runs it.
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

1. The pinned signature check (§7) on the tag, through
   `git verify-tag --raw vX.Y.Z`, then
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
2. runs the pinned signature check (§7) on the new signature;
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
2. The pinned signature check (§7) on `SHA256SUMS.asc`. The docs give
   it as one command, because a bare `gpg --verify` is not enough.
3. `sha256sum --ignore-missing -c SHA256SUMS`.
4. `gh attestation verify <tarball>` with the four pins of §4 step 3.

Step 4 is recommended, and steps 1 to 3 are the minimum. A user who
skips the PGP signature and checks only attestations gets no tag
signature check (RFC-0017 §11).

If the project key is ever revoked for compromise (ADR-0057), step 2
fails for every release, by design. For a release the advisory lists as
unaffected, the recipe becomes:

1. `gh release verify-asset vX.Y.Z SHA256SUMS`, which checks the
   downloaded file against the immutable release's recorded digest;
2. step 4;
3. a match between the release's `SHA256SUMS` digest and the advisory,
   which the successor key signs.

### 7. The pinned signature check

`gpg --verify` exits 0 and prints "Good signature" for a valid
signature from a **revoked** or **expired** key. It flags those cases
only on `--status-fd`, as `REVKEYSIG`, `KEYREVOKED`, `EXPKEYSIG` and
`EXPSIG`. Every PGP verification in the release chain therefore runs
`gpg --status-fd 1 --verify` (`git verify-tag --raw` for tags) and
passes only when both hold:

- a `VALIDSIG` line names a fingerprint from the **pin set**. Today that
  is only `66DB5100B0700E4AE051971F9A8DFF06AFD25B24`. After a rotation
  (ADR-0057) it also holds every retired key, each with the validity
  window recorded next to it in `keys/`;
- no `REVKEYSIG`, `KEYREVOKED` or `BADSIG` line appears. These always
  fail.

`EXPKEYSIG` and `EXPSIG` fail for the current key. GnuPG reports an
expired key against today's date, not against the date of the
signature.

A **retired** key is handled by its window, not by GnuPG's view of
expiry. A `VALIDSIG` from a retired fingerprint passes only when both
hold:

- **The date.** `gh release verify` shows the release was published
  inside the window recorded for that key in `keys/`, from its first use
  to its retirement date.
- **The bytes.** `gh release verify-asset vX.Y.Z` passes for both
  `SHA256SUMS` and `SHA256SUMS.asc`, so the files being checked are the
  ones the immutable release recorded. A date check alone would accept a
  forged `SHA256SUMS`, signed with a leaked retired key and placed next
  to a real release from that key's window. The asset-digest check
  rejects it, because the forged file is not the release's recorded
  asset.

Both conditions apply with or without `EXPKEYSIG`. Without the check, a
retired key that has not yet reached its OpenPGP expiry would pass on
`VALIDSIG` alone. In that case, if its private half leaked, anyone
holding it could sign a forged `SHA256SUMS` for any release and pass.

The deciding date comes from the immutable-release record, which no key
holder controls (ADR-0057). Without that record the check fails.
Releases signed by a retired key therefore stay verifiable after it
expires. A forgery made with a leaked retired key fails in both cases:
outside the key's window on the date, and inside it on the asset
digest. Neither check trusts a signer-chosen timestamp.

The check is used in four places:

- ADR-0053's `precheck`;
- `scripts/verify-release.sh` (§4);
- the user recipe (§6), which `docs/deployment.md` gives as a one-line
  shell function;
- the tap's CI (ADR-0056 §4).

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
- The SBOM tool runs on a runner that has no release bytes and no write
  permission, and its output is itself attested.

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
