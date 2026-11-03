# ADR 0055: Run the interop and systemd gates on the release artifacts, on `aarch64` Linux and on macOS with a client built from a pinned tarball

- **Status:** Proposed
- **Date:** TBD (accepted with the implementing PR)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §1 and §4 step 3 (Accepted 2026-11-03), and resolves its unresolved questions "aarch64 interop image" and "Pinning the macOS client".
  - Extends [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md), [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md) and [ADR-0048](0048-openssh-interop-client-on-debian-forky.md) without changing the PR-time gate, and reuses [ADR-0043](0043-systemd-notify-service-and-reference-unit.md)'s systemd test.
  - Runs inside [ADR-0053](0053-release-workflow.md)'s workflow.
  - Implementation: `.github/workflows/interop.yml` (made callable), `release.yml` and `tests/interop/run_openssh_client.sh`.

## Context

RFC-0017 ties the Tier-1 support level to a release-blocking interop
job that runs the published binary against a pinned client. Today the
interop gate builds the workspace from source on `x86_64` and runs in a
Debian forky container pinned by digest (ADR-0048). The open questions
were:

- **Can the same pin serve `aarch64`?** The answer was not known.
- **How can a macOS client be pinned?** Homebrew's `openssh` moves with
  Homebrew.

On 2026-11-03 the registry returned an OCI image index for the pinned
digest `debian@sha256:04db4720…`, and it includes `linux/arm64/v8`. The
existing pin therefore resolves to the right image on an arm64 runner.

Both gate scripts already take the binary from `QUANTUMSSH_BIN`.

## Decision

We will make `interop.yml` callable with a prebuilt binary and run it,
together with the systemd test, against the release artifacts. On
`aarch64` the same pinned image is used. On macOS the client is built
from the OpenSSH portable release tarball, pinned by SHA-256.

### 1. Linux interop on the artifact

- **A callable workflow.** `interop.yml` gains a `workflow_call` trigger
  with two inputs:
  - `artifact`: the name of a workflow artifact holding a release
    tarball;
  - `runner`: `ubuntu-24.04` or `ubuntu-24.04-arm`.
- **When `artifact` is set**, the job skips the toolchain and
  `cargo build`, downloads and extracts the tarball, and runs
  `tests/interop/run_openssh_client.sh` with `QUANTUMSSH_BIN` pointing
  at the extracted binary.
- **What stays the same:** the same container digest, the same snapshot
  pin and the same `ssh -V` assertion.
- **The PR-time behaviour (no inputs) does not change.** It stays the
  required check of ADR-0031.
- **Called with read-only permissions.** `release.yml` calls it once per
  Linux target with `contents: read` (ADR-0053).

### 2. systemd reference unit on the artifact

`tests/systemd/run_reference_unit.sh` runs in a `release.yml` job on
`ubuntu-24.04` with `QUANTUMSSH_BIN` set to the `x86_64` artifact. It
does not run on `aarch64`: the unit and the notify protocol do not
depend on the architecture, and interop covers the `aarch64` binary.

### 3. macOS interop with a pinned client

- **The client is built from source.** The job runs on ADR-0053's arm64
  macOS runner. It downloads `openssh-<version>.tar.gz` from
  `cdn.openbsd.org` and fails unless the file's SHA-256 equals the value
  pinned in the workflow. For 10.6p1 that value is
  `a9dc9565dffe8640f64d863cd29a32bc4a3dbdec0566a7fc44c5d6ee767d5f39`, the
  tarball whose detached signature verified against the OpenSSH release
  key on 2026-11-03.
- **The build is `./configure --without-openssl --without-zlib && make
  ssh ssh-keygen`.** ML-KEM, ML-DSA, Ed25519 and
  `chacha20-poly1305@openssh.com` are internal implementations in 10.6.
  `aes256-gcm@openssh.com` is not built, so this job exercises the
  ChaCha20 suite.
- **The gate script runs unchanged.** It gets the built client first on
  `PATH` and the macOS artifact in `QUANTUMSSH_BIN`. Any part of the
  script that is not portable to macOS is fixed in the script, not
  forked.
- **Moving the client version** is a reviewed change to the pinned
  version and hash, as moving the Debian snapshot is under ADR-0034.

With a pinned client and a release-blocking job, `aarch64-apple-darwin`
meets RFC-0017's Tier-1 definition once this job is implemented. The
release notes of the first release that runs it say so.

### 4. Digest records

Each gate job writes a `sha256sum` line for every tarball it extracted
and uploads it as the artifact `gate-digests-<job>`. ADR-0053's `attest`
job and ADR-0054's maintainer script compare those records with the
tarballs.

## Consequences

### Positive

- Each published binary has itself passed a real OpenSSH 10.6 client,
  not just a build of the same source.
- One container pin covers both Linux architectures.
- The macOS client is pinned as strictly as the Debian one, by content
  hash.

### Negative

- Building OpenSSH on every macOS release run adds a few minutes.
- `aes256-gcm@openssh.com` gets no macOS coverage. It keeps its Linux
  coverage.

### Neutral

- `interop.yml` serves two callers. Its PR-time path is unchanged and
  stays required.

## Alternatives considered

### Alternative 1: Homebrew's `openssh` on the macOS runner

This is what was tried by hand on 2026-11-03. Its version moves with
Homebrew, so the job would not be pinned, and macOS would stay Tier 2.

### Alternative 2: a separate interop workflow for releases

It would duplicate the container setup and the snapshot pin that
`interop.yml` already carries.

### Alternative 3: a second container pin for `aarch64`

It is unnecessary: the existing digest is a multi-architecture index.

## Links

- [RFC-0017](../rfcs/0017-alpha-distribution.md) §1, §4
- [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md), [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md), [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md), [ADR-0048](0048-openssh-interop-client-on-debian-forky.md)
- OpenSSH 10.6p1 `defines.h` (the `USE_MLDSA` and `USE_MLKEM768X25519` conditions)
