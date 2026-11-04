# ADR 0059: Run the OpenSSH and systemd gates from an attested image on GHCR, built once from the snapshot pin

- **Status:** Proposed
- **Date:** drafted 2026-11-04; accepted with the implementing PR
- **Deciders:** Project lead
- **Related:**
  - Resolves [#262](https://github.com/gonzafg2/quantumssh/issues/262).
  - Refines [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md): its install step moves from every run to one image build, and its bump procedure becomes two pull requests (§5). Its pinning mechanics stand.
  - Removes the last negative consequence of [ADR-0048](0048-openssh-interop-client-on-debian-forky.md), the per-run dependency on snapshot.debian.org. Its base image, snapshot, client version and client floor stand.
  - Extends the release gates of [ADR-0055](0055-interop-gate-on-published-artifacts.md) and the systemd test of [ADR-0043](0043-systemd-notify-service-and-reference-unit.md) §7.
  - Constrained by [RFC-0017](../rfcs/0017-alpha-distribution.md) §4 step 3: gate jobs hold only `contents: read` and run only bytes whose origin was checked.
  - Implementation:
    - new files: `tests/gate-image/Dockerfile`, `tests/gate-image/verify.sh` and `.github/workflows/gate-image.yml`;
    - changed files: `.github/workflows/interop.yml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml` and `tests/systemd/run_in_docker.sh`;
    - `tests/systemd/Dockerfile` is removed.

## Context

Three gates install the pinned OpenSSH 10.6p1 client at run time, from
snapshot.debian.org:

- the interop gate, `openssh-interop` (ADR-0020, ADR-0048), a required
  check;
- the release legs of that gate (ADR-0055 §1);
- the systemd reference-unit test (ADR-0043 §7), in the required check
  `build (ubuntu-latest)` and in the release gate `gate systemd`.

All three already set `Acquire::Retries "3"`. On 2026-11-04 the
snapshot service still failed four runs with `503 No healthy backends`,
`503 first byte timeout` or `504 Gateway Timeout`. Those runs were the
`v0.2.0` release, a docs-only PR and a lockfile bump. Every failure was
in an apt step, and none was related to the change under test. They
passed on manual reruns (#262 lists the runs).

ADR-0034 named this dependency as a negative consequence. It rejected a
Dockerfile built `FROM` the snapshot (its Alternative 1) because it
"adds an image build (or a published image) to every run for the same
result". The result is no longer the same: an image built once moves
the snapshot dependency from every run to each bump, and bumps are
rare.

Three platform facts shape the design. Each was checked on 2026-11-04:

- **Skipped jobs pass required checks.** GitHub skips every job whose
  `needs` failed. It reports a skipped job as "Success", and a skipped
  required check does not block a merge.
- **Attestations are public.** For a public repository, the attestation
  API answers without authentication: an unauthenticated
  `GET /repos/gonzafg2/quantumssh/attestations/sha256:<digest>` returned
  200. A token that holds only `contents: read` can therefore verify an
  attestation.
- **GHCR is free here.** GitHub Packages does not charge public packages
  for storage or transfer.

## Decision

We will build one image for the gates from ADR-0048's pin. A workflow
on `main` builds it and attests its provenance. It is published on GHCR
with its Debian sources beside it. Every gate verifies the image's
provenance on the runner host before the image runs. The gates then use
the image instead of installing packages from snapshot.debian.org.

### 1. One image, built from the snapshot pin

- **The Dockerfile.** `tests/gate-image/Dockerfile` starts `FROM`
  ADR-0048's base digest. It carries ADR-0034's install step unchanged:
  - the `SNAPSHOT` check against the base image's `debian.sources`;
  - `http` with `Signed-By`;
  - `Check-Valid-Until` off;
  - `Acquire::Retries "3"`.
- **The packages.** The image installs, from one archive state:
  - the interop gate's packages: `ca-certificates`, `curl`, `gcc`,
    `libc6-dev` and `openssh-client=<pinned version>`;
  - the systemd test's packages: `systemd`, `systemd-sysv` and `procps`.
- **The build asserts the client.** It checks what the interop gate
  checks today:
  - `ssh -V` equals the pinned string verbatim;
  - `ssh -Q kex` lists `mlkem768x25519-sha256`;
  - `ssh -Q key` lists `ssh-mldsa44-ed25519`.

  An image that fails any of these is never pushed. The gates print
  `ssh -V` to their log, but they no longer assert it: the expected
  string is kept in one place.
- **Two platforms.** The image is built for `linux/amd64` and
  `linux/arm64`, each natively on `ubuntu-24.04` and
  `ubuntu-24.04-arm`. The base digest is already a multi-arch index
  (ADR-0055 §Context). The two images are joined into one OCI image
  index, and the index digest is the one that is attested, pinned and
  verified. The implementing PR confirms that `gh attestation verify`
  accepts an attestation made on an index digest. If it does not, each
  platform manifest is attested too, and the verification checks the
  manifest for the runner's platform.
- **The systemd test runs the image directly.** It uses
  `docker run … /sbin/init`, with `SIGRTMIN+3` as the stop signal, and
  no longer builds `tests/systemd/Dockerfile`, which is removed. The pin
  is then no longer copied between `interop.yml` and a second
  Dockerfile.

### 2. Public, with its sources beside it

- **The image** is `ghcr.io/gonzafg2/quantumssh-gate`, and it is
  public:
  - anyone can pull the exact bytes a gate ran and verify their
    provenance, as anyone can for the release tarballs (RFC-0017 §4);
  - PRs from forks and from Dependabot pull it without credentials;
  - the gates keep only `contents: read`, as RFC-0017 §4 step 3
    requires.
- **The sources.** The image redistributes Debian binary packages, some
  of them under the GPL. The same build fetches, from the same
  snapshot, the source package and version of every package installed
  on either platform:
  - it reads them with
    `dpkg-query -W -f '${source:Package}=${source:Version}\n'`;
  - it fetches each one with `apt-get source --download-only`, from a
    `deb-src` entry at the same `SNAPSHOT`.

  It publishes them as `ghcr.io/gonzafg2/quantumssh-gate-sources`,
  tagged `sha256-<hex of the gate image's index digest>`, and attests
  that image too. The gate image's `org.opencontainers.image.description`
  says where its sources are, and so does its
  `org.opencontainers.image.source`, which links the package to this
  repository.
- **Retention.** No version of either package is deleted while any
  commit on `main` or any release tag pins it. In practice, none is
  deleted, so old commits and release tags can still be rerun.
- **Visibility.** After the first publish, the maintainer checks that
  both packages are public, and makes them public if GHCR created them
  private.

### 3. Who builds it, and with what provenance

`.github/workflows/gate-image.yml` runs only on GitHub-hosted runners.

- **On `pull_request`** touching `tests/gate-image/**` or the workflow
  itself, it builds both platforms and the source set. It holds only
  `contents: read`, and it pushes and attests nothing. This is how the
  bump PR (§5) checks that the Dockerfile builds and that its
  assertions hold.
- **On `push` to `main`** touching the same paths, and on
  `workflow_dispatch`, which runs only when the ref is
  `refs/heads/main`, it:
  - builds both images;
  - pushes each one by digest;
  - creates the index;
  - attests the index and the source image with `actions/attest`
    (`push-to-registry: true`).

  Only the publishing job holds `packages: write`, `id-token: write` and
  `attestations: write`, plus any other permission the attest action
  requires.
- **The job summary** prints the index digest, the source image's
  digest and `ssh -V`, for the PR that pins them (§5).

GHCR accepts a push from any workflow run in this repository that holds
`packages: write`, on any branch. Trust therefore comes from the
attestation, not from the registry. Only an image attested by this
workflow on `refs/heads/main` passes §4.

### 4. How a gate verifies the image before running it

- **One digest.** The index digest is written literally wherever the
  image is used:
  - the `container.image` of `interop.yml`, which cannot read `env`;
  - the systemd runner script.

  `tests/gate-image/verify.sh` fails unless every reference names the
  same digest. Then it runs:

  ```sh
  gh attestation verify oci://ghcr.io/gonzafg2/quantumssh-gate@sha256:<digest> \
    -R gonzafg2/quantumssh \
    --signer-workflow gonzafg2/quantumssh/.github/workflows/gate-image.yml \
    --source-ref refs/heads/main --deny-self-hosted-runners
  ```

  This is the same check users run on a release tarball, with this
  workflow and ref in place of `release.yml` and the tag. Every caller
  runs it with a token that holds only `contents: read` (§Context).
- **Where it runs.** It always runs on the runner host, before the image
  runs:
  - **`interop.yml`:** a new job, `gate-image`, that `openssh-interop`
    `needs`. This covers both the PR-time gate and the release legs
    under `workflow_call`. The container starts only after the
    verification has passed. Steps inside the container could be made to
    lie by the image they would be checking.
  - **`ci.yml`, `build (ubuntu-latest)`:** a step before the systemd
    reference-unit step.
  - **`release.yml`, `gate systemd`:** a step before
    `run_in_docker.sh`. The job's permissions do not change.
- **A failed verification blocks the merge.** If `gate-image` fails on
  a PR, `openssh-interop` is skipped, and a skipped required check does
  not block a merge (§Context). The same verification in
  `build (ubuntu-latest)`, a required check, still fails and blocks the
  PR. No required check is added. On a release, the failure fails the
  called workflow. `attest` needs every gate, so nothing is attested or
  published, which is one of RFC-0017 §4's stop conditions.

### 5. Updating the image

An ADR-0034 bump becomes two reviewed PRs:

1. **PR A** moves the values in `tests/gate-image/Dockerfile` by
   ADR-0034's procedure: the base digest, `SNAPSHOT`, the package
   version and the `ssh -V` string. `gate-image.yml` builds the new
   image without publishing it. PR A's own gates still run the image
   that is pinned.
2. **Merging PR A** publishes and attests the new image. **PR B** moves
   the pinned digest. Its CI verifies the provenance and runs every gate
   on the new client.

Nothing floats:

- rebuilding an unchanged Dockerfile with `workflow_dispatch` produces a
  new digest that no gate uses until a PR pins it;
- Dependabot has no `docker` ecosystem configured, so it does not touch
  the digest.

A snapshot outage during a build fails only that build, and it is
rerun by hand. The first image follows the same two steps. One PR adds
the Dockerfile and the workflow. A second PR switches the gates, adds
`verify.sh`, flips this ADR to `Accepted`, and names this ADR in the
Status lines of ADR-0034 and ADR-0048.

## Consequences

### Positive

- No gate run contacts snapshot.debian.org. All four failures in #262
  happened in that apt step.
- The gates no longer run `apt-get` on every run.
- Anyone can pull the exact bytes a gate ran, with their provenance and
  their sources.
- The pin lives in one Dockerfile. Today it is copied between
  `interop.yml` and `tests/systemd/Dockerfile`.

### Negative

- A bump takes two PRs instead of one.
- A new workflow holds `packages: write` and `id-token: write`, on
  `main` only. If that workflow were compromised, it could publish an
  image that verifies. This is the same class of risk as `release.yml`,
  listed in RFC-0017 §11 among the things the project does not defend
  against.
- The project now redistributes Debian binaries and their sources, and
  keeps every pinned version.
- Every gate now depends on GHCR being available. GHCR is in the same
  failure domain as the runners and the workflow artifacts the gates
  already use.
- Each gate gets packages it does not use: the interop container has
  systemd, and the systemd test has `gcc`.

### Neutral

- Image builds still depend on snapshot.debian.org, a few times a
  year.
- These are unchanged and outside #262:
  - the macOS release leg, which fetches the OpenSSH tarball from
    `cdn.openbsd.org` on every run (ADR-0055 §3);
  - `scripts/capture-openssh-kex-vector.sh`, which the maintainer runs
    by hand.
- The client version, the forky base and the 10.6p1 floor stay as
  ADR-0048 decides.

## Alternatives considered

### Alternative 1: cache the `.deb` files with `actions/cache`

The cache would be keyed on the snapshot and the package versions.
Rejected:

- GitHub evicts a cache that is not used for seven days, which brings
  the dependency back.
- ADR-0053 §1 forbids caches on the release path, so the release gates
  would keep the dependency.

### Alternative 2: vendor the `.deb` files

The files would live in the repository or in a release. Rejected for
ADR-0034's Alternative 2 reasons:

- a binary artefact in the repository;
- a dependency closure that has to be kept consistent with the base
  image;
- a manual chain of custody on every bump.

### Alternative 3: a private image

It redistributes nothing. Rejected:

- Pulling a private image needs `packages: read` in the gates, which
  contradicts RFC-0017 §4 step 3.
- Outsiders could not inspect what a gate ran.

### Alternative 4: a public image, with sources only at snapshot.debian.org

It is simpler: there is no source image, and the image's description
links to the archive. Rejected: GPLv2 §3 and GPLv3 §6(d) differ on
whether a third party's server is enough. Publishing the sources next
to the image does not depend on that reading.

### Alternative 5: more retries, or a longer back-off

This is the cheapest option. Rejected: in run 41847663703, the job
already retried each request three times. Its first two attempts,
started nine minutes apart, both failed. The third passed 34 minutes
after the second. A step cannot usefully wait that long, and more
retries still leave every run exposed.

## Links

- Issue: [#262](https://github.com/gonzafg2/quantumssh/issues/262)
- [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md), [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md), [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md), [ADR-0043](0043-systemd-notify-service-and-reference-unit.md), [ADR-0048](0048-openssh-interop-client-on-debian-forky.md), [ADR-0053](0053-release-workflow.md), [ADR-0055](0055-interop-gate-on-published-artifacts.md)
- [RFC-0017](../rfcs/0017-alpha-distribution.md) §4, §11
- GitHub Docs:
  - "Using conditions to control job execution" (a skipped job reports "Success");
  - "Publishing and installing a package with GitHub Actions";
  - "About billing for GitHub Packages".
- `actions/attest`: <https://github.com/actions/attest>
