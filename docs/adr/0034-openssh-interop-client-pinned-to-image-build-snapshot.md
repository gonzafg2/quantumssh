# ADR 0034: Pin the OpenSSH interop client to the snapshot its image was built from

- **Status:** Accepted
- **Date:** 2026-09-23 (accepted on merge of [#161](https://github.com/gonzafg2/quantumssh/pull/161))
- **Deciders:** Project lead
- **Related:** Implements the package-version bullet of [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) §Decision ("`openssh-client` is installed with an explicit version from a frozen source") and supersedes its asserted-version bullet ("`ssh -V` … must contain `OpenSSH_10.0p1`") with the exact string of the pinned package; every other bullet of ADR-0020 stands. The gate is a required check under [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md), which is what makes a floating client a problem for every PR. Implementation: `.github/workflows/interop.yml` (lands in the same PR).

## Context

ADR-0020 decided two pins for the interop gate: the container image by
digest, and `openssh-client` at an explicit version from a frozen
source. Only the first was implemented ([#84](https://github.com/gonzafg2/quantumssh/pull/84));
the package came from the live trixie mirror, and the job asserted the
`10.0p` line of `ssh -V` after trixie moved the binary from 10.0p1 to
10.0p2 under the same source version. ADR-0020's literal `OpenSSH_10.0p1`
was already behind trixie when the ADR was accepted
([#86](https://github.com/gonzafg2/quantumssh/issues/86) recorded it and
deferred the pin as a follow-up).

[#98](https://github.com/gonzafg2/quantumssh/pull/98) tried the pin and
was closed after six CI iterations: it pointed apt at a snapshot
(`20260507T000000Z`) *older* than the image, whose `libc6` was already
`2.41-12+deb13u3`; that snapshot could not satisfy `libc6-dev`'s exact
dependency, and mixing the two states is unsatisfiable by construction.

Since [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md)
the gate blocks every merge, with no admin bypass (ADR-0008). A client
that floats with the mirror can turn every open PR red for a reason that
is not in any PR — exactly the property ADR-0020 set out to prevent.

A local reproduction on 2026-09-22, in the exact digest-pinned image
(`debian:trixie-20260623-slim`, amd64), established the rule that #98
missed: the image's own `/etc/apt/sources.list.d/debian.sources` carries,
commented out, the snapshot timestamp the image was built from
(`20260623T000000Z`). Pointing apt at *that* timestamp installs
`openssh-client=1:10.0p1-7+deb13u4` with no change to `libc6`, and
`ssh -V` reads `OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026`.
Two later timestamps (one day and three months after) also install the
same package version, but upgrade `libc6` and OpenSSL underneath it and
change the `ssh -V` string; an earlier one fails as #98 did. Pinning the
package version alone therefore does not freeze the client: the
timestamp and the version pin together, and the timestamp is not a
choice — it is read from the image. `trixie-security` offered only an
older `openssh-client` at every timestamp; `+deb13u4` comes from
`trixie/main` (point release 13.5). No throttling from
snapshot.debian.org was observed; downloads were about twice as slow as
the live mirror from that network.

## Decision

We will install the interop client from the snapshot.debian.org archive
state the image was built from, at an exact version, and assert the
exact client string:

- **The snapshot timestamp is the image's build timestamp**, read from
  the image's own `debian.sources` and checked by the step before apt
  runs: a `SNAPSHOT` that does not match the image fails the job. The
  image stays pinned by digest; the digest is the dated tag it resolves
  to (`debian:trixie-20260623-slim` today), named in the comment.
- **`openssh-client` is installed at an explicit version**
  (`1:10.0p1-7+deb13u4`), together with the build prerequisites, from
  `trixie`, `trixie-updates` and `trixie-security` at that timestamp.
- **`ssh -V` is asserted verbatim** against the pinned build's string,
  which includes the OpenSSL build: the assertion now pins the library
  too. This supersedes ADR-0020's "must contain `OpenSSH_10.0p1`".
- **Transport and validity:** the snapshot is fetched over `http`, since
  the slim image ships no CA bundle and fetching one from the live mirror
  first is the mixed state #98 failed on; apt verifies the archive's
  Release signatures (`Signed-By`), so TLS would add confidentiality
  only. `Acquire::Check-Valid-Until` is off, because the archived Release
  files of `trixie-updates` and `trixie-security` are past their
  seven-day validity.
- **One bump procedure.** An OpenSSH bump is one PR that moves the four
  values together: new digest → its build timestamp into `SNAPSHOT` →
  the package version that snapshot resolves → the `ssh -V` string it
  prints. Nothing in the job floats.

## Consequences

### Positive

- The client is frozen: base filesystem, package and OpenSSL come from
  one archive state. A change in OpenSSH's wire behaviour reaches the
  gate only through a reviewed bump, as ADR-0020 intended.
- The `ssh -V` assertion becomes exact instead of a `10.0p` pattern, and
  the failure message names the expected string.
- The bump rule is verifiable from the image itself; the mistake #98
  made cannot be repeated without the job saying so.

### Negative

- The gate now depends on snapshot.debian.org being reachable, a second
  host next to the GitHub runner; `Acquire::Retries` is set, and a
  snapshot outage turns the required check red until it recovers, the
  same class of dependency as the live mirror had.
- Downloads are slower than from the CDN mirror (about twice, measured
  locally); the job's apt step is a small share of its runtime.
- The bump is manual: Dependabot does not track container digests or
  `env:` values here. It was manual before this ADR as well.

### Neutral

- `trixie-security` stays in the sources for symmetry with the image's
  original configuration; it contributes nothing to this pin today.

## Alternatives considered

### Alternative 1: Build the container `FROM` a snapshot with a Dockerfile

Consistent by construction, as #98's closing note suggested. Rejected
because it adds an image build (or a published image) to every run for
the same result: the official dated image already *is* a snapshot build,
and its timestamp is readable from inside it.

### Alternative 2: Vendor the `.deb`

Frozen and mirror-independent. Rejected: a binary artefact in the repo,
plus its dependency closure to keep consistent with the image, and a
manual chain of custody for each bump.

### Alternative 3: Keep the live mirror and the `10.0p` assertion

The state before this ADR. Rejected: it is the pin ADR-0020 decided not
to leave floating, and ADR-0031 made the gate a merge blocker for every
PR.

## Links

- Implementation: `.github/workflows/interop.yml` ("Install OpenSSH
  client + build prerequisites", `SNAPSHOT`, `OPENSSH_CLIENT_VERSION`,
  `SSH_V_EXPECTED`).
- Prior attempt and its diagnosis: [#98](https://github.com/gonzafg2/quantumssh/pull/98).
- Related ADRs: [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md)
  (implemented and partly superseded),
  [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md).
- Debian snapshot archive: <https://snapshot.debian.org/>.
