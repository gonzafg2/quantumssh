# ADR 0048: Run the OpenSSH interop gate on Debian forky, with OpenSSH 10.6p1 or later

- **Status:** Proposed
- **Date:** — (set on acceptance; drafted 2026-10-29)
- **Deciders:** Project lead
- **Related:** Subsidiary ADR 3 ("the interop client") of [RFC-0012](../rfcs/0012-composite-host-key-cutover.md) §Subsidiary decisions; it answers that RFC's unresolved "Interop base" question. It supersedes the trixie base and the 10.0 values of [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md), and the "Debian trixie container providing OpenSSH 10.0p1-7" bullet of [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) §Decision. ADR-0034's pinning mechanics and bump procedure stand. It moves together with [ADR-0047](0047-host-key-algorithm-ssh-mldsa44-ed25519.md) (the host key algorithm). Implementation: `.github/workflows/interop.yml`, in the RFC-0012 implementation PR.

## Context

The ADR-0020 gate drives a stock OpenSSH client against the release
binary on every PR, and is a required check
([ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md)).
ADR-0034 pins that client to `1:10.0p1-7+deb13u4` from the snapshot
its trixie image was built from. That client cannot speak
`ssh-mldsa44-ed25519`: OpenSSH 10.4 and 10.5 had only an experimental,
off-by-default form, and 10.6 (2026-10-06) is the first release that
enables the name ADR-0047 offers. After the cut-over, a 10.0 client
cannot connect at all.

Like ADR-0047, this ADR is written as `Proposed` and flips to
`Accepted` in the RFC-0012 implementation PR (RFC-0012 §Ordering).
Until then, the gate keeps ADR-0034's trixie client.

RFC-0012 left the base open: Debian sid at a snapshot, or forky once
`10.6p1` migrates. On 2026-10-29 (`madison`, tracker.debian.org):

| Suite | `openssh` |
|---|---|
| trixie | `1:10.0p1-7+deb13u4` |
| trixie-backports | `1:10.3p1-1~bpo13+1` |
| forky (testing) | `1:10.6p1-1`, migrated 2026-10-13 |
| sid | `1:10.6p1-1` |

10.6p1 is the latest OpenSSH release.

A local run on 2026-10-29 repeated ADR-0034's procedure on
`debian:forky-20261027-slim` (index digest
`sha256:04db4720574d184e24353e77e46dbbe4377edad01c9ba50a67aa1473cef9b9d4`,
amd64). The image's `debian.sources` carries its build snapshot,
`20261027T000000Z`. At that snapshot, `openssh-client=1:10.6p1-1`
installs from `forky`, `forky-updates` and `forky-security` with the
build prerequisites, and leaves `libc6` at the image's `2.43-7`. Its
`ssh -V` is `OpenSSH_10.6p1 Debian-1, OpenSSL 3.6.5 29 Sep 2026`.
`ssh -Q key` lists `ssh-mldsa44-ed25519`, and
`ssh-keygen -t mldsa44-ed25519` generates a key.

The newer client also tests something the 10.0 client cannot. OpenSSH
10.4 disconnects a peer that sends non-KEX messages during a
post-authentication re-key. The gate's `RekeyLimit` step then exercises
[ADR-0026](0026-phase-1-rekeying-policy.md)'s half-duplex window against
a client that enforces the rule.

## Decision

We will run the interop gate's client from Debian **forky**, at
OpenSSH **10.6p1 or later**, with ADR-0034's mechanics unchanged:

- **The base is a dated forky slim image, pinned by digest.** The
  initial values are the ones verified above: `debian:forky-20261027-slim`,
  `SNAPSHOT=20261027T000000Z`, `openssh-client=1:10.6p1-1`, and
  `ssh -V` asserted verbatim as
  `OpenSSH_10.6p1 Debian-1, OpenSSL 3.6.5 29 Sep 2026`. The
  implementation PR may move them to a later forky image through
  ADR-0034's bump procedure.
- **apt reads `forky`, `forky-updates` and `forky-security`** at the
  image's build timestamp, in place of the trixie suites.
- **The client floor is 10.6p1.** A bump to a client that cannot
  negotiate `ssh-mldsa44-ed25519` supersedes this ADR. It is not a
  routine bump.
- **Unchanged from ADR-0034:** the snapshot timestamp is read from the
  image and checked before apt runs, the package version is exact,
  `ssh -V` is asserted verbatim, apt uses `http` with `Signed-By`
  verification and `Check-Valid-Until` off, and an OpenSSH bump is one
  PR that moves digest, timestamp, version and `ssh -V` together.
- **When forky becomes stable,** nothing changes in the pin, because
  the snapshot is frozen. A later bump may move to the stable dated
  image of the same release.

## Consequences

### Positive

- The gate can exercise the composite host key, which the cut-over
  requires (RFC-0012 §Ordering).
- The re-key step runs against a client that enforces RFC 4253 §7.1
  during post-authentication re-keys (OpenSSH 10.4).
- The mechanics are ADR-0034's, which are already verified in CI, so
  only the suite and four values change.

### Negative

- Forky is Debian testing. Its packages move faster than a stable
  release's, so a bump can bring larger library changes (OpenSSL 3.6.5
  here, against 3.5.6 on trixie), and testing gets no security support
  from the Debian security team. The client runs in a throwaway
  container against loopback, and the snapshot freezes it between
  bumps.
- No client older than 10.6 is tested. After the cut-over, none can
  connect, and ADR-0047's negative check covers a client limited to
  `ssh-ed25519`.
- The gate still depends on snapshot.debian.org being reachable, as
  under ADR-0034.

### Neutral

- The GitHub-hosted runner and the job layout do not change. Only the
  container and its apt sources do.

## Alternatives considered

### Alternative 1: Debian sid at a snapshot

It had 10.6p1 a week before forky. Rejected: forky now has the same
version, and sid is the suite where transitions break, so a later bump
on sid is more likely to hit a broken dependency state. Forky only
takes packages that waited their migration delay without new
release-critical bugs.

### Alternative 2: trixie-backports

It keeps the stable base. Rejected: it carries `10.3p1`, which does not
offer `ssh-mldsa44-ed25519`.

### Alternative 3: Build OpenSSH 10.6p1 from source in the job

It is independent of any distribution. Rejected: it adds a build and a
tarball signature check to every run, and leaves the OpenSSL version to
the job instead of a reviewed archive state. A dated distribution
image already gives a reproducible binary, the reason ADR-0034
Alternative 1 kept the official image.

## Links

- Implementation: `.github/workflows/interop.yml` (`container.image`,
  `SNAPSHOT`, `OPENSSH_CLIENT_VERSION`, `SSH_V_EXPECTED`, apt suites).
- Superseded parts: [ADR-0034](0034-openssh-interop-client-pinned-to-image-build-snapshot.md)
  (base and values), [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md)
  §Decision (trixie bullet).
- Moves with: [ADR-0047](0047-host-key-algorithm-ssh-mldsa44-ed25519.md).
- Debian: <https://tracker.debian.org/pkg/openssh>,
  <https://snapshot.debian.org/>.
- OpenSSH 10.4 and 10.6 release notes:
  <https://www.openssh.org/releasenotes.html>.
