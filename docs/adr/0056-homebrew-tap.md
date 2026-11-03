# ADR 0056: Ship a Homebrew tap, `gonzafg2/homebrew-quantumssh`, as a single-user evaluation path

- **Status:** Proposed
- **Date:** TBD (accepted with the implementing PR)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §7 (Accepted 2026-11-03) and resolves its unresolved question "Updating the tap".
  - It records a departure from [ADR-0016](0016-phase-1-service-account-uid-model.md) for the tap path only.
  - Installs the artifacts of [ADR-0053](0053-release-workflow.md), with the checksums of [ADR-0054](0054-release-artifact-integrity.md).
  - Implementation: the new repository `gonzafg2/homebrew-quantumssh`.

## Context

RFC-0017 chose a tap over homebrew-core, which needs a stable upstream
version and more notability than the project has, and over a cask,
which Homebrew expects to pass Gatekeeper. The tap installs the attested
release tarball. Under `brew services` it runs the server as the user
who started it. That departs from ADR-0016:

- **ADR-0016:** a dedicated `quantumssh` account, with root-owned
  configuration and `authorized_keys`.
- **The tap:** the operator's own account, which owns its trust anchors.

RFC-0017 accepted the departure, labelled as an evaluation path.

## Decision

We will publish a tap with one formula, `quantumssh`, that installs the
release tarball for the platform and a Homebrew-path configuration,
runs under `brew services` as the invoking user, and is updated by a
reviewed pull request per release.

### 1. Repository

- **Repository:** `gonzafg2/homebrew-quantumssh`, Apache-2.0.
- **Branch protection on `main`** matches this repository's
  (`docs/infrastructure.md` §"Branch protection on `main`"):
  - signed commits;
  - linear history;
  - changes only through a pull request;
  - no force push and no deletion;
  - `enforce_admins: true`;
  - required status checks: §4's jobs on both runners. The checksum
    verification of step 2 is one of them, so a formula whose `sha256`
    does not match the signed `SHA256SUMS` cannot merge.
- **Contents:** `Formula/quantumssh.rb`, a README stating the
  evaluation-path scope, and CI.

### 2. Formula

- **URLs.** On macOS arm64, and on Linux `x86_64` and arm64, the formula
  downloads `quantumssh-<v>-<target>.tar.gz` from the GitHub release,
  each with its `sha256`.
- **Unsupported platforms.** Any other platform fails at install with a
  message that names RFC-0017's tiers. There is no source build fallback.
- **Install.**
  - `bin.install "quantumssh"`.
  - A `config.toml` goes under `etc/"quantumssh"`. Its paths point inside
    that directory, and its `listen` is `127.0.0.1:2222`.
  - Homebrew keeps an existing file under `etc` on upgrade, so the
    operator's edits survive.
- **Service.**

  ```
  service do
    run [opt_bin/"quantumssh", "--config", etc/"quantumssh/config.toml"]
    keep_alive true
    log_path var/"log/quantumssh.log"
    error_log_path var/"log/quantumssh.log"
  end
  ```

  The log is JSON because stderr is not a TTY (ADR-0024).
- **Test.** `test do` asserts that `quantumssh --version` prints the
  formula's version.
- **Caveats** state:
  - that this is a single-user evaluation path that departs from
    ADR-0016: the account owns its trust anchors and sessions carry its
    authority;
  - the OpenSSH ≥ 10.6 client floor, and that the Homebrew `ssh` is run
    by full path after `brew unlink openssh`;
  - how to create the host key and `authorized_keys`;
  - the link to the Linux deployment guide as the supported posture.
- **No `depends_on "openssh"`** (RFC-0017 §7).

### 3. Updating the tap

Each release is a manual pull request to the tap:

- The maintainer copies the three `sha256` values from the PGP-verified
  `SHA256SUMS` of the published release, never from a fresh download.
- The tap's CI checks them before it installs anything.
- No token for the tap is stored in this repository. An automated bump
  would need a cross-repository write credential, and for a few releases
  a year it would not pay for that credential.

### 4. Tap CI

On every pull request, on a macOS arm64 runner and on `ubuntu-24.04`:

1. Fetch `keys/security.asc` from this repository's `main`, check its
   fingerprint against the value pinned in the workflow, and import it.
2. Download `SHA256SUMS` and `SHA256SUMS.asc` for the formula's version,
   run the pinned signature check of ADR-0054 §7 (a bare `gpg --verify`
   would pass for a revoked key), and fail unless each `sha256` in the
   formula equals its line.
3. `brew install ./Formula/quantumssh.rb` and `brew test quantumssh`.
4. Generate a host key with the Homebrew `ssh-keygen`, start the
   service, and wait until `127.0.0.1:2222` accepts a connection.

## Consequences

### Positive

- Homebrew users can install with
  `brew install gonzafg2/quantumssh/quantumssh`, which also grants
  Homebrew 6's tap trust for that formula.
- `brew install` checks the same bytes that were attested and signed.
- The tap holds no secret.

### Negative

- It is a second repository to protect, and a compromised formula would
  redirect users. RFC-0017 §11 lists this as a non-defence. It is
  narrowed by branch protection, which includes admins, and by the
  required checksum check of §4 step 2. Neither defends against a
  compromise of the maintainer's own GitHub account.
- Each release needs a manual tap pull request.
- The evaluation path is weaker than the Linux deployment, and some
  users will run it as a real server anyway.

### Neutral

- Linux Homebrew users get the same formula. Homebrew's own tiers
  govern their glibc (RFC-0017's client-floor table).

## Alternatives considered

### Alternative 1: a LaunchDaemon with a dedicated macOS account

It would honour ADR-0016, but it needs `sudo`, a `dscl`-created account
and root-owned configuration in the formula. The project lead chose the
labelled evaluation path for the alpha.

### Alternative 2: build from source in the formula

That needs `depends_on "rust" => :build` and installs a toolchain, and
the bytes would differ from the attested ones.

### Alternative 3: automated tap bumps from `release.yml`

It needs a token that can write to the tap, held in this repository.
Deferred until releases are frequent enough to justify it.

## Links

- [RFC-0017](../rfcs/0017-alpha-distribution.md) §6, §7, §11
- [ADR-0016](0016-phase-1-service-account-uid-model.md), [ADR-0024](0024-phase-1-log-event-schema.md)
- Homebrew: `Formula-Cookbook.md` (`service do`), `Tap-Trust.md`
