# ADR 0056: Ship a Homebrew tap, `gonzafg2/homebrew-quantumssh`, as a single-user evaluation path

- **Status:** Accepted
- **Date:** 2026-11-04 (accepted with the implementing PR, [gonzafg2/homebrew-quantumssh#1](https://github.com/gonzafg2/homebrew-quantumssh/pull/1), merged as `0059265` after its CI passed on `macos-26` and `ubuntu-24.04` against the published `v0.2.0`; drafted 2026-11-03)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0017](../rfcs/0017-alpha-distribution.md) §7 (Accepted 2026-11-03) and resolves its unresolved question "Updating the tap".
  - It records a departure from [ADR-0016](0016-phase-1-service-account-uid-model.md) for the tap path only.
  - Installs the artifacts of [ADR-0053](0053-release-workflow.md), with the checksums of [ADR-0054](0054-release-artifact-integrity.md).
  - Implementation: the repository [`gonzafg2/homebrew-quantumssh`](https://github.com/gonzafg2/homebrew-quantumssh), created 2026-11-04 with §1's branch protection.

> **Post-acceptance errata** (per [ADR-0015](0015-permit-annotated-errata-in-adrs.md)):
>
> - **2026-11-03** ([PR #256](https://github.com/gonzafg2/quantumssh/pull/256)):
>   §2's caveats and §4 step 4 gained one step, `chmod g-w "$(brew --prefix)/etc"`.
>   Without it the service described here cannot start on a default
>   install. For an account in the `admin` group, Homebrew's installer
>   leaves `$(brew --prefix)/etc` group-writable (mode 775), and
>   ADR-0029 refuses `config.toml`, the host key and `authorized_keys`
>   under a group-writable ancestor. `quantumssh keygen` refuses to
>   write there too (ADR-0058). This was checked with the release
>   binary on 2026-11-03. Homebrew's installer itself applies `go-w`
>   for a non-admin account, so an `etc` at mode 755 is a layout it
>   supports. The decision, its layout and its paths are unchanged.
> - **2026-11-04** (this PR, after [gonzafg2/homebrew-quantumssh#1](https://github.com/gonzafg2/homebrew-quantumssh/pull/1)):
>   the tap's first CI runs showed three steps of this ADR that do not
>   work as written. The decision, its layout and its paths are
>   unchanged.
>   - §4 step 3: Homebrew 7 refuses `brew install ./Formula/quantumssh.rb`,
>     a bare file path. CI taps the checkout and trusts it with
>     `brew trust`. Then it runs `brew style`,
>     `brew readall --os=all --arch=all`, `brew audit --strict`,
>     `brew install` and `brew test`.
>   - §4 step 4: CI creates the host key with `quantumssh keygen`
>     (ADR-0058), as the caveats tell the user to, not with
>     `ssh-keygen`. On `ubuntu-24.04`, Homebrew's `etc` carries a
>     default ACL. The umask there is 0022, but under that ACL
>     `ssh-keygen` 10.6p1 left the composite private key at mode 0644,
>     and ADR-0029 refuses a group-readable private key. `quantumssh
>     keygen` creates the file at 0600. `brew install openssh` stays,
>     for the client only.
>   - §2 "Install" and the caveats: Homebrew's `write_file` gives a new
>     file the mode that the directory's defaults allow. That same ACL
>     left `config.toml` group-writable, as a umask of 002 would, and
>     ADR-0029 refuses it. The formula sets `config.toml` to 0600 after
>     writing it. The caveats install `authorized_keys` with
>     `install -m 0644`, as `docs/deployment.md` §12 does.

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
  - resolved conversations before merge;
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
  - that `$(brew --prefix)/etc` must not be group-writable, with the
    command `chmod g-w "$(brew --prefix)/etc"`, because ADR-0029 refuses
    the configuration and both key files under a group-writable
    ancestor;
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

1. Fetch the whole pin-set bundle from this repository's `main` and
   import every key it lists (ADR-0054 §6):
   - `keys/release-keys.txt`;
   - `keys/security.asc`;
   - `keys/retired/*.asc`.

   Check the current fingerprint against the value pinned in the
   workflow. ADR-0057's rotation and compromise steps update that pin.
2. Run `scripts/verify-download.sh <version>`, fetched from the same
   `main`, for the formula's version. It implements ADR-0054 §7 in full,
   retired-key branch included, so older releases and rotations stay
   checkable. A bare `gpg --verify` would pass for a revoked key. Then
   fail unless each `sha256` in the formula equals its line in the
   verified `SHA256SUMS`.
3. `brew install ./Formula/quantumssh.rb` and `brew test quantumssh`.
4. Run the service end to end:
   - `chmod g-w "$(brew --prefix)/etc"`, as the caveats tell the user
     to;
   - `brew install openssh`, because neither runner's own OpenSSH can
     create the composite key;
   - generate the host key with
     `"$(brew --prefix openssh)/bin/ssh-keygen" -t mldsa44-ed25519`;
   - generate an Ed25519 client key and install its `.pub` as
     `authorized_keys`; the server refuses to start without one;
   - start the service;
   - wait until `127.0.0.1:2222` accepts a connection;
   - run `"$(brew --prefix openssh)/bin/ssh" … true`, which must exit
     0.

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
