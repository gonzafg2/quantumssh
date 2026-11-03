# RFC 0017: Alpha distribution — prebuilt binaries, a Homebrew tap, support tiers and the OpenSSH 10.6 floor

- **Status:** Draft
- **Authors:** Gonzalo Fleming Garrido
- **Created:** 2026-11-03
- **Roadmap issue:** [#248](https://github.com/gonzafg2/quantumssh/issues/248) (Phase 3)
- **Implementation PR:** TBD

## Summary

`0.1.0` shipped as source only: to run QuantumSSH you build it with
Cargo. From `0.2.0` on, each release also ships:

- **Prebuilt binaries:** static Linux binaries linked against musl for
  `x86_64` and `aarch64`, and a macOS binary for `arm64`.
- **One binary per target, everywhere:** every target is built from the
  signed tag on a native GitHub runner. Each tarball and the SBOM carry a
  GitHub build-provenance attestation. A `SHA256SUMS` file lists them, and
  the maintainer signs it with the project PGP key. The release is then
  published as an immutable release. The interop gate runs against these
  exact bytes before they are published, and the signed `SHA256SUMS` must
  list exactly the digests the gate tested.
- **A Homebrew tap,** `gonzafg2/homebrew-quantumssh`, that installs those
  same bytes on macOS and on Homebrew-on-Linux and runs the server under
  `brew services`.

The RFC also:

- defines support tiers and binds Tier 1 to the interop gate;
- states OpenSSH 10.6 as the client floor on every platform;
- names WSL2 as the only Windows path until a native port has its own RFC;
- leaves host-key generation to RFC-0018
  ([#249](https://github.com/gonzafg2/quantumssh/pull/249)), which this
  RFC does not depend on;
- amends the `README.md` roadmap and threat model §5.5.2 and §6.4,
  because it moves part of Phase 4 ("Distribution packages") forward and
  ships binaries before Phase 3's reproducible builds.

## Motivation

**Building from source is the only way in.** An operator who wants to try
the alpha needs a Rust toolchain at the pinned channel and a release
build of the workspace before reading a line of `docs/deployment.md`.
Most people evaluating an SSH server expect to download a binary or run a
package manager.

**Host-key generation is a separate problem.** Step 3 of the operator
guide needs `ssh-keygen` 10.6, which many server distributions lack (see
the client-floor table below). That is true for source builds as well as
binaries, so it is decided in its own RFC, RFC-0018
([#249](https://github.com/gonzafg2/quantumssh/pull/249)), as
`docs/rfcs/README.md` §"Scope: one decision per RFC" requires. Until
RFC-0018 lands, this RFC's install guide keeps `ssh-keygen` 10.6.

**Binaries are an asset the threat model already names.** §5.5.2.b lists
"what binaries ship under the project's name" among the assets a
compromised maintainer controls. §5.5.2 and §6.4 defer reproducible
builds and the SBOM to Phase 3, behind an RFC. Shipping binaries without
saying how they are produced and verified would add an unstated trust
assumption. This RFC states it.

**People ask about Windows, and native Windows does not build.**
`cargo check --workspace` fails on both `x86_64-pc-windows-msvc` and
`aarch64-pc-windows-msvc`, with 48 errors in `quantumssh-core`.
`pty.rs`, `sftp.rs` and `exec.rs` use `rustix::{fs,process,pty,termios}`
and `std::os::unix`. The binary adds Unix-permission StrictModes
(ADR-0029), systemd notification (ADR-0043) and Unix signals. Windows
needs an explicit answer, not silence.

**The client floor needs to be written down per platform.** RFC-0012 set
OpenSSH 10.6 as the floor. In practice:

- macOS 27 ships OpenSSH 10.5p1. It knows only the experimental
  `ssh-mldsa44-ed25519@openssh.com` name, so the handshake fails with
  "no matching host key type found".
- Windows 11 25H2 ships `OpenSSH_for_Windows_9.5p2`, which offers no
  post-quantum key exchange at all. Win32-OpenSSH added
  `mlkem768x25519-sha256` and `sntrup761x25519-sha512` only in
  10.0.0.0p2-Preview (2025-10-27).
- The newest Win32-OpenSSH, 10.4.0.0p1-Preview (2026-10-20), predates
  10.6.

## Guide-level explanation

### Support tiers

| Tier | What the project promises | Targets |
|---|---|---|
| **1** | A published binary; the test suite in CI; a release-blocking interop job run against **the published binary** with a **pinned** OpenSSH ≥ 10.6 client | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` |
| **2** | A published binary; the test suite in CI; a release-blocking interop job whose OpenSSH ≥ 10.6 client is not yet pinned | `aarch64-apple-darwin` (becomes Tier 1 once its client is pinned; see Unresolved questions) |
| **Unsupported, with a documented path** | No binary. Nothing is promised | Windows on `x86_64` and `arm64`, through WSL2 with the Linux binary; macOS on Intel, built from source, with no runner to test it on |

### The client floor

Every client must be **OpenSSH 10.6 or newer**, on every platform. There
is no fallback. An older client fails with "no matching host key type
found. Their offer: ssh-mldsa44-ed25519", and the documentation says so
in those words.

The install guide lists where 10.6 comes from:

| Platform | How to get OpenSSH ≥ 10.6 |
|---|---|
| Arch, Alpine edge, Debian forky or sid, Fedora rawhide, openSUSE Tumbleweed, Void, NixOS 26.05 | The distribution package |
| Ubuntu (every release), Debian 13, Fedora 44 | Homebrew on Linux (`openssh` 10.6p1 has `x86_64_linux` and `arm64_linux` bottles). It is Homebrew's Tier 1 at glibc ≥ 2.39. On Ubuntu 22.04 (glibc 2.35) Homebrew installs its own glibc and supports it only at Tier 2 |
| RHEL 9 and rebuilds (glibc 2.34), openSUSE Leap | No supported route. Homebrew's Tier 2 (its own glibc, bottles "may be unavailable or fail to install") is best effort only. The server side waits for RFC-0018's `keygen`, or for a distribution OpenSSH ≥ 10.6. The guide does not suggest generating the key on another machine |
| macOS (arm64) | Homebrew `openssh`, used by full path or after `brew unlink openssh`, so the system `ssh` stays in place |
| Windows | A client inside WSL2. No native Windows build of 10.6 is known to work |

### Installing on Linux

`gpg --verify` means something only once the project key is imported and
its fingerprint checked, as `SECURITY.md` shows. That comes first:

```sh
gh release download v0.2.0 -R gonzafg2/quantumssh -p 'quantumssh-0.2.0-x86_64-unknown-linux-musl.tar.gz' -p 'SHA256SUMS*'
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify quantumssh-0.2.0-x86_64-unknown-linux-musl.tar.gz -R gonzafg2/quantumssh \
  --signer-workflow gonzafg2/quantumssh/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.0 --deny-self-hosted-runners
tar -xzf quantumssh-0.2.0-x86_64-unknown-linux-musl.tar.gz
sudo install -m 0755 quantumssh-0.2.0-x86_64-unknown-linux-musl/quantumssh /usr/local/bin/quantumssh
```

The rest of `docs/deployment.md` is unchanged: the service account, the
StrictModes layout, the host key (step 3, `ssh-keygen` 10.6, from the
client-floor table when the distribution lacks it), the configuration
file and the systemd unit. If RFC-0018 is accepted, `quantumssh keygen`
replaces the `ssh-keygen` line.

### Installing on macOS

```sh
brew install gonzafg2/quantumssh/quantumssh openssh
brew unlink openssh
E="$(brew --prefix)/etc/quantumssh"
"$(brew --prefix openssh)/bin/ssh-keygen" -t mldsa44-ed25519 -N '' -f "$E/ssh_host_mldsa44_ed25519_key"
install -m 0644 ~/.ssh/id_ed25519.pub "$E/authorized_keys"
brew services start quantumssh
"$(brew --prefix openssh)/bin/ssh" -p 2222 "$USER@127.0.0.1"
```

The formula installs `$(brew --prefix)/etc/quantumssh/config.toml`. Its
paths point inside that directory, its `listen` is `127.0.0.1:2222`, and
it is not overwritten on upgrade. The client is the Homebrew `ssh`, by
full path. After `brew unlink`, a plain `ssh` is macOS's 10.5p1, which
does not connect.

**This is a single-user evaluation path, not ADR-0016's posture.**
`brew services` runs the server as the user who started it. On macOS that
is usually an administrator account, and it owns the configuration under
`$(brew --prefix)/etc/quantumssh/`, including `authorized_keys`. ADR-0016
runs the server as a dedicated `quantumssh` account. The configuration
and `authorized_keys` are owned by root so that the account cannot change
them (`docs/deployment.md` §3). On the Homebrew path the server's account
can rewrite its own trust anchors, and sessions carry that user's full
authority. The guide says this in those terms. The supported server
posture stays the Linux deployment.

### Windows

QuantumSSH does not run natively on Windows. On Windows 10 or 11 with
WSL2, the guide:

- installs a distribution, with `wsl --install archlinux` recommended
  because Arch already ships OpenSSH 10.6;
- turns on systemd where the distribution does not, with
  `[boot] systemd=true` in `/etc/wsl.conf`;
- follows the Linux steps with the binary for the machine's
  architecture.

In the default NAT mode, Windows itself reaches the server on
`localhost`. Reaching it from the LAN takes mirrored networking and a
Hyper-V firewall rule. A systemd service does not keep a WSL instance
running, and the guide says so.

## Reference-level explanation

### 1. Tiers are bound to the interop gate

A target is Tier 1 only while two things hold:

- the interop gate (ADR-0020) runs as a **release-blocking job** in
  `release.yml` against the artifact the release publishes for that
  target;
- that job uses a pinned client, as ADR-0020 pins its own.

"Release-blocking" means §4's stop conditions. It is not a
branch-protection required check, because a tag-triggered workflow never
reports on a pull request. The PR-time interop gate stays the required
check it is today (ADR-0031). A target cannot be listed as Tier 1
because a different build of the same source passed. Losing the gate
drops a target to Tier 2 in the next release notes.

### 2. Targets and build

| Target | Runner | Notes |
|---|---|---|
| `x86_64-unknown-linux-musl` | `ubuntu-24.04` | Static; Rust's self-contained musl linking |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | Static; native arm64 runner, free for public repositories since 2025-08 |
| `aarch64-apple-darwin` | macOS arm64 runner | Ad-hoc signature from the linker; not notarized (§6) |

- **Build settings.** Every target is built with
  `rustup target add <target>` and then
  `cargo build --release --locked -p quantumssh --target <target>`, on
  the toolchain `rust-toolchain.toml` pins. The explicit `--target`
  matters: without it, a Linux runner builds its host's glibc target.
  No target is built for an architecture other than its runner's, and no
  release generator (dist, GoReleaser) is used. The release profile does
  not change.
- **Static-link check, fail closed.** Before anything is attested, each
  Linux binary must show no `NEEDED` entry and no `PT_INTERP` program
  header (`readelf -d` and `readelf -l`). It must also run `--version`
  inside an Alpine container pinned by digest, as the project's gate
  containers are (ADR-0020, ADR-0048), with the binary mounted
  read-only. A dynamically linked binary stops the workflow.
- **Allocator.** musl's default allocator is kept. Its known ceiling is
  lock contention under many concurrent connections, and the admission
  caps (ADR-0028) bound that load. The workflow marks it with a
  `ponytail:` comment. The upgrade path is a global allocator such as
  mimalloc, which is a new dependency and would need its own ADR.
- **macOS on Intel.** Not built. Rust demoted `x86_64-apple-darwin` to
  Tier 2 in 1.90 after GitHub ended free Intel macOS runners, and the
  project would ship it untested.

### 3. Artifacts

Per target there is `quantumssh-<version>-<target>.tar.gz`, containing a
directory of the same name with:

- the `quantumssh` binary;
- `LICENSE`, `README.md` and `CHANGELOG.md`;
- `contrib/systemd/quantumssh.service`;
- an example `config.toml`, copied from `docs/deployment.md` §4, with
  `/etc/quantumssh` paths. The tap installs its own copy with Homebrew
  paths (§7).

Per release:

- `SHA256SUMS`, listing every tarball and the SBOM;
- `SHA256SUMS.asc`, a detached PGP signature over `SHA256SUMS`;
- `quantumssh-<version>.cdx.json`, a CycloneDX SBOM of the `quantumssh`
  dependency graph.

Every tarball and the SBOM also carry a GitHub build-provenance
attestation, stored by GitHub. Verifying one means pinning everything
the attestation records:

- the signer workflow, `.github/workflows/release.yml`, the release
  workflow this RFC adds (§4);
- the source ref, `refs/tags/vX.Y.Z`;
- a GitHub-hosted runner (`--deny-self-hosted-runners`).

A check with only `-R gonzafg2/quantumssh` would accept an attestation
from any workflow in the repository on any ref, including a branch or
the `rehearsal-*` tags used to rehearse a release (§4). That check is
not the one documented.

### 4. Release procedure

From `0.2.0` on, a release follows these steps in order:

1. **Tag.** The maintainer signs and pushes the annotated tag
   `vX.Y.Z` with the project PGP key, as for `v0.1.0`. A repository
   ruleset protects `v*` tags: only the maintainer may create one, and no
   tag can be moved or deleted.
   - **A failed release consumes its version.** If the build or a gate
     fails, the draft is discarded, the tag stays, and the fix ships as
     the next patch version with a CHANGELOG note. A tag never points at
     two different releases.
   - **Rehearsals use another namespace.** They use `rehearsal-*` tags,
     outside the `v*` ruleset. Their attestations name a `rehearsal-*`
     ref, so the user check (`--source-ref refs/tags/vX.Y.Z`) rejects
     them.
2. **Build.** `.github/workflows/release.yml`, triggered by the tag,
   fails before building unless the tagged commit is reachable from
   `main`. It then builds §2's targets, assembles §3's artifacts, attests
   them and creates a **draft** release carrying them. Each kind of work
   is its own job with only the permissions it needs:
   - **build:** `contents: read`, with no OIDC and no attestation
     permission, and `persist-credentials: false` on checkout. A
     compromised build script (threat model §5.5.2.a) therefore runs
     with nothing to mint or publish;
   - **attest:** `id-token: write` and `attestations: write`. It
     downloads the exact artifacts the gates passed and runs no project
     code;
   - **publish:** `contents: write`. It only creates the draft and
     uploads the assets. The workflow's own
   check is a tripwire, not a guarantee: a tag on an unreviewed commit
   runs that commit's copy of the workflow. Step 4 is the check that
   counts.
3. **Gates on the bytes.**
   - **What runs.** The interop gate and the systemd reference-unit test
     (ADR-0043) run the Linux binaries, and an interop job on the macOS
     runner runs the macOS binary.
   - **Least privilege.** Gate jobs hold only `contents: read`. They never
     have `id-token: write` or `attestations: write`, so a binary a gate
     executes cannot mint an attestation under the release workflow's
     identity.
   - **Only bytes whose origin was checked.** The planned release-workflow
     ADR (§12) picks one of two orders:
     - **Preferred:** the gates run on the build job's workflow artifacts
       before any draft exists, and only bytes that passed are attested
       and uploaded;
     - **Otherwise:** each gate verifies the downloaded asset's
       attestation with the pins of §3 before executing it.
   - **Digests.** Each gate job records the SHA-256 of every tarball it
     ran.
   - **Stop conditions.** A red gate, or a missing or failed provenance
     check, stops the release.
4. **Verify and sign.** In a local terminal, the maintainer:
   - verifies the tag with `git tag -v vX.Y.Z` against the project key,
     and checks that the tagged commit is an ancestor of `main`
     (`git merge-base --is-ancestor`);
   - downloads the draft's assets;
   - runs `gh attestation verify` on every tarball and the SBOM, with the
     pins of §3, and checks that the commit each attestation names is the
     tagged commit;
   - **recomputes** the checksums of those verified files into a local
     `SHA256SUMS`. The release stops unless that file is byte-identical
     to the copy CI uploaded, and unless its tarball lines equal the
     digests the gates recorded in step 3;
   - signs the local `SHA256SUMS` with the project PGP key, checks the
     new signature with `gpg --verify`, and uploads `SHA256SUMS.asc` to
     the draft.

   Signing the CI copy without recomputing it would let anyone able to
   edit the draft swap one line of `SHA256SUMS` and get it signed.
   Comparing against the gates' digests keeps an ungated re-upload from
   being signed. If any asset changes after step 3, steps 3 and 4 run
   again.
5. **Publish.** The draft is published. The repository's
   immutable-releases setting is on, so the tag and the assets are
   locked from then on and GitHub attaches a release attestation
   (`gh release verify`). Zenodo archives the release as before.
6. **Tap.** The tap's formula is updated to the new version and
   checksums, and the tap's CI must be green.

RFC-0015 §5 listed the preconditions for the `0.1.0` tag. Steps 3 to 5
are the standing preconditions for every later release.

### 5. Who signs what

| Object | Signed by | Mechanism |
|---|---|---|
| Commits on `main` | The author's SSH key | ADR-0006, unchanged |
| Release tags | The project PGP key, `66DB 5100 B070 0E4A E051 971F 9A8D FF06 AFD2 5B24` | `git tag -s`. This records the practice `v0.1.0` started |
| `SHA256SUMS` | The same PGP key | `gpg --detach-sign --armor` |
| Build provenance | GitHub Actions' OIDC identity, keyless, through Sigstore | `actions/attest-build-provenance` |

ADR-0006 keeps PGP for embargoed disclosure and moves commit signing to
SSH, "one keypair per purpose". This RFC adds a release-signing role to
the same key, the one `SECURITY.md` publishes, so a user verifies one key
for both the source tag and the binaries. That broadens an accepted
decision. A planned subsidiary ADR (§12) records the role, supersedes
ADR-0006's disclosure-only wording, and states what a compromise or a
rotation of the key (ADR-0005) means for releases already published. The PGP signature is made in the maintainer's
terminal, because the key's passphrase needs a TTY. The PGP private key
is never given to CI.

### 6. macOS without notarization

The macOS binary is not notarized and the project does not join the
Apple Developer Program.

- **Downloads through brew and curl are not quarantined.** Homebrew and
  `curl` do not set `com.apple.quarantine`, so Gatekeeper does not assess
  the binary. The linker gives arm64 code the ad-hoc signature it needs
  to run.
- **Browser downloads are.** A browser sets the attribute and Gatekeeper
  blocks the file. The release notes and the install guide say to use the
  tap or `curl`. They never tell the user to strip the quarantine
  attribute.

### 7. The Homebrew tap

- **Repository:** `gonzafg2/homebrew-quantumssh`, Apache-2.0. It is
  created once this RFC is accepted.
- **Branch protection:** signed commits, same as this repository.
- **Formula:** one formula, `quantumssh`. On macOS arm64 and on Linux
  `x86_64` and `aarch64`, it downloads the release tarball for the
  platform, with its `sha256` fixed in the formula. That `sha256` is copied
  from the maintainer-signed `SHA256SUMS`, never computed from a download.
  The formula also installs a `config.toml` under `#{etc}/quantumssh/`.
  Its paths point inside that directory, its `listen` is
  `127.0.0.1:2222`, and it is never overwritten on upgrade. Another
  platform gets an install error naming the supported tiers. It does not fall back to a
  source build.
- **Service:** a `service do` block runs
  `quantumssh --config #{etc}/quantumssh/config.toml` with `keep_alive`,
  as the user who runs `brew services`. That makes the tap the
  single-user evaluation path described under Guide-level, a recorded
  departure from ADR-0016 that the planned tap ADR (§12) carries. The
  formula's `caveats` repeat it.
- **No `depends_on "openssh"`.** Installing the server must not replace
  the `ssh` the user already has. The client floor goes in the formula's
  `caveats`.
- **CI:** the tap's CI does two things on macOS arm64 and on Linux:
  - before installing, it checks the formula's checksums against the
    release's `SHA256SUMS`, after `gpg --verify` of `SHA256SUMS.asc` with
    the project key;
  - it then runs `brew install`, `brew test` (`quantumssh --version`) and
    a `brew services` start.
- **homebrew-core is out of scope.** Its acceptance policy needs upstream
  to call the version stable, and a self-submission needs 225 stars, or
  90 forks or 90 watchers.

### 8. Host-key generation

Host-key generation is decided in RFC-0018
([#249](https://github.com/gonzafg2/quantumssh/pull/249)), not here.
Nothing in this RFC depends on it. If RFC-0018 is accepted, the install
guide and the tap's `brew test` start using `quantumssh keygen`. Until
then they use `ssh-keygen` 10.6.

### 9. Windows

- **No native build.** No Windows target is built, attested or
  published, and no winget manifest is submitted.
- **What it would take** is a separate RFC: a port to ConPTY, Job
  Objects, ACL-based StrictModes and the Service Control Manager, through
  crates that wrap Win32 safely, because first-party `unsafe` stays
  forbidden (ADR-0018). That RFC needs an interop job on a Windows runner,
  then a winget package: a portable zip first, then an MSI to register a
  service.
- **The WSL2 guide** (§ Guide-level) is tested by hand on Windows 11
  before each release, because no CI runner offers WSL2. The release
  notes say which release it was last checked against.

### 10. Changes to other documents

| Document | Change |
|---|---|
| `README.md`, roadmap | Phase 3 gains "Prebuilt binaries (Linux x86_64/aarch64, macOS arm64) with provenance, and a Homebrew tap (RFC-0017)". Phase 4's "Distribution packages (Debian, Arch, Alpine, Homebrew)" becomes "(Debian, Arch, Alpine, homebrew-core)" |
| `docs/threat-model.md` §5.5.2 | The test handle names this RFC's release controls next to `cargo deny` |
| `docs/threat-model.md` §6.4 | A new control, "Release provenance (RFC-0017)". See §11 |
| `docs/deployment.md` | Step 1 downloads and verifies a release. Step 3 points at the client-floor table for `ssh-keygen` 10.6. A new section covers WSL2, and another the Homebrew path as single-user evaluation |
| `SECURITY.md` | The verification recipe covers the release assets as well as the tag |

The README is a commitment document, so its roadmap changes through this
RFC rather than an ADR.

### 11. Threat-model statement

The new §6.4 control reads, in substance:

> **Release provenance (RFC-0017).**
>
> *Defends against:*
> - substitution of a release asset after publication (immutable
>   releases);
> - an asset built outside the project's workflow. A provenance
>   attestation binds each tarball and the SBOM to the workflow file, the
>   commit and the tag that produced it;
> - a release tag pushed with a stolen write credential to an unreviewed
>   commit. The tag ruleset narrows who can push one. Before signing
>   `SHA256SUMS`, the maintainer checks the tag's PGP signature and that
>   the attested commit is on `main` (§4 step 4);
> - an asset swapped between CI and publication (`SHA256SUMS` signed by
>   the maintainer, who first checks the attestations and recomputes the
>   checksums from the verified files and the digests the gates
>   tested, §4 step 4). Gates run with read-only permissions, only on
>   bytes whose origin was checked (§4 step 3).
>
> *Does **not** defend against:*
> - a compromise of the release workflow itself or of GitHub Actions;
> - a maintainer who tags malicious source;
> - a compromise of the project PGP key. The planned signing ADR (§12)
>   covers revocation, rotation (ADR-0005) and what they mean for
>   releases already signed;
> - a user who checks only the attestation and not `SHA256SUMS.asc`.
>   That user gets no check of the tag signature;
> - a compromise of the tap repository or its formula. `brew install`
>   trusts the formula's `sha256`, not the PGP signature. The tap's
>   branch protection and CI check (§7) narrow this, and a user who wants
>   the full chain verifies the tarball as on Linux.
>
> It is not a substitute for reproducible builds. Those stay Phase-3
> work, and they are what would let a third party rebuild an asset and
> compare it.

Attestations give SLSA Build Level 2. Level 3 needs the build in a
reusable workflow, and the planned release-workflow ADR (§12) will
decide whether to move there.

### 12. Subsidiary ADRs (planned)

None of these ADRs exists yet. They are written after this RFC is
accepted. The numbers are the next free ones today and may shift, since
numbering follows merge order.

| ADR | Decision |
|---|---|
| ADR-0053 | The release workflow: §2's matrix, runners, pinned actions and static-link check; the build / attest / publish job split and their permissions; the `v*` tag ruleset; the ancestry tripwire; the gates' digest records; the draft → gates → sign → publish flow of §4; and whether the build moves to a reusable workflow for SLSA Build Level 3 |
| ADR-0054 | Artifact integrity: attestation action, SBOM tool (`cargo-cyclonedx` or `cargo auditable`), `SHA256SUMS` format, the immutable-releases setting, the user verification recipe |
| ADR-0055 | The interop gate on published artifacts, on `aarch64` Linux and on macOS arm64; extends ADR-0020 |
| ADR-0056 | The Homebrew tap of §7, including its recorded departure from ADR-0016 as a single-user evaluation path |
| ADR-0057 | Release signing with the project PGP key (§5): the new role, superseding ADR-0006's disclosure-only wording; key compromise, revocation and rotation (ADR-0005) for published releases |

## Drawbacks

- **A release takes longer and needs the maintainer at every step.** It
  becomes a sequence with a human in the middle: the tag, then CI, then a
  local verification and signature, then publication. A release cannot be
  cut from a phone.
- **A second repository to secure.** The tap can be compromised on its
  own, and a malicious formula would point users at other bytes. Branch
  protection and the formula's fixed `sha256` reduce that risk but do
  not remove it.
- **The Homebrew path is weaker than the Linux deployment.** It runs the
  server as the operator's own account, which owns its trust anchors
  (§7). That is acceptable for evaluating the alpha and is labelled as
  such, but users may run it as their real server anyway.
- **The interim trust model leans on GitHub.** Attestations prove that
  GitHub's runners produced the bytes from the tag. Nobody outside can
  rebuild them yet.
- **musl's allocator** may cost throughput under load.
- **Windows users get a second-class path,** and macOS users who
  download with a browser hit Gatekeeper.
- **It can look more mature than it is.** Binaries and a tap read as
  "ready" to many people. Every artifact, the formula's description and
  the release notes keep the alpha label and the Phase-3 caveat
  (threat model §8.12).

## Rationale and alternatives

### Alternative 1: stay source-only until Phase 3's reproducible builds

This keeps the threat model as it is. It also leaves the alpha out of
reach for almost everyone who would test it. The interim controls (§11)
are honest about what they leave open.

### Alternative 2: a release generator (dist or GoReleaser)

- `dist` v0.34.0 (2026-11-02) is maintained, but macOS signing and
  Sigstore are still "coming soon", it has no winget publisher, and it
  generates the workflow, which then has to be reviewed on every
  upgrade.
- GoReleaser's Rust builder says Cargo workspaces "might not work", and
  its MSI support for winget is in the paid tier.

With three targets on native runners, a hand-written workflow with
actions pinned by SHA, as the rest of `.github/workflows/` does, has
less to trust.

### Alternative 3: glibc instead of musl

A glibc build on `ubuntu-22.04` (glibc 2.35) keeps glibc's allocator. It
does not run on RHEL 9 (glibc 2.34) or Alpine, and two libc families
would double the matrix. One static binary per architecture is simpler
for operators, and performance comes after correctness and security
(MANIFIESTO).

### Alternative 4: a notarized macOS binary or a cask

Notarization costs US$99 a year, needs Apple credentials in CI, and
fixes only browser downloads. Homebrew casks are expected to pass
Gatekeeper: since 2026-09-01 homebrew/cask has disabled the ones that
fail. A formula that installs the attested tarball avoids both.

### Alternative 5: homebrew-core now

Not possible. Its acceptance policy requires a stable upstream version,
and a self-submission needs 225 stars, or 90 forks or 90 watchers. The
project had 3 stars on 2026-11-03.

### Alternative 6: a native Windows port and winget now

This is a port, not packaging (§9 and Motivation). It would also ship a
server whose Windows users have no native client to reach it with,
because no Windows OpenSSH build has `ssh-mldsa44-ed25519`. It is
deferred to its own RFC.

### Alternative 7: cosign or minisign instead of PGP

Either would add a second release key or identity for users to learn.
The project already publishes and rotates a PGP key (ADR-0005), and the
tag is already signed with it. The planned signing ADR (§12) records
the broader role. Keyless provenance is covered by the attestations.

### Alternative 8: `.deb` and `.rpm` packages now

Packages imply a repository for updates (apt, rpm), a decision on
hosting, and maintainer scripts that create the service account. That
is worth doing, but in a later ADR on top of the tarballs this RFC
ships. Official distribution inclusion stays Phase 4.

## Prior art

- **ripgrep** ships static musl Linux binaries and a winget package as a
  portable zip (`BurntSushi.ripgrep.MSVC`).
- **OpenSSH portable** ships signed source tarballs only. Distributions
  and Homebrew build it.
- **Arti (Tor)** builds reproducibly in Docker with a fixed build path,
  `SOURCE_DATE_EPOCH` and a fixed target CPU. It is the model for the
  Phase-3 work this RFC leaves open.
- **GitHub artifact attestations** (SLSA v1.0 Build Level 2) and
  **immutable releases** (generally available since 2025-10-28) are the
  platform features §4 and §11 use.

## Unresolved questions

- **aarch64 interop image.** The interop container is pinned by digest
  (ADR-0048). Whether that digest is a multi-architecture index usable
  on `ubuntu-24.04-arm` decides whether the planned interop ADR (§12) needs a second pin.
- **Pinning the macOS client.** The macOS interop job uses Homebrew's
  `openssh`, which moves with Homebrew. ADR-0020 pins its client. How
  the planned interop ADR (§12) pins or records the macOS client version
  is open.
- **musl linking on the runners.** Rust's self-contained musl linking
  should not need `musl-gcc`, because the workspace has no C
  dependencies. A dry run on a `rehearsal-*` tag must confirm it.
- **SBOM tool.** `cargo-cyclonedx` writes a separate file;
  `cargo auditable` embeds the dependency list in the binary. The planned
  integrity ADR (§12) will pick one or both.
- **Updating the tap.** By a manual PR per release, or by a workflow in
  this repository with a token scoped to the tap. For the planned tap
  ADR (§12).
- **Primary key or subkey.** Whether releases are signed by the project
  key's primary or by a dedicated signing subkey under it, which keeps
  one fingerprint for users while separating the purposes. For the
  planned signing ADR (§12).
- **A native Windows client.** MSYS2 packages OpenSSH 10.6p1. Whether
  that build reaches the server from Windows has not been tested.
- **Version.** If RFC-0018 lands in the same release, that release adds
  a feature and is `0.2.0`. A release that only adds artifacts would be
  `0.1.1`.

## Future possibilities

- A native Windows port and winget, under their own RFC (§9). Windows
  code signing from Chile would go through SignPath Foundation or
  Certum's open-source certificate. Azure Artifact Signing accepts
  individuals only in the United States and Canada.
- `.deb` and `.rpm` packages and a package repository, such as
  Cloudsmith's open-source tier.
- Reproducible builds and an independent rebuild check (Phase 3).
- homebrew-core once the project calls a version stable.
- Tier 1 for macOS, once the planned interop ADR pins the macOS job's
  client.
- mimalloc if musl's allocator shows up in measurements.
