<!--
  Governance status (2026-11-03):
  Non-authoritative design note (ADR-0027). It sequences the work that
  RFC-0017 (Draft) proposes and records the evidence gathered before the
  RFC was written. It decides nothing: the decisions are RFC-0017 and its
  subsidiary ADRs 0053–0057, once accepted. Until then this note
  describes a proposal.
-->
# Alpha distribution — milestones and evidence (non-normative)

**Status:** plan for [RFC-0017](../rfcs/0017-alpha-distribution.md),
which is in Draft. The RFC holds the decisions; this note orders the
work and gives each milestone a check that says when it is done.

## Milestones

| # | Deliverable | Done when |
|---|---|---|
| M1 | RFC-0017 accepted | The PR merges after its comment period, with every substantive objection answered |
| M2 | ADR-0053 to ADR-0057 | Merged as Proposed, each citing RFC-0017 |
| M3 | `quantumssh keygen` (ADR-0057) | In the interop container, `ssh-keygen -y -f` 10.6 reads a key `keygen` wrote and prints the same public key, and the server loads a key `ssh-keygen` 10.6 wrote. Unit tests cover the refusal cases: an existing file, a symlink, an unsafe parent directory |
| M4 | Release workflow (ADR-0053, ADR-0054) | A test tag on a branch produces a draft release with the three tarballs, `SHA256SUMS`, the SBOM and an attestation per asset, and `gh attestation verify` passes on each with the signer-workflow, source-ref and hosted-runner pins (RFC-0017 §3) |
| M5 | Gates on the artifacts (ADR-0055) | Interop runs green against the draft's binaries on `x86_64` and `aarch64` Linux and on macOS arm64; the systemd reference-unit test runs green against the `x86_64` tarball |
| M6 | Homebrew tap (ADR-0056) | `brew install`, `brew test` and `brew services start` are green in the tap's CI on macOS arm64 and on Linux |
| M7 | Documentation | `docs/deployment.md` downloads and verifies a release and uses `keygen`; a WSL2 section; the client-floor table; `SECURITY.md`'s recipe covers the assets; the README roadmap and threat model §5.5.2 and §6.4 amended (RFC-0017 §10) |
| M8 | `0.2.0` | Signed tag; a locally recomputed `SHA256SUMS` byte-identical to CI's, and its `SHA256SUMS.asc` on the draft; immutable release; `gh release verify v0.2.0` passes; tap updated; Zenodo record created; the WSL2 guide checked by hand on Windows 11 |

M3 does not depend on M4 to M6, so the two lines can run in parallel.

## Evidence gathered on 2026-11-03

### The code on each target

`cargo check --workspace --all-targets`:

| Target | Result |
|---|---|
| `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin` | 0 errors, 0 warnings |
| `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc` | 48 errors in `quantumssh-core` (`rustix::{fs,process,pty,termios}`, `std::os::unix`) |

### macOS arm64, end to end

The setup:

- macOS 27 on arm64 runs `cargo test --workspace` green: 315 tests in 11
  suites.
- The client is OpenSSH 10.6p1 from Homebrew, at
  `/opt/homebrew/opt/openssh/bin`.
- The server is the release binary.

What passed:

- **Negotiation:** the client negotiated `mlkem768x25519-sha256`, host key
  `ssh-mldsa44-ed25519` and `chacha20-poly1305@openssh.com`.
- **Fingerprint:** the one the client printed matched `server.started`'s
  `host_key_fingerprint` and `ssh-keygen -l`.
- **Sessions:**
  - `exec` printed its output;
  - `ssh -tt` allocated `/dev/ttys006` and returned the command's exit
    status, 3;
  - `sftp` did a put, `ls` and get of a 200 kB file and the copy
    compared equal;
  - so did `scp`.
- **Old client:** macOS's own OpenSSH 10.5p1 failed with "no matching host
  key type found. Their offer: ssh-mldsa44-ed25519", and the server logged
  `rejected: no-host-key-algorithm`.
- **Shutdown:** `SIGTERM` started the graceful drain (ADR-0028).

### OpenSSH builds

- **ML-DSA is always on in 10.6.** OpenSSH 10.6p1 defines `USE_MLDSA`
  under the same compiler condition as `USE_MLKEM768X25519`. The
  implementation is internal, with no OpenSSL dependency, so every
  standard build of 10.6 offers `ssh-mldsa44-ed25519`.
- **Where 10.6 is, by distribution:** RFC-0017's Motivation and its
  client-floor table give it, from Repology.
- **Windows:** the inbox client on Windows 11 25H2 is 9.5p2, and the
  latest Win32-OpenSSH is 10.4.0.0p1-Preview.
- **Homebrew:** `openssh` 10.6p1 has bottles for macOS arm64 and for Linux
  `x86_64` and `arm64`, and none for Intel macOS.

## Not in this plan

- The native Windows port and winget: a future RFC (RFC-0017 §9).
- `.deb`/`.rpm` packages and a package repository.
- Reproducible builds: Phase 3.
