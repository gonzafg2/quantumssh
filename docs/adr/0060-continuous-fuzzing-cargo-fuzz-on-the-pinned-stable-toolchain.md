# ADR 0060: Fuzz every pre-authentication parser with cargo-fuzz on the pinned stable toolchain, in CI

- **Status:** Proposed
- **Date:** drafted 2026-11-06; accepted with the implementing PR
- **Deciders:** Project lead
- **Related:**
  - The continuous-fuzzing workstream of Phase 3, [#248](https://github.com/gonzafg2/quantumssh/issues/248). Its acceptance item is "a fuzz target for every pre-authentication parser, running continuously".
  - Implements the fuzzing commitments of the [threat model](../threat-model.md): §4.1 (the pre-authentication path must be fuzzable), §5.1.2's test handle, §5.4.5's SFTP test handle and §6.2's "Fuzzing as a Phase-3 deliverable".
  - Ends the Phase-1 deferral in [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) ("Phase 1 deliberately does **not** add `cargo-fuzz`").
  - Keeps these decisions unchanged:
    - [ADR-0017](0017-phase-1-workspace-topology-two-crates-flat.md): the workspace keeps its two members, and the fuzz package stays outside it (§2).
    - [ADR-0018](0018-phase-1-unsafe-code-forbid-workspace.md): the fuzz package forbids `unsafe` too (§2).
    - [ADR-0039](0039-rust-toolchain-pinned-to-exact-release.md): no second toolchain (§1).
    - [ADR-0031](0031-required-status-checks-commit-lint-and-openssh-interop.md): no new required-check name (§7).
  - Encrypts findings to the key that [ADR-0054](0054-release-artifact-integrity.md) §6 and [ADR-0057](0057-release-signing-with-the-project-pgp-key.md) pin, the same key [`SECURITY.md`](../../SECURITY.md) takes private reports on (§8).
  - Implementation, planned:
    - new files: `fuzz/` (`Cargo.toml`, `Cargo.lock`, `fuzz_targets/`, `seeds/`, `regressions/`), `.github/workflows/fuzz.yml` and `crates/quantumssh-core/src/fuzzing.rs`;
    - changed files:
      - `crates/quantumssh-core/src/lib.rs` and `src/transport.rs` (§3);
      - the root `Cargo.toml` (`check-cfg`);
      - `.github/workflows/ci.yml` and `.github/workflows/deny.yml`;
      - `deny.toml` and `.github/dependabot.yml`;
      - `docs/threat-model.md` §5.1.2, §5.4.5 and §6.2;
      - `docs/operations.md`;
      - the review rules in `CLAUDE.md` and `AGENTS.md` (§9).

## Context

The threat model makes fuzzing part of how the pre-authentication path
earns trust. §5.1.2 asks for "a fuzzer (`cargo-fuzz`, OSS-Fuzz) with
corpora derived from the RFC 4253 binary packet grammar". §5.4.5 says
"§6.2's Phase-3 fuzzing harness" drives the SFTP request handlers in a
scratch directory. Today the repository has no fuzz target and no fuzzing
job. The parsers were written for fuzzing: `wire.rs` and `cert.rs` are
pure functions over bounded byte slices.

Facts that shape the design (checked on 2026-11-06):

- **cargo-fuzz runs on our pinned stable toolchain without a sanitizer.**
  - Its README says it "needs a nightly compiler", because its default
    sanitizer, `address`, takes `-Zsanitizer`. With `--sanitizer none` it
    passes only `-C` flags and `--cfg fuzzing` (`src/project.rs`
    L178–196 at 0.13.2). The coverage instrumentation it relies on
    (`-Cpasses=sancov-module` and the `-sanitizer-coverage-*` LLVM
    arguments) is accepted by stable rustc.
  - Tested on macOS arm64 with cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13
    and rustc 1.99.1, the `rust-toolchain.toml` pin:
    - `cargo fuzz build -s none` built a target over
      `wire::parse_peer_id`, `kex::parse_kexinit` and
      `wire::decode_packet_body`.
    - `cargo fuzz run -s none` ran it with coverage feedback for 3,000,903
      executions (`cov: 83`, 88 corpus entries).
    - The default build failed: "the option `Z` is only accepted on the
      nightly compiler".
  - On Linux the same targets built and ran in the `rust:1.99.1` image
    (`sha256:8a4e90c7…`) under Docker on that Mac: natively on aarch64,
    and emulated on x86_64. Both runs fuzzed with coverage feedback
    (`cov: 83` and `cov: 86`), and §5's allocator cap fired on both.
    GitHub's runners have not run it yet. The implementing PR adds these
    steps to `build (ubuntu-latest)` itself, so a failure there blocks
    only that PR, not the PRs after it.
- **ClusterFuzzLite and OSS-Fuzz support only AddressSanitizer for Rust,
  on their own nightly.**
  - Their base image `gcr.io/oss-fuzz-base/base-builder-rust` sets
    `RUSTUP_TOOLCHAIN nightly-2025-09-05` to override
    `rust-toolchain.toml` (oss-fuzz `infra/base-images/base-builder-rust/Dockerfile`
    L25–29 at `f3af0cb`). That nightly is rustc 1.91.0, below our MSRV of
    1.92: a build of a package with `rust-version = "1.92"` fails on it.
  - The ClusterFuzzLite actions have one tag, `v1`. Even pinned by commit,
    they pull the mutable images `clusterfuzzlite-build-fuzzers:v1` and
    `run-fuzzers:v1` (`actions/build_fuzzers/action.yml` L56,
    `actions/run_fuzzers/action.yml` L77). Both were re-pushed on
    2026-11-05.
- **OSS-Fuzz accepts projects with "a significant user base and/or
  critical to the global IT infrastructure"** (its "Accepting new
  projects" page). An alpha published two days ago does not meet that
  bar. Its bugs stay private until they are fixed or for 90 days.
- **Without a sanitizer, libFuzzer does not catch a large allocation.**
  - Tested: a target that allocates 128 MiB ran clean under
    `-malloc_limit_mb=64`. The malloc hooks that limit depends on are
    installed by a sanitizer runtime. `-rss_limit_mb` samples RSS about
    once a second, so it misses a buffer that is freed quickly.
  - A Rust global allocator with a cap catches it. `cap` 0.1.2 wraps
    `System`: 478 lines, no dependencies, MIT OR Apache-2.0. Installed
    with `#[global_allocator]` under `#![forbid(unsafe_code)]`, it turned
    the same allocation into "memory allocation of 134217728 bytes
    failed" and a libFuzzer crash with a written reproducer. Writing that
    allocator ourselves would take an `unsafe impl GlobalAlloc`, which
    ADR-0018 forbids.
- **`fuzz_target!` compiles under `#![forbid(unsafe_code)]`.** The macro
  emits a plain `#[no_mangle]`, and rustc does not report the
  `unsafe_code` lint inside an external macro's expansion. Tested: the
  target built, and an `unsafe {}` block added to it failed with "usage
  of an `unsafe` block", so the lint stays in force for the code we write.
- **`--cfg fuzzing` leaves our dependencies' runtime behaviour as it is.**
  Among the 92 registry crates in `Cargo.lock`, only `tokio` uses it at
  runtime, and only to add a `fuzz` module (`src/lib.rs` L693, 1.51.6).
  `proc-macro2` and `syn` use it at build time.
- **Many parsers cannot be reached from outside the crate.**
  - Reachable through the public API: `wire::parse_peer_id`,
    `wire::validate_packet_length`, `wire::decode_packet_body`,
    `kex::parse_kexinit`, `kex::negotiate`, `kex::hybrid_exchange`,
    `cipher::PacketCipher::{body_len, open}` and the `transport` stage
    methods.
  - Not reachable:
    - `cert::verify` and `sftp::serve`, which are `pub(crate)`;
    - the `composite` module, which is private;
    - the `SSH_MSG_SERVICE_REQUEST` and `SSH_MSG_USERAUTH_REQUEST`
      parsing, which is inline in the async stage methods
      `read_service_request` and `authenticate` (`transport.rs` L539 and
      L670), behind the AEAD. A byte-level fuzzer cannot get past the
      AEAD without the session keys.
- **`libfuzzer-sys` is `(MIT OR Apache-2.0) AND NCSA`.** It bundles
  LLVM's libFuzzer source, and `deny.toml` does not allow NCSA.
- **On this public repository, every Actions log and artifact is
  public.** A crash found by a run is visible, input and stack trace
  included, from the moment it is found. GitHub-hosted standard runners
  are free for public repositories. A job may run for up to 6 hours. A
  scheduled workflow can be delayed or dropped under load, and is
  disabled after 60 days without repository activity.
- **A panic before authentication ends only that connection.** The
  release profile unwinds (no `panic = "abort"` in any manifest). Each
  connection is its own task in the server's `JoinSet`
  (`server.rs` L266), and `log_join` reports a panic as a closed
  connection (`server.rs` L307). Fuzzing still treats every panic as a
  finding: §5.1.2 lists "panic-induced denial of service".

## Decision

We will fuzz with cargo-fuzz and libFuzzer, on the toolchain
`rust-toolchain.toml` pins, without a sanitizer. One target covers each
parser of peer-supplied bytes, every pre-authentication parser first. CI
builds every target and replays its committed inputs on every PR, fuzzes
on PRs that touch the code, and fuzzes every day on `main`. A crash is
encrypted to the project's security key before it leaves the runner.

### 1. Engine and toolchain

- The engine is cargo-fuzz **0.13.2**, installed in CI with
  `cargo install cargo-fuzz --version 0.13.2 --locked`, over
  `libfuzzer-sys` 0.4. A version bump is a reviewed PR.
- Every build and run passes `--sanitizer none`. rustup reads the
  toolchain from `rust-toolchain.toml`, found from `fuzz/`, so the fuzz
  build uses the same compiler as every other job. No nightly is
  installed anywhere.
- cargo-fuzz's defaults stay on: `-Cdebug-assertions`, which makes
  integer overflow a panic, and `--cfg fuzzing`.

### 2. The fuzz package

- `fuzz/` at the repository root holds one package, `quantumssh-fuzz`,
  with `publish = false`. Its `Cargo.toml` has its own `[workspace]`
  table, and its `Cargo.lock` is committed. It is not a member of the
  root workspace, whose `members` stay ADR-0017's two crates. It is never
  built into a release artifact.
- It cannot inherit `[workspace.lints]`, so its manifest sets
  `[lints.rust] unsafe_code = "forbid"` itself. ADR-0018 applies to it
  as written.
- Its dependencies are `libfuzzer-sys`, `cap` (§5), `quantumssh-core`
  by path, and `tokio`, already in the graph, for the stateful target.
  All of them pass `cargo deny`:
  - `deny.yml` runs a second check with `manifest-path: fuzz/Cargo.toml`
    against the same `deny.toml`;
  - `deny.toml` adds a license exception for NCSA, scoped to
    `libfuzzer-sys`, not a global allow;
  - `.github/dependabot.yml` adds a `cargo` entry for `/fuzz`.

### 3. How targets reach the parsers

- `quantumssh-core` gets one module, `fuzzing`, declared as
  `#[cfg(fuzzing)] pub mod fuzzing;`. It holds thin entry points that
  call the crate's own functions. It holds no parsing logic and no
  alternative code path.
- That declaration is the only `cfg(fuzzing)` in first-party code. No
  function body, and nothing a normal build compiles, branches on
  `fuzzing`, so the code under test is the code that ships. The root
  `Cargo.toml` declares `check-cfg = ["cfg(fuzzing)"]` under
  `unexpected_cfgs`, so the workspace build stays warning-free.
- The `SSH_MSG_SERVICE_REQUEST` and `SSH_MSG_USERAUTH_REQUEST` parsing
  moves out of `read_service_request` and `authenticate` into pure
  functions over the decrypted payload. The stage methods call those
  functions, with no behaviour change. Each function parses one message
  type, and its stage still accepts only that type. The type-state
  machine is not loosened (RFC-0003).
- There is no plaintext or null cipher under `cfg(fuzzing)`. Code behind
  the AEAD is reached through its pure parsers, not by switching off
  encryption.

### 4. Targets

These pre-authentication targets are the set #248's acceptance item
requires.

| Target | Entry point | What it covers |
|---|---|---|
| `peer_id` | `wire::parse_peer_id` | the client identification line |
| `packet` | `wire::validate_packet_length`, `wire::decode_packet_body` | plaintext binary packet framing and padding |
| `kexinit` | `kex::parse_kexinit`, then `kex::negotiate(&peer, true)` and `kex::negotiate(&peer, false)` on the same input | `SSH_MSG_KEXINIT` and negotiation, for the first exchange and for a rekey. The `initial` flag is the only difference between the two in these functions. A rekey's encrypted delivery runs after authentication, in `Expect<S, Session>`, and is not in this table |
| `hybrid_init` | `kex::hybrid_exchange` | the client's ML-KEM-768 encapsulation key and X25519 share; either half failing aborts |
| `sealed_frame` | `cipher::PacketCipher::body_len` and `open`, for both AEAD ciphers with fixed keys | length decryption, the length bound, tag checks |
| `service_request` | the parser extracted from `read_service_request` | `SSH_MSG_SERVICE_REQUEST` |
| `userauth_request` | the parser extracted from `authenticate`. When the request carries a signature and names a key in a fixed `authorized_keys` set, it goes on to `auth::verify_auth_signature` with a fixed session id | `SSH_MSG_USERAUTH_REQUEST` with and without a signature (the probe), its `publickey` fields, the key blob, and the Ed25519 signature blob through `ed25519-dalek`'s strict verification |
| `user_certificate` | `cert::verify`, with a fixed trusted CA and a fixed `now` | the OpenSSH user certificate, its principals and options, and the composite CA signature through the `composite` module's verification, both halves |
| `handshake` | `transport::version_exchange`, then `exchange_kexinit`, `run_hybrid` and `exchange_newkeys`, over an in-memory stream | the identification-line reader, plaintext framing, and every stage transition through the peer's `SSH_MSG_NEWKEYS`. Input after that meets the AEAD, which `sealed_frame` covers |

These post-authentication targets follow, because §5.4.5 already commits
to the first:

| Target | Entry point | What it covers |
|---|---|---|
| `sftp` | `sftp::serve` over the input, in a scratch directory created empty for each input and removed after it | SFTP framing and request handlers |
| `pty_modes` | `pty::Modes::parse`, `pty::valid_term` | the `pty-req` terminal modes and `TERM` |

The channel layer (`channel.rs`) gets no target in this ADR. It runs
inside the async session and spawns processes. Fuzzing it needs the same
extraction as §3, so it is a follow-up issue linked from #248.

Rules every target follows:

- It reads only its input. Fixed state, such as a host key from fixed
  seeds, a CA, keys or a Tokio current-thread runtime, is built once and
  reused. The target never changes that state. State the code under test
  does change, such as the `sftp` target's scratch directory, is rebuilt
  for every input, so a reproducer replays alone in a fresh process.
- Control flow depends only on the input. `kex::hybrid_exchange` and
  `run_hybrid` draw the server's ephemeral secrets from the OS, but no
  branch on the peer's bytes depends on them, so a reproducer replays the
  same way.

### 5. What counts as a finding

- **A panic**, including integer overflow under `-Cdebug-assertions`.
- **An allocation over the cap.** Each target installs
  `cap::Cap<System>` as its global allocator. The default cap is 64 MiB
  of live Rust heap. That is two orders of magnitude above the largest
  legitimate buffer, an SFTP packet of at most 256 KiB, and far below
  what a 32-bit length field can request. A target may lower its own
  cap. Going over it aborts, and libFuzzer records the input. This makes
  §5.1.2's "no allocation without an explicit bound" testable without
  ASan.
- **A timeout**: `-timeout=5` seconds per input.
- **RSS over libFuzzer's default `-rss_limit_mb=2048`.**

### 6. Seeds and corpus

- `fuzz/seeds/<target>/` holds small, reviewed, valid inputs:
  - the OpenSSH 10.6p1 client's identification line, KEXINIT and hybrid
    init, from `tests/vectors/mlkem768x25519-sha256-openssh.txt` (§5.1.2:
    "derived from the RFC 4253 binary packet grammar");
  - messages built with the encoders the integration tests already use
    (`tests/support/mod.rs`: `client_kexinit`, `service_request_payload`,
    `signed_auth_request`, `probe_auth_request`);
  - a certificate signed by the test CA.

  How each seed was produced is written next to it.
- `fuzz/regressions/<target>/` holds the minimized input of every fixed
  finding, committed with its fix.
- The evolved corpus lives in the Actions cache, one entry per target.
  - Only scheduled runs on `main` save it, after `cargo fuzz cmin`. PR
    runs restore it and never save it.
  - A cache entry that goes unread for 7 days is evicted. If that
    happens, fuzzing starts again from the seeds. The seeds are the
    floor, and nothing is lost that a run cannot rebuild.

### 7. CI

- **Deterministic, on every PR.** Two steps join the existing
  `build (ubuntu-latest)` job in `ci.yml`, already a required check:
  - `cargo fuzz build -s none` builds every target;
  - each target runs over its `seeds/` and `regressions/` with
    `-runs=0`.

  A PR that breaks a target, or brings back a fixed finding, cannot
  merge. No required-check name changes (ADR-0031).
- **Exploratory, on PRs.** `fuzz.yml` runs on PRs that change
  `crates/quantumssh-core/src/**` or `fuzz/**`, for 60 seconds per
  target from the cached corpus, in a matrix. It is not a required
  check: a finding it reports is real, but its absence proves little.
- **Continuous, on `main`.** `fuzz.yml` runs every day at 03:17 UTC, off
  the hour as GitHub's scheduling notes advise, for 20 minutes per
  target, as a matrix on standard runners. Then it minimizes and saves
  each corpus.
- The workflow holds only `contents: read` and needs no secret, so it
  behaves the same on fork PRs. Its actions are pinned by commit SHA, as
  in every other workflow.

### 8. Crashes are encrypted before they leave the runner

- libFuzzer's output and the program's stderr go to a file on the
  runner, never to the job log. The public log says which target failed
  and that an encrypted report was uploaded.
- On a failure, the job archives `fuzz/artifacts/<target>/` and that
  output, and encrypts the archive with `gpg --encrypt` to the key that
  `keys/release-keys.txt` lists as `current`. It reads that key from
  `keys/security.asc` and checks its fingerprint against the pin first.
  That key's encryption subkey (`cv25519 [E]`) is the one `SECURITY.md`
  takes private reports on.
- The encrypted archive is uploaded as `fuzz-crash-<target>-<run_id>`,
  with `retention-days: 90`, the most GitHub allows on a public
  repository. The run fails. Triage starts by downloading the archive:
  from then on, the maintainer keeps the decrypted reproducer with the
  advisory or the fix, so the artifact's expiry loses nothing. The
  `SECURITY.md` embargo counts from acknowledgement and can run to
  120 days.
- The maintainer decrypts it and triages it like an external report
  under `SECURITY.md`:
  - a vulnerability goes through a private GitHub security advisory and
    its temporary private fork;
  - anything else is fixed in an ordinary PR.

  Either way, the fix commits the minimized reproducer to
  `fuzz/regressions/<target>/`. `docs/operations.md` gets the
  decrypt-and-replay recipe.
- What stays public: that a run failed, which target, and when.

### 9. Keeping it true

- **A review rule**, added to `CLAUDE.md` "Hard security rules" and to
  the `AGENTS.md` review rules: a PR that adds or changes a parser of
  peer-supplied bytes before authentication adds or updates its fuzz
  target and seeds in the same PR.
- **OSS-Fuzz is not abandoned.** We apply once the project meets its
  bar, and no earlier than `0.5.0`, reusing these targets. That would add
  ASan and private bug tracking. The outcome is recorded in #248.

## Consequences

### Positive

- Every pre-authentication parser gets coverage-guided fuzzing, every
  day, with no second toolchain and no image or action outside the
  repository's pins.
- Unbounded allocations become findings even without a sanitizer (§5).
- A crash is not published by the job that found it.
- The deterministic replay turns each fixed finding into a permanent
  regression test in a check that already blocks merges.
- Extracting the two inline parsers leaves `authenticate` and
  `read_service_request` with less to do. The parsing becomes testable
  without a socket.

### Negative

- **No AddressSanitizer.** A memory-safety bug inside a dependency's
  `unsafe` code surfaces only if it crashes. First-party code has no
  `unsafe` (ADR-0018), so this gap is confined to the primitive layer.
  The upgrade paths are OSS-Fuzz (§9), or a nightly ASan job, which
  would need an ADR superseding the single-toolchain rule of ADR-0039.
- **Two new fuzz-only dependencies.**
  - `libfuzzer-sys` brings C++ code and an NCSA license exception.
  - `cap` has had no release since 2023-03. It is small, and the
    alternative is first-party `unsafe`.

  Neither reaches the shipped binary.
- **More CI time.**
  - `build (ubuntu-latest)` gets longer, by the cargo-fuzz install and a
    second release build of the core.
  - The daily matrix takes about 20 minutes of wall time across 11
    parallel jobs.
- **Public failures.** A finding is visible as a failed run on `main`
  before it is fixed. An attacker who sees it learns which parser to
  fuzz, and the targets are public.
- **Scheduled runs need activity.** GitHub disables a scheduled workflow
  after 60 days without activity.
- **Stable flags, unstable semantics.** The `-sanitizer-coverage-*` LLVM
  arguments go through `-Cllvm-args`, which can change with the LLVM
  inside a new rustc. A toolchain bump PR (ADR-0039) would show that as
  a red `build (ubuntu-latest)`, which is the right place to see it.

### Neutral

- The fuzz package is a third `Cargo.toml` in the repository, outside
  the workspace.
- `quantumssh-core` gains one module that no normal build compiles.

## Alternatives considered

### Alternative 1: ClusterFuzzLite

It is the closest to what the threat model names. It brings ASan, PR
fuzzing and batch fuzzing. It was not chosen for three reasons:

- Its pinned nightly is below our MSRV, so we would have to override the
  toolchain in our own Dockerfile and maintain a nightly beside
  `rust-toolchain.toml`.
- Its `v1` images are mutable, whatever commit the action is pinned to.
- Keeping a corpus beyond the 90-day artifact retention takes its
  `storage-repo` option, which needs a personal access token with write
  access stored as a secret. This project holds no such secret today.

### Alternative 2: apply to OSS-Fuzz now

It brings ASan, Google's capacity and private bugs. It was not chosen
because an alpha with few users does not meet its stated bar, and an
application that gets rejected delays fuzzing for nothing. It stays the
path for after `0.5.0` (§9).

### Alternative 3: cargo-fuzz on a pinned nightly, with ASan, in our own workflow

It closes the dependency-`unsafe` gap. It was not chosen because it is a
second toolchain, which ADR-0039 rules out, and on Rust code with no
first-party `unsafe` ASan's added findings are confined to the
primitive layer. §5's allocator cap recovers the one sanitizer feature
the safe code needs.

### Alternative 4: afl.rs, honggfuzz-rs or bolero

They are capable engines. None matches what the threat model and README
name, cargo-fuzz and OSS-Fuzz. afl.rs needs its own compiler wrapper and
toolchain, and bolero adds a layer over the same engines. cargo-fuzz
targets are what OSS-Fuzz builds, so §9 stays open.

### Alternative 5: property tests only

ADR-0020 named `proptest` round trips as Phase 1's soft complement, and
the repository never adopted them. Property tests check properties of
inputs drawn from a strategy the test writes. They do not search for
inputs that reach new code, which is what a parser facing an adversary
needs.

### Alternative 6: the fuzz package as a workspace member

It would inherit the workspace lints. It was not chosen because it would
change ADR-0017's two-member topology, and because `cargo build` and
`cargo test --workspace` would then compile libFuzzer on every run.

### Alternative 7: crashes in the clear, or fuzzing only on the maintainer's machine

Clear logs are the simplest option, but they publish each input and
stack trace as soon as they are found. Fuzzing only on the maintainer's
machine keeps findings private, but it is not CI, it depends on one
machine being on, and it competes with that machine's other work.
Encryption keeps the findings private, at the cost of about fifteen
lines of workflow.

## Links

- Planned implementation: `fuzz/`, `.github/workflows/fuzz.yml`,
  `crates/quantumssh-core/src/fuzzing.rs`, and the changes listed under
  Related.
- Threat model §4.1, §5.1.2, §5.4.5 and §6.2; `SECURITY.md`.
- Related ADRs: ADR-0017, ADR-0018, ADR-0020, ADR-0031, ADR-0039,
  ADR-0054, ADR-0057.
- cargo-fuzz: <https://github.com/rust-fuzz/cargo-fuzz> (0.13.2);
  libfuzzer-sys: <https://github.com/rust-fuzz/libfuzzer> (0.4.13);
  `cap`: <https://github.com/alecmocatta/cap> (0.1.2).
- OSS-Fuzz, accepting new projects:
  <https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/>;
  ClusterFuzzLite, Rust:
  <https://google.github.io/clusterfuzzlite/build-integration/rust-lang/>.
- GitHub Actions billing and limits:
  <https://docs.github.com/en/billing/concepts/product-billing/github-actions>,
  <https://docs.github.com/en/actions/reference/limits>.
