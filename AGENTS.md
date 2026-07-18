# AGENTS.md — QuantumSSH

High-signal facts for automated agents working in this repo.
CLAUDE.md is the authoritative review criteria; this file complements it with
operational context that reading multiple files would be needed to infer.

## Development commands (exact order matters)

```sh
cargo fmt --all -- --check          # formatting
cargo clippy --workspace --all-targets -- -D warnings  # lint (warnings = errors)
cargo test --workspace              # unit + integration tests
cargo deny check                    # licence/advisory/source audit
cargo audit                         # vulnerability audit (cargo-audit)
cargo build --workspace --release   # release sanity check
```

Run `fmt` then `clippy` before pushing. CI enforces this order and fails on
warnings.

## Architecture (not obvious from filenames)

- **Two crates, flat layout**: `crates/quantumssh` (thin binary — CLI, log
  subscriber, runtime) and `crates/quantumssh-core` (library — all server
  logic). The library is the real code; the binary is glue.
- **Pre-auth path is the highest-trust surface** (threat model §4.1).
  `wire.rs` is the entry point: pure functions over byte slices, bounded
  allocations, no I/O, fuzzable by construction.
- **Transport is a type-state machine.** The current code covers M2
  (handshake through NEWKEYS). Never loosen this to accept-and-branch.
- **AEAD-only.** The MAC list is nominal — never exercised, never consulted
  in negotiation. Both ciphers are AEAD (`chacha20-poly1305@openssh.com`,
  `aes256-gcm@openssh.com`).
- **Server is sequential** (ADR-0022): spawn-and-join, one connection at a
  time, bounded by the handshake budget.
- **Audit log is two-layer** (ADR-0024): `tracing` facade with a separate
  audit layer whose filter is compiled in — `RUST_LOG` cannot suppress audit
  events. All output to stderr.

## Code conventions (deviations from Rust defaults)

- Every module starts with `//!` doc comment citing the ADR it implements.
- Every public function is `#[must_use]` when it returns a value (even
  constructors).
- Every fallible function has an `# Errors` section in its doc comment.
- `Debug` implementations never expose key material (threat model §4.3) —
  use `finish_non_exhaustive()` or show only the fingerprint.
- Sensitive buffers use `Zeroizing` and are explicitly `drop`ped.
- No stubs, no mocks, no placeholder code. Everything committed must be
  functional.
- Clippy is set to `all` + `pedantic` + `nursery` at warn level.
  Cognitive complexity threshold is 20 (`clippy.toml`).

## Hard constraints (never violate)

- **`unsafe_code = "forbid"`** workspace-wide. No first-party `unsafe`, no
  `#[allow]` escape. Dependencies may contain `unsafe` — that's the audited
  primitive layer.
- **No legacy crypto.** RSA, DSA, ECDSA-NIST, CBC modes,
  `diffie-hellman-group1/14-sha1`, `ssh-rsa`, password auth, and compression
  are *not compiled in*, not merely configured off. That list is the
  permanent floor; anything NIST/IETF **disallows** is also legacy, while
  deprecation only starts a managed migration
  ([RFC-0009](docs/rfcs/0009-zero-legacy-moving-frontier.md),
  [RFC-0007](docs/rfcs/0007-cryptographic-primitive-migration-procedure.md)).
  A deprecated-but-not-yet-disallowed primitive is **not** legacy — do not
  reject a PR that keeps one in use during its migration window (e.g.
  `ssh-ed25519` under [RFC-0006](docs/rfcs/0006-post-quantum-host-key-signatures.md)).
- **Only KEX**: `mlkem768x25519-sha256`. Failure of either hybrid half
  aborts — never silently fall back.
- **Strict-kex required.** No `SSH_MSG_IGNORE`/`DEBUG` before KEXINIT.
  Terrapin-hardened.
- **Fail closed.** Every rejection is `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`
  (3). Downgrade is impossible — there's nothing to downgrade to.

## Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each source
  file.
- Integration tests in `crates/quantumssh-core/tests/` use `tokio::test`
  with real TCP against an ephemeral-port server.
- `cargo test --workspace` runs everything. No special setup required.

## Git workflow

- Branch from `main`, PR against `main`. Never push to `main`.
- Commits: Conventional Commits (`feat:`, `fix:`, `docs:`, …), DCO sign-off
  (`git commit -s`), and signed (`git commit -S`). CI rejects unsigned or
  unsigned-off commits.
- Spanish and English are both first-class in issues, PRs, and commits.
- Automated reviewers (`opencode`, `Claude Code Review`) only run on PRs from `OWNER`/`MEMBER`/`COLLABORATOR`. Dependabot and other bots are excluded.

## Dependencies

- All dependency versions are pinned centrally in workspace `Cargo.toml`
  under `[workspace.dependencies]`. Crates declare `workspace = true`.
- A new dependency must be justified in its PR and pass `cargo deny`.
- No `russh` — greenfield on audited pure-Rust crypto primitives only
  (RFC-0003).
- Licenses: only Apache-2.0, MIT, BSD, ISC, Unicode, Zlib, CC0-1.0.
  No copyleft (GPL/AGPL/LGPL).

## Key files

| Path | Role |
|---|---|
| `CLAUDE.md` | Authoritative review criteria |
| `docs/threat-model.md` | Defensive posture |
| `docs/adr/` | Architecture Decision Records |
| `docs/rfcs/` | RFCs (shape-determining decisions) |
| `deny.toml` | `cargo deny` configuration |
| `clippy.toml` | Clippy tuning |
| `rust-toolchain.toml` | Pinned toolchain (stable, MSRV 1.92) |
| `rustfmt.toml` | Formatting rules (100 cols, module imports) |
