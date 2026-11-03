# ADR 0058: Implement `quantumssh keygen` as a core encoder plus a binary module that writes through a verified directory descriptor

- **Status:** Proposed
- **Date:** TBD (accepted with the implementing PR)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0018](../rfcs/0018-host-key-generation.md) §8 (Accepted 2026-11-03; [#249](https://github.com/gonzafg2/quantumssh/pull/249)).
  - It reuses the loader of [ADR-0047](0047-host-key-algorithm-ssh-mldsa44-ed25519.md) and the composite key of [ADR-0035](0035-ml-dsa-crate-rustcrypto.md), and the ancestor rule of [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md). It extends the [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) gate.
  - Phase 3 roadmap: [#248](https://github.com/gonzafg2/quantumssh/issues/248).
  - Implementation: the `host_key` module of `quantumssh-core`; `crates/quantumssh/src/{main.rs,keygen.rs}`; `crates/quantumssh/tests/keygen.rs`; `.github/workflows/interop.yml`.

## Context

RFC-0018 decided what `quantumssh keygen <PATH>` does:

- the container layout, padding rule and empty comment;
- the creation order, modes, refusals and cleanup;
- RNG fail-closed;
- the zeroization list.

It left three things to this ADR: how the command-line parser tells the
subcommand from the server flags, where the code lives, and the CI
steps.

Four facts constrain the code:

- **The parser is hand-written.** `parse_cli` in `main.rs` walks the
  flags, and `main` prints `error: …` plus the usage text and exits with
  `ExitCode::FAILURE` on a parse error.
- **The composite key does not keep its seeds.**
  `composite::SigningKey::from_seeds` expands them and drops them. An
  encoder must therefore take the seeds itself.
- **The binary has no `getrandom` dependency.** The core crate has it.
- **`rustix` with `fs` is already a dependency of both crates.** It
  gives safe `openat`, `fchmod`, `fstat`, `fsync` and `unlinkat`.

## Decision

We will split `keygen` into a pure encoder in `quantumssh-core` and a
file-writing module in the binary. The binary opens the canonical
parent directory once, checks that directory through the descriptor,
and creates both files relative to that descriptor. No new dependency is
added.

### 1. Command line

- **Recognizing the subcommand.** `parse_cli` treats the subcommand as
  present only when the first argument is exactly `keygen`. Then:
  - exactly one more argument must follow;
  - that argument must not start with `-`;
  - any other shape is the parse error
    `usage: quantumssh keygen <PATH>`, reported like the existing ones.
- **Separate modes.** `keygen` is never combined with server flags.
  `CliOutcome` gains a `Keygen(PathBuf)` variant.
- **Before the server starts.** `main` dispatches it after the PTY and
  SFTP helper checks and before any configuration, logging or runtime
  setup.
- **Help text.** `--help` gains a `SUBCOMMANDS:` section with the one
  line `keygen <PATH>  Write a new ssh-mldsa44-ed25519 host key (RFC-0018)`.
- **Exit codes.** `ExitCode::SUCCESS` when the key is written, and
  `ExitCode::FAILURE` for everything else, as the server already does.

### 2. The encoder, in `quantumssh-core::host_key`

```rust
pub struct GeneratedHostKey {
    pub private_pem: Zeroizing<String>,
    pub public_line: String,      // "ssh-mldsa44-ed25519 <base64>"
    pub fingerprint: String,      // "SHA256:…"
}

pub fn generate_host_key() -> Result<GeneratedHostKey, RngError>;
pub(crate) fn generate_host_key_with(
    fill: impl FnOnce(&mut [u8]) -> Result<(), RngError>,
) -> Result<GeneratedHostKey, RngError>;
```

- **Randomness.** `generate_host_key` passes `getrandom::fill`.
- **One draw.** A single call draws 68 bytes into a `Zeroizing` buffer:
  the 64 seed bytes, then the 4-byte check word. A failed draw returns
  `Err` before any byte is used.
- **The container.** The encoder builds it with the existing `Writer`
  and pads with a helper, `pad_to_block(len) -> usize` (zero when
  aligned, RFC-0018 §2). Every intermediate buffer is `Zeroizing`.
- **The fingerprint.** It is the same function `server.started` uses.

### 3. Writing the files, in `crates/quantumssh/src/keygen.rs`

1. **The leaf.** Split `<PATH>` into its parent and a leaf. The leaf must
   be a normal path component: not empty, not `.` and not `..`.
2. **The parent.** `std::fs::canonicalize` the parent, failing on
   `ENOENT`, `EACCES` or a dangling link. Then open it with
   `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
3. **The checks.**
   - `fstat` the directory descriptor and apply ADR-0029's
     group- and world-writable predicate to it.
   - Walk the canonical ancestors above it with the same predicate.
   - `config.rs` exposes the predicate as `pub(crate)`, with no change
     to what it checks.
4. **The private file.** `openat(dir, leaf,
   O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY | O_CLOEXEC, 0o600)`.
5. **The public file.** `openat(dir, leaf + ".pub", same flags, 0o644)`.
6. **The modes.** `fchmod` the private file to `0o600` and the public
   file to `0o644`.
7. **The key.** Call `generate_host_key()`.
8. **The contents.** Write the private PEM, then `fsync` it. Write the
   public line plus `\n`, then `fsync` it.
9. **The output.** `fstat` both files and print the two paths with
   their observed modes, then the fingerprint.

- **Failures.** A failure in steps 6 to 8 runs `unlinkat` on both leaves
  through the directory descriptor. A failed `unlinkat` is reported as
  its own error that names the path left behind. If the failure came
  after step 8 began writing the private key, the message says the key
  must be treated as never used (RFC-0018 §3).
- **Injecting the generator.** The generator in step 7 is a parameter
  of `keygen::run`. Production passes `generate_host_key`, and tests
  pass a closure that fails.

Creating the files relative to the verified directory descriptor
removes the race on the parent that a path-based `open` would leave.
Only the ancestors above it keep ADR-0029's best-effort window.

### 4. Tests

- **Core unit tests:**
  - a generated key round-trips through `HostKey::from_openssh_pem` to
    the same public key;
  - `pad_to_block` returns the right value for every residue from 0
    to 7;
  - the private section of a generated key has a length that is a
    multiple of 8 and padding bytes `1, 2, 3, …`;
  - a failing `fill` returns `Err`.
- **Binary integration tests** (`crates/quantumssh/tests/keygen.rs`,
  which spawn `CARGO_BIN_EXE_quantumssh`) cover:
  - success, with modes `0600` and `0644`;
  - a run under `umask 077` set in a `sh -c` wrapper, which still gives
    `0644` on `.pub`;
  - refusal when `<PATH>` exists, when only `.pub` exists, when the leaf
    is a symlink, when the parent is a symlink to a `0777` directory,
    and when an ancestor is group-writable. Each leaves no new file;
  - a failing generator, which leaves neither file. It goes through a
    test-only path into `keygen::run`;
  - every usage-error shape of §1.

  The keys are generated at run time, and no private-key fixture is
  committed.
- **CI interop**, in `interop.yml` after the release build:
  - `quantumssh keygen "$W/hk"`;
  - `ssh-keygen -y -f "$W/hk"` must equal the type and blob fields of
    `"$W/hk.pub"`;
  - `ssh-keygen -lf "$W/hk.pub"` must equal the fingerprint `keygen`
    printed;
  - the server started with `--host-key "$W/hk"` must accept
    `ssh … true` with exit status 0 from the pinned client.

  The existing gate run keeps its `ssh-keygen` host key, so both
  directions stay covered.

## Consequences

### Positive

- The secret-handling code is small and lives in two places: a pure
  encoder that can be tested without a file system, and a writer that
  never calls a path-based `open` on the key.
- No dependency is added. `cargo deny` sees no change.

### Negative

- `config.rs` exposes its ancestor predicate as `pub(crate)`. The
  behaviour does not change, but its visibility widens.
- The binary gains its first subcommand path in `parse_cli`.

### Neutral

- The fingerprint function is shared with `server.started`. They cannot
  disagree.

## Alternatives considered

### Alternative 1: path-based `open` after the ancestor walk

It is simpler, but a parent replaced between the walk and the `open`
would redirect the write. The directory descriptor closes that window.

### Alternative 2: keep the seeds inside `composite::SigningKey`

This would let the encoder start from a key. It also keeps secret seeds
alive in every loaded server key for no runtime use. The encoder taking
the seeds directly keeps them only for the encoding.

### Alternative 3: an argument-parsing crate

It is a new dependency for a single subcommand. The hand-written parser
handles it in a few lines.

## Links

- [RFC-0018](../rfcs/0018-host-key-generation.md) §1–§8
- [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md), [ADR-0047](0047-host-key-algorithm-ssh-mldsa44-ed25519.md)
- `crates/quantumssh-core/src/host_key.rs` (the loader this encoder mirrors), `crates/quantumssh/src/config.rs`
