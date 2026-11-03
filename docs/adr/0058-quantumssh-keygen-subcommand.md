# ADR 0058: Implement `quantumssh keygen` as a core encoder plus a binary module that writes through a verified directory descriptor

- **Status:** Accepted
- **Date:** 2026-11-03 (accepted with the implementing PR [#252](https://github.com/gonzafg2/quantumssh/pull/252); drafted 2026-11-03)
- **Deciders:** Project lead
- **Related:**
  - Implements [RFC-0018](../rfcs/0018-host-key-generation.md) §8 (Accepted 2026-11-03; [#249](https://github.com/gonzafg2/quantumssh/pull/249)).
  - It reuses the loader of [ADR-0047](0047-host-key-algorithm-ssh-mldsa44-ed25519.md) and the composite key of [ADR-0035](0035-ml-dsa-crate-rustcrypto.md), and the ancestor rule of [ADR-0029](0029-phase-2-config-file-v1-schema-parser-strictmodes.md). It extends the [ADR-0020](0020-phase-1-ci-openssh-interop-gate.md) gate.
  - Phase 3 roadmap: [#248](https://github.com/gonzafg2/quantumssh/issues/248).
  - Implementation: the `host_key` module of `quantumssh-core`, `crates/quantumssh/src/main.rs`, `crates/quantumssh/src/config.rs` (the predicate becomes crate-visible) and `tests/interop/run_openssh_client.sh`. Two files are new, created by the implementing PR: `crates/quantumssh/src/keygen.rs` and `crates/quantumssh/tests/keygen.rs`.

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

1. **The leaf.** Split `<PATH>` into its parent and a leaf. If the
   parent is empty, as for a bare file name with no separator, it is
   taken as `.`. The leaf must be a normal path component: not empty,
   not `.` and not `..`.
2. **The parent.** `std::fs::canonicalize` the parent, failing on
   `ENOENT`, `EACCES` or a dangling link. Then open it with
   `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
3. **The checks.**
   - `fstat` the directory descriptor and apply ADR-0029's
     group- and world-writable predicate to it.
   - Walk the canonical ancestors above it with the same predicate.
   - `config.rs` makes the predicate and its `mode_of` helper visible to
     the rest of the crate, with no change to what they check. They are
     `pub` inside the private `config` module, which clippy's
     `redundant_pub_crate` lint requires in place of `pub(crate)`; the
     visibility is the same.
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

- **Failures.**
  - `keygen::run` records each file this run created.
  - A failure at any step from 5 on runs `unlinkat` through the directory
    descriptor on exactly those files and on no others. A step-5 failure
    therefore removes only the private file that step 4 created. If the
    cause was an existing `.pub`, that file is the operator's and is left
    alone.
  - A failed `unlinkat` is reported as its own error that names the path
    left behind.
  - If the failure came after step 8 began writing the private key, the
    message says the key must be treated as never used (RFC-0018 §3).
- **Injecting the generator.** The generator in step 7 is a parameter
  of `keygen::run`. Production passes `generate_host_key`. Only the
  `#[cfg(test)]` unit tests inside `keygen.rs` pass a closure that fails.
  The shipped binary has no flag, environment variable or other hook
  that can force a failure.

Creating the files relative to the verified directory descriptor
removes the race on the parent that a path-based `open` would leave.
Only the ancestors above it keep ADR-0029's best-effort window.

This stays within RFC-0018 §3 and does not supersede it. The RFC
requires both files to be created "under the canonical parent joined
with the leaf name", and the descriptor is exactly that directory. The
RFC accepts the residual check-to-open race on ADR-0029's terms; it does
not require the race to exist. This ADR narrows it to the ancestors, and
on those it keeps the RFC's acceptance.

### 4. Tests

- **Core unit tests:**
  - a generated key round-trips through `HostKey::from_openssh_pem` to
    the same public key;
  - `pad_to_block` returns the right value for every residue from 0
    to 7;
  - the private section of a generated key has a length that is a
    multiple of 8 and padding bytes `1, 2, 3, …`;
  - the private section's comment is the empty string, asserted
    directly, because the loader and `ssh-keygen -y` both ignore it;
  - a failing `fill` returns `Err`.
- **Binary integration tests** (`crates/quantumssh/tests/keygen.rs`,
  which spawn `CARGO_BIN_EXE_quantumssh`) cover:
  - success, with modes `0600` and `0644`;
  - success with a bare file name (`keygen hk`), run from a safe
    working directory;
  - a run under `umask 077` set in a `sh -c` wrapper, which still gives
    `0644` on `.pub`;
  - refusal when `<PATH>` exists, when only `.pub` exists, when the leaf
    is a symlink, when the parent is a symlink to a `0777` directory,
    and when an ancestor is group-writable. Each leaves no new file;
  - every usage-error shape of §1.
- **Binary unit tests** (`#[cfg(test)]` in `crates/quantumssh/src/keygen.rs`,
  in-process, because the binary crate has no library target that
  integration tests could call):
  - `keygen::run` with a generator that returns `Err`. Neither file is
    left, and the error says no key was written.

  The keys are generated at run time, and no private-key fixture is
  committed.
- **CI interop**, in `tests/interop/run_openssh_client.sh` (the gate
  `interop.yml` runs, ADR-0020). The check is a new step after the
  existing checks finish and the first server has been stopped.
  - **Setup.** It reuses `$BIN` and the ancestor-safe `$WORK` under
    `target/`. A `/tmp` workdir would fail the ancestor rule this command
    enforces.
  - **Key generation.** It runs `"$BIN" keygen "$WORK/kghk"`. Then
    `ssh-keygen -y -f "$WORK/kghk"` must equal the type and blob fields of
    `"$WORK/kghk.pub"`, and `ssh-keygen -lf "$WORK/kghk.pub"` must equal
    the fingerprint `keygen` printed.
  - **Server.** It starts a second server with
    `--host-key "$WORK/kghk"` and the same `authorized_keys` on
    `$PORT + 1`. It records that server's PID in the script's cleanup
    trap and waits on that port's readiness. `ssh … true` against that
    port must exit 0 with the pinned client.
  - **No false pass.** The first server is already stopped, so a pass
    cannot come from it.

  The existing gate run keeps its `ssh-keygen` host key, so both
  directions stay covered.

## Consequences

### Positive

- The secret-handling code is small and lives in two places: a pure
  encoder that can be tested without a file system, and a writer that
  never calls a path-based `open` on the key.
- No dependency is added. `cargo deny` sees no change.

### Negative

- `config.rs` makes its ancestor predicate crate-visible. The behaviour
  does not change, but its visibility widens.
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
