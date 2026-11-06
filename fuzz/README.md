# Fuzz targets

QuantumSSH's cargo-fuzz targets
([ADR-0060](../docs/adr/0060-continuous-fuzzing-cargo-fuzz-on-the-pinned-stable-toolchain.md)).
This package has its own workspace and lockfile, outside the root
workspace. It is built with `--sanitizer none` on the toolchain that
`rust-toolchain.toml` pins, and is never part of a release.

## Layout

| Path | What |
|---|---|
| `fuzz_targets/` | One target per parser of peer-supplied bytes (ADR-0060 §4) |
| `src/lib.rs` | What every target shares: the 64 MiB allocator cap (§5) and the fixtures |
| `fixtures/` | The `authorized_keys` and `trusted_user_ca_keys` the auth targets check against |
| `seeds/<target>/` | Valid inputs every run starts from (§6) |
| `regressions/<target>/` | The minimized input of every fixed finding, committed with its fix |

`scripts/fuzz-seeds.py` writes every file under `fixtures/` and `seeds/`,
and its docstring and comments say where each one comes from. The
script is deterministic, so running it again writes the same bytes.
`corpus/`, `artifacts/` and `target/` are local and ignored.

## Running

From the repository root:

```sh
bash scripts/fuzz-prepare.sh                     # cargo-fuzz, lockfile alignment, build
cargo fuzz list
cargo fuzz run --sanitizer none <target> fuzz/seeds/<target> -- -runs=0   # replay, as CI does
cargo fuzz run --sanitizer none <target>         # fuzz until stopped
```

`build (ubuntu-latest)` runs the replay on every PR, and `fuzz.yml`
fuzzes on PRs and daily on `main`. Triage of a finding is in
[`docs/operations.md`](../docs/operations.md#fuzzing).

## Adding a target

A PR that adds or changes a parser of peer-supplied bytes before
authentication adds or updates its target here in the same PR (§9).

1. Add a `[[bin]]` to `Cargo.toml`. `fuzz.yml` reads its matrix from
   there.
2. Add its seeds to `scripts/fuzz-seeds.py`, and run the script.
3. If the parser is crate-private, add an entry point to
   `crates/quantumssh-core/src/fuzzing.rs`. That module holds no parsing
   logic of its own.

A target reads only its input. It never touches the filesystem or the
network, and it never changes its fixed state.
