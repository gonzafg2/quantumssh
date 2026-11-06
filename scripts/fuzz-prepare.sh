#!/usr/bin/env bash
# Prepares a fuzz build (ADR-0060 §1–§2): installs the pinned cargo-fuzz
# when it is missing or another version, aligns fuzz/Cargo.lock to the
# root Cargo.lock, and builds the targets without a sanitizer, on the
# toolchain rust-toolchain.toml pins. Shared by ci.yml and fuzz.yml so the
# cargo-fuzz version is named once.
#
# Usage: scripts/fuzz-prepare.sh [target]   (from the repository root;
#        every target when none is given)
set -euo pipefail

CARGO_FUZZ_VERSION=0.13.2

if [ "$(cargo fuzz --version 2>/dev/null || true)" != "cargo-fuzz $CARGO_FUZZ_VERSION" ]; then
    cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked
fi
python3 scripts/align-fuzz-lock.py
cargo fuzz build --sanitizer none "$@"
