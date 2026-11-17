#!/usr/bin/env bash
# Records the AES-256 key schedules of the `aes` crate's software backend
# for a fixed key, in the two forms that backend holds them:
#   - compact: the 240 bytes the cipher object stores;
#   - native64: the 960 bytes it widens them to for each call, on a
#     target with 64-bit words.
#
# The stack-residue tests of crates/quantumssh-core/src/cipher.rs search
# the stack for these bytes when they are built with
# `--cfg aes_backend="soft"` (ADR-0061 §5). No public API exposes them,
# so this program reads the cipher object through `unsafe`. That is why
# it is built here, in a throwaway package outside the workspace, which
# forbids `unsafe` (ADR-0018).
#
# Usage: bash scripts/capture-aes-fixslice-schedule.sh \
#            > crates/quantumssh-core/tests/vectors/aes256-fixslice-schedule.txt
#
# Run it from the repository root, on a 64-bit target. It pins the `aes`
# version the root Cargo.lock resolves.
set -euo pipefail

aes_version="$(awk '/^name = "aes"$/ { getline; gsub(/[^0-9.]/, "", $3); print $3; exit }' Cargo.lock)"
[ -n "$aes_version" ] || { echo "error: no aes entry in Cargo.lock" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/src"

cat > "$work/Cargo.toml" <<EOF
[package]
name = "capture-aes-fixslice-schedule"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
aes = { version = "=$aes_version", default-features = false }
EOF

cat > "$work/src/main.rs" <<'EOF'
use aes::Aes256;
use aes::cipher::{Array, KeyInit, consts::U32};

/// One compact round-key word as the backend widens it to 64 bits.
fn widen(b: u16) -> u64 {
    let x = u64::from(b);
    let x = (x | (x << 24)) & 0x0000_00ff_0000_00ff;
    let x = (x | (x << 12)) & 0x000f_000f_000f_000f;
    let x = (x | (x << 6)) & 0x0303_0303_0303_0303;
    let x = (x | (x << 3)) & 0x1111_1111_1111_1111;
    x | (x << 1) | (x << 2) | (x << 3)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    assert!(
        !aes::hardware_accelerated(),
        "the hardware backend is in use: build with --cfg aes_backend=\"soft\""
    );
    assert_eq!(size_of::<usize>(), 8, "a 64-bit target is required");
    assert_eq!(
        size_of::<Aes256>(),
        240,
        "the cipher object is not the 240-byte compact schedule: the representation changed"
    );
    // The SHA-256 initial hash value (FIPS 180-4 §5.3.3): 32 bytes with
    // no structure. A patterned key, such as 00 01 02 …, gives schedule
    // chunks of zeros and of bit masks, which any stack holds.
    let key: [u8; 32] = [
        0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5,
        0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0,
        0xcd, 0x19,
    ];
    let cipher = Box::new(Aes256::new(&Array::<u8, U32>::from(key)));
    // SAFETY: `cipher` is a live, initialized `Aes256` of exactly 240
    // bytes, checked above, and is read as bytes without being moved.
    let compact =
        unsafe { std::slice::from_raw_parts((&raw const *cipher).cast::<u8>(), 240) }.to_vec();
    let native: Vec<u8> = compact
        .chunks_exact(2)
        .flat_map(|c| widen(u16::from_ne_bytes([c[0], c[1]])).to_ne_bytes())
        .collect();
    println!("key = {}", hex(&key));
    println!("compact = {}", hex(&compact));
    println!("native64 = {}", hex(&native));
}
EOF

rustc_version="$(rustc --version)"
values="$(cd "$work" && RUSTFLAGS='--cfg aes_backend="soft"' cargo run --release --quiet)"

cat <<EOF
# AES-256 key schedules of the software (fixslice) backend of the \`aes\`
# crate, for a key that is the SHA-256 initial hash value, captured by
# scripts/capture-aes-fixslice-schedule.sh:
#   aes: $aes_version, built with --cfg aes_backend="soft"
#   toolchain: $rustc_version
#   target: $(rustc --print host-tuple)
# compact is the 240 bytes the cipher object stores. native64 is the 960
# bytes the backend widens them to for each call on a 64-bit target.
# Both are in the target's byte order. Do not edit by hand.

$values
EOF
