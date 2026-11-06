//! What every fuzz target shares (ADR-0060): the allocator cap of §5 and
//! the fixtures of §4, written by `scripts/fuzz-seeds.py`.
//!
//! Each target links this crate, so each gets the capped allocator.

use cap::Cap;
use std::alloc::System;

/// ADR-0060 §5: more than 64 MiB of live Rust heap aborts, and libFuzzer
/// records the input. The largest legitimate buffer is an SFTP packet of
/// at most 256 KiB; a 32-bit length field can ask for 4 GiB.
#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, 64 * 1024 * 1024);

/// The `userauth_request` target's `authorized_keys`: the Ed25519 public
/// key of RFC 8032 §7.1 TEST 1.
pub const AUTHORIZED_KEYS: &str = include_str!("../fixtures/authorized_keys");

/// The `user_certificate` target's `trusted_user_ca_keys`: the composite
/// key of the OpenSSH golden vector.
pub const TRUSTED_USER_CA_KEYS: &str = include_str!("../fixtures/trusted_user_ca_keys");

/// The `userauth_request` target's session id.
pub const SESSION_ID: [u8; 32] = [0x5a; 32];

/// The seeds of the `handshake` target's host key.
pub const HOST_KEY_SEEDS: [u8; 64] = [0x42; 64];
