//! `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 §7) with and without a signature,
//! and Ed25519 verification for a request naming the fixture key.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing::Userauth;
use quantumssh_fuzz::{AUTHORIZED_KEYS, SESSION_ID};
use std::sync::LazyLock;

static FIXTURE: LazyLock<Userauth> = LazyLock::new(|| Userauth::new(AUTHORIZED_KEYS, SESSION_ID));

fuzz_target!(|data: &[u8]| {
    FIXTURE.check(data);
});
