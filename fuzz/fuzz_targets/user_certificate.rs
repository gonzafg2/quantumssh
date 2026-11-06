//! The OpenSSH user certificate: its fields, principals and options, and
//! the composite CA signature, at a fixed clock.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing::UserCertificate;
use quantumssh_fuzz::TRUSTED_USER_CA_KEYS;
use std::sync::LazyLock;

static FIXTURE: LazyLock<UserCertificate> =
    LazyLock::new(|| UserCertificate::new(TRUSTED_USER_CA_KEYS));

fuzz_target!(|data: &[u8]| {
    FIXTURE.check(data);
});
