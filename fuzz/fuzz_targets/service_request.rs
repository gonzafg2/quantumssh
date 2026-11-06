//! `SSH_MSG_SERVICE_REQUEST` (RFC 4253 §10).
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    fuzzing::service_request(data);
});
