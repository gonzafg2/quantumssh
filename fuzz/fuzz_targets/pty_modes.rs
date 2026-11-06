//! The `pty-req` terminal modes (RFC 4254 §8) and `TERM`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    fuzzing::pty_modes(data);
});
