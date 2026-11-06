//! SFTP framing and field parsing. The request handlers are not run: they
//! pass paths to the OS unconfined (ADR-0060 §4).
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    fuzzing::sftp(data);
});
