//! The channel layer's inbound messages and window arithmetic (#271). The
//! handlers are not run: they spawn processes (ADR-0060 §4).
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    fuzzing::channel(data);
});
