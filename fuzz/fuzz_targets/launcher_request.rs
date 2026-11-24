//! A record from the network server, as the root launcher parses it
//! (ADR-0063 §6): the one parser at the privilege boundary of account mode.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::fuzzing;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    fuzzing::launcher_request(data);
});
