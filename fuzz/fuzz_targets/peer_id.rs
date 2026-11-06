//! The client identification line (RFC 4253 §4.2).
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::wire;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    let _ = wire::parse_peer_id(data);
});
