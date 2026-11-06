//! The client's ML-KEM-768 encapsulation key and X25519 share; either
//! half failing aborts.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::kex;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    let _ = kex::hybrid_exchange(data);
});
