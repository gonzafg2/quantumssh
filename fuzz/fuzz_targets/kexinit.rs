//! `SSH_MSG_KEXINIT` and negotiation, for the first exchange and for a
//! rekey: the `initial` flag is the only difference between the two.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::kex;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    if let Ok(peer) = kex::parse_kexinit(data) {
        let _ = kex::negotiate(&peer, true);
        let _ = kex::negotiate(&peer, false);
    }
});
