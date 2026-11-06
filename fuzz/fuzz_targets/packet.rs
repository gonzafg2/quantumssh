//! Plaintext binary packet framing and padding (RFC 4253 §6).
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::wire;
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    // As the transport reads a plaintext packet: the length field, then
    // exactly that many body bytes.
    let Some((length, rest)) = data.split_first_chunk::<4>() else {
        return;
    };
    let Ok(body_len) = wire::validate_packet_length(u32::from_be_bytes(*length)) else {
        return;
    };
    if let Some(body) = rest.get(..body_len) {
        let _ = wire::decode_packet_body(body);
    }
});
