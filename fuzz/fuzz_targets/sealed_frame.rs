//! Encrypted packet framing: length decryption, the length bound and the
//! tag check, for both AEAD ciphers with fixed keys.
//!
//! Input: a selector byte (even: ChaCha20-Poly1305, odd: AES-256-GCM),
//! a sequence number, the four length bytes, then the body and tag.
//!
//! The sequence number is the receiver's own counter, not a wire field.
//! ChaCha20-Poly1305 derives its nonce from it, so the target takes it
//! from the input. AES-256-GCM derives its nonce from an invocation
//! counter that the transport keeps in step with the sequence number
//! (`open` asserts it), so a fresh cipher is opened at sequence number 0.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::cipher::{AES256_GCM, CHACHA20_POLY1305, PacketCipher};
use quantumssh_fuzz as _;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Some((seqnr, rest)) = rest.split_first_chunk::<4>() else {
        return;
    };
    let Some((length, rest)) = rest.split_first_chunk::<4>() else {
        return;
    };
    let (cipher, seqnr) = if selector % 2 == 0 {
        (
            PacketCipher::new(CHACHA20_POLY1305, &[0x11; 64], &[]),
            u32::from_be_bytes(*seqnr),
        )
    } else {
        (PacketCipher::new(AES256_GCM, &[0x22; 32], &[0x33; 12]), 0)
    };
    let mut cipher = cipher.expect("fixed key and IV lengths");
    // As the transport reads a sealed packet: the length the cipher
    // yields, then exactly that many bytes.
    let Ok(body_len) = cipher.body_len(seqnr, *length) else {
        return;
    };
    if let Some(body) = rest.get(..body_len) {
        let mut body = body.to_vec();
        let _ = cipher.open(seqnr, *length, &mut body);
    }
});
