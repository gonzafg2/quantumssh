//! AEAD packet ciphers for the encrypted transport: the two — and
//! only two — ciphers of the ADR-0021 profile.
//!
//! - **`chacha20-poly1305@openssh.com`** (OpenSSH
//!   `PROTOCOL.chacha20poly1305`): two independent 256-bit keys; the
//!   packet length is encrypted separately under the header key; the
//!   per-packet Poly1305 key is the first 32 bytes of the main key's
//!   block-0 keystream; the nonce is the packet sequence number as a
//!   64-bit big-endian integer. This cannot be expressed through the
//!   IETF AEAD construction (96-bit nonce, single key), so it is
//!   assembled here from the loose `chacha20` + `poly1305` primitives.
//! - **`aes256-gcm@openssh.com`** (RFC 5647): the packet length stays
//!   in cleartext and is authenticated as AAD; the 12-byte nonce is a
//!   4-byte fixed field plus a 64-bit invocation counter incremented
//!   per packet, both seeded from the derived IV.
//!
//! Both directions of a connection hold one [`PacketCipher`] each,
//! constructed from the RFC 4253 §7.2 key material after NEWKEYS.
//!
//! Fail-closed: a packet whose tag does not verify is **never**
//! partially processed — the length check happens before the body is
//! read, and the tag check happens before decryption is attempted
//! (encrypt-then-MAC order in both constructions).

use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::wire::{self, WireError};

/// `chacha20-poly1305@openssh.com` (ADR-0021 §3–4, client's first
/// preference in stock OpenSSH).
pub const CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";
/// `aes256-gcm@openssh.com` (ADR-0021 §3–4).
pub const AES256_GCM: &str = "aes256-gcm@openssh.com";

/// Authentication tag length — 16 bytes in both constructions.
pub const TAG_LEN: usize = 16;

/// Errors from the AEAD packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// The authentication tag did not verify, or decryption failed.
    /// Fail closed: nothing about the packet is trustworthy.
    BadTag,
    /// The (decrypted or cleartext) length field is invalid.
    Wire(WireError),
}

impl From<WireError> for CipherError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadTag => write!(f, "packet authentication failed"),
            Self::Wire(e) => write!(f, "invalid packet length: {e}"),
        }
    }
}

impl std::error::Error for CipherError {}

/// One direction's packet cipher, selected by negotiation.
pub enum PacketCipher {
    /// `chacha20-poly1305@openssh.com`.
    ChaCha(ChaCha20Poly1305Openssh),
    /// `aes256-gcm@openssh.com` (boxed: the AES round keys make
    /// it an order of magnitude larger than the `ChaCha20` state).
    Gcm(Box<Aes256GcmOpenssh>),
}

impl std::fmt::Debug for PacketCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material — name only.
        f.write_str(match self {
            Self::ChaCha(_) => "PacketCipher(chacha20-poly1305@openssh.com)",
            Self::Gcm(_) => "PacketCipher(aes256-gcm@openssh.com)",
        })
    }
}

impl PacketCipher {
    /// Bytes of key material this cipher needs from the RFC 4253 §7.2
    /// derivation (letter `'C'`/`'D'`).
    #[must_use]
    pub const fn key_len(name: &str) -> usize {
        // Single comparison over the two profile names; both are
        // compile-time constants.
        if matches!(name.as_bytes(), b"chacha20-poly1305@openssh.com") {
            64
        } else {
            32
        }
    }

    /// Bytes of IV material this cipher needs (letter `'A'`/`'B'`).
    /// The `ChaCha20` construction takes none — its nonce is the packet
    /// sequence number.
    #[must_use]
    pub const fn iv_len(name: &str) -> usize {
        if matches!(name.as_bytes(), b"chacha20-poly1305@openssh.com") {
            0
        } else {
            12
        }
    }

    /// Constructs one direction's cipher from derived key material.
    ///
    /// # Errors
    ///
    /// [`CipherError::Wire`] when `name` is not one of the two profile
    /// ciphers, or when `key`/`iv` are not exactly the lengths
    /// [`PacketCipher::key_len`] / [`PacketCipher::iv_len`] mandate.
    pub fn new(name: &str, key: &[u8], iv: &[u8]) -> Result<Self, CipherError> {
        if key.len() != Self::key_len(name) || iv.len() != Self::iv_len(name) {
            return Err(CipherError::Wire(WireError::Truncated));
        }
        match name {
            CHACHA20_POLY1305 => Ok(Self::ChaCha(ChaCha20Poly1305Openssh::new(key))),
            AES256_GCM => Ok(Self::Gcm(Box::new(Aes256GcmOpenssh::new(key, iv)))),
            _ => Err(CipherError::Wire(WireError::Truncated)),
        }
    }

    /// Seals one payload into a complete wire packet
    /// (`length ‖ ciphertext ‖ tag`).
    ///
    /// # Errors
    ///
    /// [`CipherError::Wire`] if the payload cannot fit in a legal
    /// packet, or if the system random source fails to produce the
    /// padding.
    pub fn seal(&mut self, seqnr: u32, payload: &[u8]) -> Result<Vec<u8>, CipherError> {
        match self {
            Self::ChaCha(c) => c.seal(seqnr, payload),
            Self::Gcm(c) => c.seal(seqnr, payload),
        }
    }

    /// Validates the 4 length bytes that precede a packet body and
    /// returns how many further bytes the packet occupies (body plus
    /// tag). This is the bound applied **before** any allocation.
    ///
    /// # Errors
    ///
    /// [`CipherError::Wire`] when the (decrypted, for `ChaCha20`)
    /// length is outside the legal range or misaligned.
    pub fn body_len(&self, seqnr: u32, length_bytes: [u8; 4]) -> Result<usize, CipherError> {
        match self {
            Self::ChaCha(c) => c.body_len(seqnr, length_bytes),
            Self::Gcm(_) => {
                let packet_length = u32::from_be_bytes(length_bytes);
                Ok(validate_aead_length(packet_length, Aes256GcmOpenssh::BLOCK)? + TAG_LEN)
            }
        }
    }

    /// Opens one packet: verifies the tag, decrypts, strips padding,
    /// and returns the payload. `body` is the [`PacketCipher::body_len`]
    /// bytes that followed `length_bytes` on the wire.
    ///
    /// # Errors
    ///
    /// [`CipherError::BadTag`] when authentication fails — fail
    /// closed, nothing decrypted; [`CipherError::Wire`] when the
    /// authenticated plaintext violates RFC 4253 §6 padding rules.
    pub fn open(
        &mut self,
        seqnr: u32,
        length_bytes: [u8; 4],
        body: &mut [u8],
    ) -> Result<Vec<u8>, CipherError> {
        match self {
            Self::ChaCha(c) => c.open(seqnr, length_bytes, body),
            Self::Gcm(c) => c.open(seqnr, length_bytes, body),
        }
    }
}

/// Validates an AEAD `packet_length`: bounded by [`wire::MAX_PACKET`]
/// **before** any allocation, big enough for `padding_length` plus
/// minimum padding, and aligned to the cipher's block. The length
/// field itself is *not* part of the aligned region in either AEAD
/// construction (PROTOCOL.chacha20poly1305; RFC 5647 §5.2).
fn validate_aead_length(packet_length: u32, block: usize) -> Result<usize, CipherError> {
    if packet_length > wire::MAX_PACKET
        || packet_length < 1 + u32::from(wire::MIN_PADDING)
        || !(packet_length as usize).is_multiple_of(block)
    {
        return Err(CipherError::Wire(WireError::BadPacketLength(packet_length)));
    }
    Ok(packet_length as usize)
}

/// Builds `padding_length ‖ payload ‖ random padding` such that the
/// whole region is the smallest multiple of `block` with at least
/// [`wire::MIN_PADDING`] bytes of padding (the 4 length bytes are
/// excluded from alignment in both AEAD constructions).
fn padded_body(payload: &[u8], block: usize) -> Result<Vec<u8>, CipherError> {
    let unpadded = 1 + payload.len();
    let mut padding = block - (unpadded % block);
    while padding < usize::from(wire::MIN_PADDING) {
        padding += block;
    }
    let packet_length = unpadded + padding;
    if u32::try_from(packet_length).map_or(true, |l| l > wire::MAX_PACKET) {
        return Err(CipherError::Wire(WireError::BadPacketLength(u32::MAX)));
    }
    let mut body = Vec::with_capacity(packet_length);
    // padding fits in u8: at most block + MIN_PADDING (20).
    body.push(u8::try_from(padding).map_err(|_| CipherError::Wire(WireError::BadPadding))?);
    body.extend_from_slice(payload);
    let mut pad = vec![0u8; padding];
    getrandom::fill(&mut pad).map_err(|_| CipherError::Wire(WireError::Truncated))?;
    body.extend_from_slice(&pad);
    Ok(body)
}

/// `chacha20-poly1305@openssh.com` (OpenSSH
/// `PROTOCOL.chacha20poly1305`).
pub struct ChaCha20Poly1305Openssh {
    /// `K_2` in the OpenSSH document: encrypts the packet body and
    /// generates the per-packet Poly1305 key.
    k_main: Zeroizing<[u8; 32]>,
    /// `K_1`: encrypts the 4-byte length field, and nothing else.
    k_header: Zeroizing<[u8; 32]>,
}

impl ChaCha20Poly1305Openssh {
    /// Body alignment block (RFC 4253 §6 minimum — the length field is
    /// excluded from the padded region in this construction).
    const BLOCK: usize = 8;

    /// Splits the 64 bytes of derived key material:
    /// the **first** 32 bytes are the main key, the **second** 32 the
    /// header key (PROTOCOL.chacha20poly1305 §"chacha20-poly1305").
    fn new(key: &[u8]) -> Self {
        let mut k_main = Zeroizing::new([0u8; 32]);
        let mut k_header = Zeroizing::new([0u8; 32]);
        k_main.copy_from_slice(&key[..32]);
        k_header.copy_from_slice(&key[32..64]);
        Self { k_main, k_header }
    }

    /// The per-packet Poly1305 key: the first 32 bytes of the main
    /// key's keystream at block counter 0 for this sequence number.
    fn poly_key(&self, nonce: [u8; 8]) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut stream = ChaCha20Legacy::new((&*self.k_main).into(), (&nonce).into());
        stream.apply_keystream(key.as_mut());
        key
    }

    fn seal(&self, seqnr: u32, payload: &[u8]) -> Result<Vec<u8>, CipherError> {
        let nonce = u64::from(seqnr).to_be_bytes();
        let mut body = padded_body(payload, Self::BLOCK)?;
        let packet_length =
            u32::try_from(body.len()).map_err(|_| CipherError::Wire(WireError::BadPadding))?;

        // Length: encrypted under the header key, block counter 0.
        let mut length_bytes = packet_length.to_be_bytes();
        ChaCha20Legacy::new((&*self.k_header).into(), (&nonce).into())
            .apply_keystream(&mut length_bytes);

        // Body: main key, keystream starting at block 1 (the first
        // block is reserved for the Poly1305 key).
        let mut stream = ChaCha20Legacy::new((&*self.k_main).into(), (&nonce).into());
        stream.seek(64u32);
        stream.apply_keystream(&mut body);

        // Tag over everything sent: encrypted length ‖ encrypted body.
        let poly_key = self.poly_key(nonce);
        let tag = finalize_openssh_poly(&poly_key, length_bytes, &body);

        let mut out = Vec::with_capacity(4 + body.len() + TAG_LEN);
        out.extend_from_slice(&length_bytes);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn body_len(&self, seqnr: u32, length_bytes: [u8; 4]) -> Result<usize, CipherError> {
        let nonce = u64::from(seqnr).to_be_bytes();
        let mut decrypted = length_bytes;
        ChaCha20Legacy::new((&*self.k_header).into(), (&nonce).into())
            .apply_keystream(&mut decrypted);
        let packet_length = u32::from_be_bytes(decrypted);
        validate_aead_length(packet_length, Self::BLOCK).map(|len| len + TAG_LEN)
    }

    fn open(
        &self,
        seqnr: u32,
        length_bytes: [u8; 4],
        body: &mut [u8],
    ) -> Result<Vec<u8>, CipherError> {
        let nonce = u64::from(seqnr).to_be_bytes();
        let Some(ct_len) = body.len().checked_sub(TAG_LEN) else {
            return Err(CipherError::BadTag);
        };
        let (ciphertext, tag) = body.split_at_mut(ct_len);

        // Verify BEFORE decrypting (encrypt-then-MAC), constant-time.
        let poly_key = self.poly_key(nonce);
        let expected = finalize_openssh_poly(&poly_key, length_bytes, ciphertext);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(CipherError::BadTag);
        }

        let mut stream = ChaCha20Legacy::new((&*self.k_main).into(), (&nonce).into());
        stream.seek(64u32);
        stream.apply_keystream(ciphertext);
        Ok(wire::decode_packet_body(ciphertext)?.to_vec())
    }
}

/// Poly1305 over `encrypted_length ‖ encrypted_body` exactly as
/// OpenSSH computes it: one flat message, no padding between the two
/// regions and no length suffix (this is *not* the IETF AEAD MAC).
fn finalize_openssh_poly(key: &[u8; 32], length_bytes: [u8; 4], ciphertext: &[u8]) -> [u8; 16] {
    let mut msg = Vec::with_capacity(4 + ciphertext.len());
    msg.extend_from_slice(&length_bytes);
    msg.extend_from_slice(ciphertext);
    Poly1305::new_from_slice(key)
        .expect("poly1305 key is exactly 32 bytes")
        .compute_unpadded(&msg)
        .into()
}

/// `aes256-gcm@openssh.com` (RFC 5647, with the RFC 5116 §5.1 nonce:
/// 4-byte fixed field ‖ 8-byte invocation counter).
pub struct Aes256GcmOpenssh {
    cipher: Aes256Gcm,
    fixed: [u8; 4],
    invocation: u64,
    initial_invocation: u64,
}

impl Aes256GcmOpenssh {
    /// Body alignment block: the AES block size; the cleartext length
    /// field is excluded from the padded region (RFC 5647 §5.2).
    const BLOCK: usize = 16;

    fn new(key: &[u8], iv: &[u8]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("aes-256-gcm key is exactly 32 bytes");
        let mut fixed = [0u8; 4];
        fixed.copy_from_slice(&iv[..4]);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&iv[4..12]);
        let initial_invocation = u64::from_be_bytes(counter);
        Self {
            cipher,
            fixed,
            invocation: initial_invocation,
            initial_invocation,
        }
    }

    /// The current nonce; the invocation counter advances by one per
    /// packet, in lockstep with the peer (RFC 5647 §7.1).
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.fixed);
        nonce[4..].copy_from_slice(&self.invocation.to_be_bytes());
        nonce
    }

    fn seal(&mut self, seqnr: u32, payload: &[u8]) -> Result<Vec<u8>, CipherError> {
        debug_assert_eq!(
            self.invocation.wrapping_sub(self.initial_invocation),
            u64::from(seqnr),
            "GCM invocation counter out of sync on seal"
        );
        let mut body = padded_body(payload, Self::BLOCK)?;
        let packet_length =
            u32::try_from(body.len()).map_err(|_| CipherError::Wire(WireError::BadPadding))?;
        let length_bytes = packet_length.to_be_bytes();

        let nonce = self.nonce();
        let nonce_arr = Nonce::try_from(&nonce[..]).expect("gcm nonce is 12 bytes");
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &nonce_arr,
                &length_bytes,
                InOutBuf::from(body.as_mut_slice()),
            )
            .map_err(|_| CipherError::BadTag)?;
        self.invocation = self.invocation.wrapping_add(1);

        let mut out = Vec::with_capacity(4 + body.len() + TAG_LEN);
        out.extend_from_slice(&length_bytes);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn open(
        &mut self,
        seqnr: u32,
        length_bytes: [u8; 4],
        body: &mut [u8],
    ) -> Result<Vec<u8>, CipherError> {
        debug_assert_eq!(
            self.invocation.wrapping_sub(self.initial_invocation),
            u64::from(seqnr),
            "GCM invocation counter out of sync on open"
        );
        let Some(ct_len) = body.len().checked_sub(TAG_LEN) else {
            return Err(CipherError::BadTag);
        };
        let (ciphertext, tag) = body.split_at_mut(ct_len);

        let nonce = self.nonce();
        let nonce_arr = Nonce::try_from(&nonce[..]).expect("gcm nonce is 12 bytes");
        let tag_arr = aes_gcm::Tag::try_from(&*tag).map_err(|_| CipherError::BadTag)?;
        self.cipher
            .decrypt_inout_detached(
                &nonce_arr,
                &length_bytes,
                InOutBuf::from(&mut *ciphertext),
                &tag_arr,
            )
            .map_err(|_| CipherError::BadTag)?;
        self.invocation = self.invocation.wrapping_add(1);
        Ok(wire::decode_packet_body(ciphertext)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chacha_pair() -> (PacketCipher, PacketCipher) {
        // 64 bytes of key material, distinct halves so a swapped
        // main/header key cannot pass the round-trip tests.
        let key: Vec<u8> = (0u8..64).collect();
        (
            PacketCipher::new(CHACHA20_POLY1305, &key, &[]).unwrap(),
            PacketCipher::new(CHACHA20_POLY1305, &key, &[]).unwrap(),
        )
    }

    fn gcm_pair() -> (PacketCipher, PacketCipher) {
        let key: Vec<u8> = (100u8..132).collect();
        let iv: Vec<u8> = (1u8..13).collect();
        (
            PacketCipher::new(AES256_GCM, &key, &iv).unwrap(),
            PacketCipher::new(AES256_GCM, &key, &iv).unwrap(),
        )
    }

    fn roundtrip(tx: &mut PacketCipher, rx: &mut PacketCipher, seqnr: u32, payload: &[u8]) {
        let packet = tx.seal(seqnr, payload).unwrap();
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&packet[..4]);
        let body_len = rx.body_len(seqnr, length_bytes).unwrap();
        assert_eq!(body_len, packet.len() - 4, "declared body length");
        let mut body = packet[4..].to_vec();
        let opened = rx.open(seqnr, length_bytes, &mut body).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn chacha20_legacy_keystream_known_answer() {
        // djb's original ChaCha20 test vector: all-zero 256-bit key,
        // all-zero 64-bit nonce, counter 0. Pins the `chacha20` crate
        // to the variant PROTOCOL.chacha20poly1305 requires.
        let mut block = [0u8; 32];
        ChaCha20Legacy::new(&[0u8; 32].into(), &[0u8; 8].into()).apply_keystream(&mut block);
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7,
        ];
        assert_eq!(block, expected);
    }

    #[test]
    fn poly1305_rfc8439_known_answer() {
        // RFC 8439 §2.5.2 test vector, computed through the same
        // one-shot path `finalize_openssh_poly` uses.
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag: [u8; 16] = Poly1305::new(&key.into()).compute_unpadded(msg).into();
        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn chacha_roundtrip_across_sizes_and_sequence_numbers() {
        let (mut tx, mut rx) = chacha_pair();
        for (seqnr, size) in [(0u32, 1usize), (1, 8), (2, 255), (3, 4096), (7, 32_000)] {
            let payload: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
            roundtrip(&mut tx, &mut rx, seqnr, &payload);
        }
    }

    #[test]
    fn gcm_roundtrip_across_sizes() {
        let (mut tx, mut rx) = gcm_pair();
        // GCM's invocation counter advances per packet on BOTH sides —
        // sealing and opening must stay in lockstep. Seqnr must match
        // the invocation delta (debug-asserted).
        for (seqnr, size) in (0u32..).zip([1usize, 16, 255, 4096, 32_000]) {
            let payload: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
            roundtrip(&mut tx, &mut rx, seqnr, &payload);
        }
    }

    #[test]
    fn chacha_wrong_sequence_number_fails_closed() {
        let (mut tx, rx) = chacha_pair();
        let packet = tx.seal(5, b"payload").unwrap();
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&packet[..4]);
        // Sealed with seqnr 5, read with seqnr 6: the wrong nonce
        // decrypts the length to garbage, which body_len can only reject
        // as a bad packet length (the sole failure `validate_aead_length`
        // returns).
        assert!(matches!(
            rx.body_len(6, length_bytes),
            Err(CipherError::Wire(WireError::BadPacketLength(_)))
        ));
    }

    #[test]
    fn every_flipped_bit_is_rejected() {
        for (mut tx, mut rx, seqnr) in [
            {
                let (a, b) = chacha_pair();
                (a, b, 0u32)
            },
            {
                let (a, b) = gcm_pair();
                (a, b, 0u32)
            },
        ] {
            let packet = tx.seal(seqnr, b"attack at dawn").unwrap();
            for i in 0..packet.len() {
                let mut tampered = packet.clone();
                tampered[i] ^= 0x01;
                let mut length_bytes = [0u8; 4];
                length_bytes.copy_from_slice(&tampered[..4]);
                let outcome = rx.body_len(seqnr, length_bytes).and_then(|_| {
                    let mut body = tampered[4..].to_vec();
                    rx.open(seqnr, length_bytes, &mut body)
                });
                assert!(outcome.is_err(), "flipped byte {i} must be rejected");
            }
        }
    }

    #[test]
    fn gcm_nonce_advances_per_packet() {
        let (mut tx, _) = gcm_pair();
        let a = tx.seal(0, b"same payload").unwrap();
        let b = tx.seal(1, b"same payload").unwrap();
        // Identical plaintext, the invocation counter (driven by
        // sequential seqnr) makes the two ciphertexts differ.
        assert_ne!(a, b);
    }

    #[test]
    fn oversized_declared_length_is_rejected_before_allocation() {
        let (_, rx) = gcm_pair();
        let length_bytes = (wire::MAX_PACKET + 16).to_be_bytes();
        assert!(matches!(
            rx.body_len(0, length_bytes),
            Err(CipherError::Wire(WireError::BadPacketLength(_)))
        ));
    }

    #[test]
    fn key_and_iv_lengths_are_enforced() {
        assert!(PacketCipher::new(CHACHA20_POLY1305, &[0u8; 32], &[]).is_err());
        assert!(PacketCipher::new(AES256_GCM, &[0u8; 32], &[0u8; 11]).is_err());
        assert!(PacketCipher::new("aes128-ctr", &[0u8; 16], &[0u8; 16]).is_err());
        assert_eq!(PacketCipher::key_len(CHACHA20_POLY1305), 64);
        assert_eq!(PacketCipher::iv_len(CHACHA20_POLY1305), 0);
        assert_eq!(PacketCipher::key_len(AES256_GCM), 32);
        assert_eq!(PacketCipher::iv_len(AES256_GCM), 12);
    }
}
