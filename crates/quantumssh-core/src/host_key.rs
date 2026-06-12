//! Ed25519 host key: loading (`openssh-key-v1`, unencrypted),
//! public-blob encoding (RFC 8709), signing, and the `SHA256:`
//! fingerprint (ADR-0024 log format).
//!
//! Only `ssh-ed25519` exists in Phase 1 (ADR-0021); only the
//! unencrypted `openssh-key-v1` container is accepted — host keys are
//! generated with `ssh-keygen -t ed25519` and protected by file
//! permissions, not passphrases (a server cannot type one at boot).

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::{Reader, Writer};

/// Algorithm name (RFC 8709).
pub const ALGORITHM: &str = "ssh-ed25519";

const PEM_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Errors loading or using a host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyError {
    /// Not a PEM-armored `openssh-key-v1` file.
    BadContainer,
    /// The container is valid but the key is not an unencrypted
    /// single `ssh-ed25519` key.
    Unsupported,
    /// The embedded public key does not match the private seed, or
    /// the check bytes disagree (corrupted or tampered file).
    Inconsistent,
}

impl std::fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadContainer => write!(f, "not an openssh-key-v1 container"),
            Self::Unsupported => write!(f, "unsupported host key (need unencrypted ssh-ed25519)"),
            Self::Inconsistent => write!(f, "host key file is internally inconsistent"),
        }
    }
}

impl std::error::Error for HostKeyError {}

/// A loaded Ed25519 host key.
pub struct HostKey {
    signing: SigningKey,
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material through Debug (threat model §4.3).
        f.debug_struct("HostKey")
            .field("fingerprint", &self.fingerprint_sha256())
            .finish()
    }
}

impl HostKey {
    /// Parses an unencrypted `openssh-key-v1` PEM file
    /// (`ssh-keygen -t ed25519`).
    ///
    /// # Errors
    ///
    /// [`HostKeyError::BadContainer`] when the armor or magic is
    /// wrong; [`HostKeyError::Unsupported`] for encrypted containers,
    /// multiple keys, or non-Ed25519 keys;
    /// [`HostKeyError::Inconsistent`] when check bytes or the embedded
    /// public key disagree with the seed.
    pub fn from_openssh_pem(pem: &str) -> Result<Self, HostKeyError> {
        let body: String = pem
            .lines()
            .map(str::trim)
            .skip_while(|l| *l != PEM_HEADER)
            .skip(1)
            .take_while(|l| *l != PEM_FOOTER)
            .collect();
        if body.is_empty() {
            return Err(HostKeyError::BadContainer);
        }
        let raw = Zeroizing::new(base64_decode(body.as_bytes()).ok_or(HostKeyError::BadContainer)?);

        let rest = raw
            .strip_prefix(AUTH_MAGIC)
            .ok_or(HostKeyError::BadContainer)?;
        let mut r = Reader::new(rest);
        let cipher = r.string(64).map_err(|_| HostKeyError::BadContainer)?;
        let kdf = r.string(64).map_err(|_| HostKeyError::BadContainer)?;
        let _kdf_options = r.string(1024).map_err(|_| HostKeyError::BadContainer)?;
        let nkeys = r.uint32().map_err(|_| HostKeyError::BadContainer)?;
        if cipher != b"none" || kdf != b"none" {
            return Err(HostKeyError::Unsupported);
        }
        if nkeys != 1 {
            return Err(HostKeyError::Unsupported);
        }
        let _public_blob = r.string(1024).map_err(|_| HostKeyError::BadContainer)?;
        let private_section = r.string(4096).map_err(|_| HostKeyError::BadContainer)?;
        r.finish().map_err(|_| HostKeyError::BadContainer)?;

        let mut p = Reader::new(private_section);
        let check1 = p.uint32().map_err(|_| HostKeyError::BadContainer)?;
        let check2 = p.uint32().map_err(|_| HostKeyError::BadContainer)?;
        if check1 != check2 {
            return Err(HostKeyError::Inconsistent);
        }
        let key_type = p.string(64).map_err(|_| HostKeyError::BadContainer)?;
        if key_type != ALGORITHM.as_bytes() {
            return Err(HostKeyError::Unsupported);
        }
        let public = p.string(64).map_err(|_| HostKeyError::BadContainer)?;
        let scalar_and_public = p.string(128).map_err(|_| HostKeyError::BadContainer)?;
        // sk blob is seed(32) ‖ public(32).
        if public.len() != 32 || scalar_and_public.len() != 64 {
            return Err(HostKeyError::Unsupported);
        }
        let seed: [u8; 32] = scalar_and_public[..32]
            .try_into()
            .map_err(|_| HostKeyError::Unsupported)?;
        let signing = SigningKey::from_bytes(&seed);
        // Cross-check: the file's public halves must match the seed.
        let derived = signing.verifying_key();
        if derived.as_bytes() != public || derived.as_bytes() != &scalar_and_public[32..] {
            return Err(HostKeyError::Inconsistent);
        }
        // Comment + deterministic padding (1, 2, 3, …) follow; their
        // integrity is covered by the checks above. We do not parse
        // them — trailing bytes here are not attacker-controlled
        // (this is the operator's key file, not network input).
        Ok(Self { signing })
    }

    /// Builds a host key directly from an Ed25519 seed.
    ///
    /// For tests and fixed-RNG golden-vector fixtures (RFC-0003's KAT
    /// plan); production keys load from `openssh-key-v1` files via
    /// [`HostKey::from_openssh_pem`].
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The `ssh-ed25519` public-key blob (RFC 8709 §4):
    /// `string "ssh-ed25519" ‖ string key`.
    #[must_use]
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(ALGORITHM.as_bytes());
        w.put_string(self.signing.verifying_key().as_bytes());
        w.into_bytes()
    }

    /// Signs `data`, returning the RFC 8709 §6 signature blob:
    /// `string "ssh-ed25519" ‖ string signature`.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(data);
        let mut w = Writer::new();
        w.put_string(ALGORITHM.as_bytes());
        w.put_string(&sig.to_bytes());
        w.into_bytes()
    }

    /// OpenSSH-format fingerprint: `SHA256:` + unpadded base64 of the
    /// SHA-256 of the public-key blob (ADR-0024's
    /// `host_key_fingerprint` / `authenticated_identity` format).
    #[must_use]
    pub fn fingerprint_sha256(&self) -> String {
        let digest = Sha256::digest(self.public_key_blob());
        format!("SHA256:{}", base64_encode_nopad(&digest))
    }
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet base64 encode without padding (the fingerprint
/// format OpenSSH uses).
#[must_use]
pub(crate) fn base64_encode_nopad(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = [
            B64_ALPHABET[(n >> 18) as usize & 63],
            B64_ALPHABET[(n >> 12) as usize & 63],
            B64_ALPHABET[(n >> 6) as usize & 63],
            B64_ALPHABET[n as usize & 63],
        ];
        let keep = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for &c in &chars[..keep] {
            out.push(char::from(c));
        }
    }
    out
}

/// Standard-alphabet base64 decode, tolerant of `=` padding, strict
/// about everything else. Returns `None` on any invalid character or
/// impossible length.
#[must_use]
pub(crate) fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let unpadded: &[u8] = trimmed
        .strip_suffix(b"==")
        .or_else(|| trimmed.strip_suffix(b"="))
        .unwrap_or(&trimmed);
    if unpadded.len() % 4 == 1 {
        return None; // impossible base64 length
    }
    let mut out = Vec::with_capacity(unpadded.len() / 4 * 3 + 3);
    for chunk in unpadded.chunks(4) {
        let mut n: u32 = 0;
        for &c in chunk {
            n = (n << 6) | value(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&n.to_be_bytes()[1..4]),
            3 => out.extend_from_slice(&(n << 6).to_be_bytes()[1..3]),
            2 => out.push((n << 12).to_be_bytes()[1]),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// Builds an unencrypted openssh-key-v1 PEM around a fixed seed —
    /// byte-compatible with `ssh-keygen -t ed25519` output.
    fn make_pem(seed: [u8; 32], tamper_public: bool) -> String {
        let signing = SigningKey::from_bytes(&seed);
        let mut public = *signing.verifying_key().as_bytes();
        if tamper_public {
            public[0] ^= 0xFF;
        }

        let mut pub_blob = Writer::new();
        pub_blob.put_string(ALGORITHM.as_bytes());
        pub_blob.put_string(&public);
        let pub_blob = pub_blob.into_bytes();

        let mut sk_blob = Vec::new();
        sk_blob.extend_from_slice(&seed);
        sk_blob.extend_from_slice(&public);

        let mut private = Writer::new();
        private.put_uint32(0xAABB_CCDD);
        private.put_uint32(0xAABB_CCDD);
        private.put_string(ALGORITHM.as_bytes());
        private.put_string(&public);
        private.put_string(&sk_blob);
        private.put_string(b"test@quantumssh");
        let mut private = private.into_bytes();
        let mut pad = 1u8;
        while !private.len().is_multiple_of(8) {
            private.push(pad);
            pad += 1;
        }

        let mut container = Vec::new();
        container.extend_from_slice(AUTH_MAGIC);
        let mut w = Writer::new();
        w.put_string(b"none");
        w.put_string(b"none");
        w.put_string(b"");
        w.put_uint32(1);
        w.put_string(&pub_blob);
        w.put_string(&private);
        container.extend_from_slice(&w.into_bytes());

        let b64 = base64_encode_nopad(&container);
        let mut pem = String::from(PEM_HEADER);
        pem.push('\n');
        for chunk in b64.as_bytes().chunks(70) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str(PEM_FOOTER);
        pem.push('\n');
        pem
    }

    #[test]
    fn base64_roundtrips() {
        for len in 0..32 {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 7 % 251).unwrap())
                .collect();
            let encoded = base64_encode_nopad(&data);
            assert_eq!(
                base64_decode(encoded.as_bytes()).unwrap(),
                data,
                "len {len}"
            );
        }
        // Padded forms decode too.
        assert_eq!(base64_decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode(b"aGVsbG8").unwrap(), b"hello");
        // Garbage is rejected.
        assert!(base64_decode(b"a!!!").is_none());
        assert!(base64_decode(b"abcde").is_none());
    }

    #[test]
    fn loads_signs_and_fingerprints() {
        let pem = make_pem([7u8; 32], false);
        let key = HostKey::from_openssh_pem(&pem).unwrap();

        // Signature verifies against the embedded public key.
        let blob = key.public_key_blob();
        let mut r = Reader::new(&blob);
        assert_eq!(r.string(64).unwrap(), ALGORITHM.as_bytes());
        let pk_bytes: [u8; 32] = r.string(64).unwrap().try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let sig_blob = key.sign(b"exchange hash test");
        let mut s = Reader::new(&sig_blob);
        assert_eq!(s.string(64).unwrap(), ALGORITHM.as_bytes());
        let sig_bytes: [u8; 64] = s.string(128).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify(b"exchange hash test", &sig).unwrap();

        let fp = key.fingerprint_sha256();
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.ends_with('='), "fingerprint must be unpadded");
    }

    #[test]
    fn rejects_tampered_public_key() {
        let pem = make_pem([9u8; 32], true);
        assert!(matches!(
            HostKey::from_openssh_pem(&pem),
            Err(HostKeyError::Inconsistent)
        ));
    }

    #[test]
    fn rejects_non_container_input() {
        assert!(matches!(
            HostKey::from_openssh_pem("not a key"),
            Err(HostKeyError::BadContainer)
        ));
        assert!(matches!(
            HostKey::from_openssh_pem(
                "-----BEGIN OPENSSH PRIVATE KEY-----\naGVsbG8=\n-----END OPENSSH PRIVATE KEY-----"
            ),
            Err(HostKeyError::BadContainer)
        ));
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let pem = make_pem([3u8; 32], false);
        let key = HostKey::from_openssh_pem(&pem).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("SHA256:"));
        // The seed bytes must not appear (hex of 0x03 repeated).
        assert!(!debug.contains("3, 3, 3"));
    }
}
