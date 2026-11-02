//! The composite `ssh-mldsa44-ed25519` host key (ADR-0047): loading
//! (`openssh-key-v1`, unencrypted), public-blob encoding, signing, and
//! the `SHA256:` fingerprint (ADR-0024 log format).
//!
//! It is the only host key type (RFC-0012); only the unencrypted
//! `openssh-key-v1` container is accepted — host keys are generated with
//! `ssh-keygen -t mldsa44-ed25519` (OpenSSH 10.6 or later) and protected
//! by file permissions, not passphrases (a server cannot type one at
//! boot).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::composite::{self, SEEDS_LEN, SigningKey};
use crate::wire::{Reader, Writer};

/// Algorithm name (`draft-ietf-sshm-composite-sigs-00` §4.1.1).
pub const ALGORITHM: &str = composite::ALGORITHM;

/// Bounds for the container's fields. The public blob is
/// 4 + 19 + 4 + 1344 bytes; the private section adds the 64-byte seeds,
/// the comment and padding.
const PUBLIC_BLOB_BOUND: usize = 2048;
const PRIVATE_SECTION_BOUND: usize = 4096;

const PEM_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Errors loading or using a host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyError {
    /// Not a PEM-armored `openssh-key-v1` file.
    BadContainer,
    /// The container is valid but the key is not an unencrypted
    /// single `ssh-mldsa44-ed25519` key.
    Unsupported,
    /// The embedded public key does not match the private seeds, or
    /// the check bytes disagree (corrupted or tampered file).
    Inconsistent,
    /// Signing failed: the OS RNG did not deliver the per-signature
    /// randomness (ADR-0035 §3).
    Sign,
}

impl std::fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadContainer => write!(f, "not an openssh-key-v1 container"),
            Self::Unsupported => write!(
                f,
                "unsupported host key (need an unencrypted ssh-mldsa44-ed25519 key)"
            ),
            Self::Inconsistent => write!(f, "host key file is internally inconsistent"),
            Self::Sign => write!(f, "host key signing failed"),
        }
    }
}

impl std::error::Error for HostKeyError {}

/// A loaded composite host key. Both signing halves zeroize on drop
/// (RFC-0012 §Key material).
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
    /// (`ssh-keygen -t mldsa44-ed25519`).
    ///
    /// # Errors
    ///
    /// [`HostKeyError::BadContainer`] when the armor or magic is
    /// wrong; [`HostKeyError::Unsupported`] for encrypted containers,
    /// multiple keys, or keys of any other type, `ssh-ed25519` included;
    /// [`HostKeyError::Inconsistent`] when check bytes or the embedded
    /// public key disagree with the seeds.
    pub fn from_openssh_pem(pem: &str) -> Result<Self, HostKeyError> {
        // Zeroizing: the base64 body encodes the private-seed container;
        // erase it on drop like the decoded `raw` below (threat model §4.3).
        let body = Zeroizing::new(
            pem.lines()
                .map(str::trim)
                .skip_while(|l| *l != PEM_HEADER)
                .skip(1)
                .take_while(|l| *l != PEM_FOOTER)
                .collect::<String>(),
        );
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
        let _public_blob = r
            .string(PUBLIC_BLOB_BOUND)
            .map_err(|_| HostKeyError::BadContainer)?;
        let private_section = r
            .string(PRIVATE_SECTION_BOUND)
            .map_err(|_| HostKeyError::BadContainer)?;
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
        // OpenSSH's `ssh-mldsa-eddsa.c`: string public key
        // (mldsa_pk ‖ ed25519_pk), string seeds (mldsa_seed ‖ ed25519_seed).
        let public = p
            .string(PUBLIC_BLOB_BOUND)
            .map_err(|_| HostKeyError::BadContainer)?;
        let seeds = p.string(128).map_err(|_| HostKeyError::BadContainer)?;
        let seeds = Zeroizing::new(
            <[u8; SEEDS_LEN]>::try_from(seeds).map_err(|_| HostKeyError::Unsupported)?,
        );
        let signing = SigningKey::from_seeds(&seeds);
        // Cross-check: the file's public key must match the seeds.
        if signing.public_key().as_slice() != public {
            return Err(HostKeyError::Inconsistent);
        }
        // Comment + deterministic padding (1, 2, 3, …) follow; their
        // integrity is covered by the checks above. We do not parse
        // them — trailing bytes here are not attacker-controlled
        // (this is the operator's key file, not network input).
        Ok(Self { signing })
    }

    /// Builds a host key directly from its seeds, `mldsa_seed ‖
    /// ed25519_seed` as OpenSSH stores them.
    ///
    /// For tests and fixed-RNG golden-vector fixtures (RFC-0003's KAT
    /// plan); production keys load from `openssh-key-v1` files via
    /// [`HostKey::from_openssh_pem`].
    #[must_use]
    pub fn from_seeds(seeds: &[u8; 64]) -> Self {
        Self {
            signing: SigningKey::from_seeds(seeds),
        }
    }

    /// The public-key blob (`draft-ietf-sshm-composite-sigs-00` §4.1.1):
    /// `string "ssh-mldsa44-ed25519" ‖ string (mldsa_pk ‖ ed25519_pk)`.
    #[must_use]
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(ALGORITHM.as_bytes());
        w.put_string(self.signing.public_key());
        w.into_bytes()
    }

    /// Signs `data`, returning the signature blob
    /// (`draft-ietf-sshm-composite-sigs-00` §4.2.2.1):
    /// `string "ssh-mldsa44-ed25519" ‖ string (mldsa_sig ‖ ed25519_sig)`.
    ///
    /// # Errors
    ///
    /// [`HostKeyError::Sign`] when the OS RNG fails; the caller fails
    /// the key exchange closed (ADR-0035 §3).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostKeyError> {
        let signature = self.signing.sign(data).map_err(|_| HostKeyError::Sign)?;
        let mut w = Writer::new();
        w.put_string(ALGORITHM.as_bytes());
        w.put_string(&signature);
        Ok(w.into_bytes())
    }

    /// OpenSSH-format fingerprint: `SHA256:` + unpadded base64 of the
    /// SHA-256 of the public-key blob (ADR-0024's
    /// `host_key_fingerprint` / `authenticated_identity` format).
    #[must_use]
    pub fn fingerprint_sha256(&self) -> String {
        fingerprint_sha256(&self.public_key_blob())
    }
}

/// OpenSSH-format fingerprint of a public-key blob: `SHA256:` + unpadded
/// base64 of its SHA-256 (RFC-0014 §4).
pub(crate) fn fingerprint_sha256(blob: &[u8]) -> String {
    let digest = Sha256::digest(blob);
    format!("SHA256:{}", base64_encode_nopad(&digest))
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet base64 encode without padding (the fingerprint
/// format, also used by the `authorized_keys` test helpers).
///
/// Not part of the library's stable public API — exposed for integration
/// tests. Prefer the `SHA256:` fingerprint through [`HostKey`].
#[doc(hidden)]
#[must_use]
pub fn base64_encode_nopad(input: &[u8]) -> String {
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
    use crate::composite::VerifyingKey;

    /// Builds an unencrypted openssh-key-v1 PEM of `key_type` around a
    /// public key and a private blob, in `ssh-keygen`'s layout.
    fn pem(key_type: &[u8], public: &[u8], private_blob: &[u8]) -> String {
        let mut pub_blob = Writer::new();
        pub_blob.put_string(key_type);
        pub_blob.put_string(public);
        let pub_blob = pub_blob.into_bytes();

        let mut private = Writer::new();
        private.put_uint32(0xAABB_CCDD);
        private.put_uint32(0xAABB_CCDD);
        private.put_string(key_type);
        private.put_string(public);
        private.put_string(private_blob);
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

    /// A composite key file around fixed seeds — byte-compatible with
    /// `ssh-keygen -t mldsa44-ed25519` output.
    fn make_pem(seeds: [u8; 64], tamper_public: bool) -> String {
        let mut public = *SigningKey::from_seeds(&seeds).public_key();
        if tamper_public {
            public[0] ^= 0xFF;
        }
        pem(ALGORITHM.as_bytes(), &public, &seeds)
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
        let pem = make_pem([7u8; 64], false);
        let key = HostKey::from_openssh_pem(&pem).unwrap();

        // The signature verifies against the blob's public key.
        let blob = key.public_key_blob();
        let mut r = Reader::new(&blob);
        assert_eq!(r.string(64).unwrap(), ALGORITHM.as_bytes());
        let vk = VerifyingKey::from_bytes(r.string(2048).unwrap()).unwrap();

        let sig_blob = key.sign(b"exchange hash test").unwrap();
        let mut s = Reader::new(&sig_blob);
        assert_eq!(s.string(64).unwrap(), ALGORITHM.as_bytes());
        assert!(vk.verify(b"exchange hash test", s.string(4096).unwrap()));
        s.finish().unwrap();

        let fp = key.fingerprint_sha256();
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.ends_with('='), "fingerprint must be unpadded");
        assert_eq!(fp, HostKey::from_seeds(&[7u8; 64]).fingerprint_sha256());
    }

    #[test]
    fn rejects_tampered_public_key() {
        let pem = make_pem([9u8; 64], true);
        assert!(matches!(
            HostKey::from_openssh_pem(&pem),
            Err(HostKeyError::Inconsistent)
        ));
    }

    /// ADR-0047: an `ssh-ed25519` host key no longer starts the server.
    #[test]
    fn rejects_an_ed25519_host_key() {
        let seed = [4u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let mut private_blob = seed.to_vec();
        private_blob.extend_from_slice(&public);
        let pem = pem(b"ssh-ed25519", &public, &private_blob);
        let err = HostKey::from_openssh_pem(&pem).unwrap_err();
        assert_eq!(err, HostKeyError::Unsupported);
        assert!(err.to_string().contains("ssh-mldsa44-ed25519"), "{err}");
    }

    #[test]
    fn rejects_seeds_of_the_wrong_length() {
        let public = *SigningKey::from_seeds(&[2u8; 64]).public_key();
        let pem = pem(ALGORITHM.as_bytes(), &public, &[2u8; 63]);
        assert_eq!(
            HostKey::from_openssh_pem(&pem).unwrap_err(),
            HostKeyError::Unsupported
        );
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
        let pem = make_pem([3u8; 64], false);
        let key = HostKey::from_openssh_pem(&pem).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("SHA256:"));
        // The seed bytes must not appear (hex of 0x03 repeated).
        assert!(!debug.contains("3, 3, 3"));
    }
}
