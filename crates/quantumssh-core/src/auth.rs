//! Public-key authentication (RFC 4252 §7): the `ssh-userauth` service
//! implemented with exactly the `publickey` method and exactly Ed25519
//! keys (ADR-0021, ADR-0024).
//!
//! The authentication loop is driven by the transport type-state machine
//! ([`crate::transport::Expect<UserAuth>`]). This module supplies the
//! parsing, verification, and `authorized_keys` loading.
//!
//! - **One method**: `publickey` (ADR-0021). Every other method is
//!   refused with `SSH_MSG_USERAUTH_FAILURE` naming only `publickey`.
//! - **One key type**: `ssh-ed25519`. A different key algorithm is
//!   refused with `SSH_MSG_USERAUTH_FAILURE`.
//! - **`authorized_keys`** is read once at startup (`std::fs`, per
//!   ADR-0022). Options are ignored (Phase 1 — ADR-0023 scope cut).

use std::fmt;
use std::path::Path;

use crate::host_key;
use crate::wire::{Reader, Writer};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 §8).
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// `SSH_MSG_USERAUTH_FAILURE` (RFC 4252 §8).
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// `SSH_MSG_USERAUTH_SUCCESS` (RFC 4252 §8).
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// `SSH_MSG_USERAUTH_PK_OK` (RFC 4252 §7, "publickey" method).
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;

/// The only auth method Phase 1 offers.
pub const AUTH_METHOD: &str = "publickey";
/// The only key algorithm accepted.
pub const KEY_ALGORITHM: &str = "ssh-ed25519";

/// Maximum authentication attempts per connection (per-source counter,
/// not per-user — ADR-0024).
pub const MAX_AUTH_ATTEMPTS: u32 = 12;

// Bounds for auth-request fields (wire::Reader requires explicit bounds).
pub(crate) const USER_NAME_BOUND: usize = 256;
pub(crate) const SERVICE_NAME_BOUND: usize = 64;
pub(crate) const METHOD_NAME_BOUND: usize = 32;
pub(crate) const KEY_ALGO_BOUND: usize = 64;
/// Ed25519 blob: 4(len) + 11(algo) + 4(len) + 32(key). Headroom.
pub(crate) const KEY_BLOB_BOUND: usize = 1024;
pub(crate) const SIGNATURE_BOUND: usize = 256;

/// Errors loading or parsing the `authorized_keys` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// File cannot be read or is completely invalid.
    Io(String),
    /// A line does not contain a parsable `ssh-ed25519` key.
    MalformedLine {
        /// 1-indexed line number.
        line: usize,
        /// What went wrong.
        reason: String,
    },
    /// The key type on the line is not `ssh-ed25519`.
    UnsupportedKeyType {
        /// 1-indexed line number.
        line: usize,
        /// The algorithm name found.
        found: String,
    },
    /// No valid key entries were found.
    Empty,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read authorized_keys: {e}"),
            Self::MalformedLine { line, reason } => {
                write!(f, "authorized_keys line {line}: {reason}")
            }
            Self::UnsupportedKeyType { line, found } => {
                write!(
                    f,
                    "authorized_keys line {line}: unsupported key type '{found}' (need ssh-ed25519)"
                )
            }
            Self::Empty => write!(f, "authorized_keys file contains no keys"),
        }
    }
}

impl std::error::Error for AuthError {}

/// A single parsed entry from an `authorized_keys` file.
#[derive(Debug)]
pub struct AuthorizedKey {
    /// Raw wire-format key blob (string algorithm + string key).
    pub blob: Vec<u8>,
    /// `SHA256:` + base64(SHA-256(blob)) — the `authenticated_identity`
    /// field in audit events (ADR-0024).
    pub fingerprint: String,
    /// The verified public key, ready to check signatures.
    pub verifying_key: VerifyingKey,
}

/// The parsed `authorized_keys` file, ready for lockup.
///
/// `Debug` never exposes key material (threat model §4.3).
pub struct AuthorizedKeys {
    keys: Vec<AuthorizedKey>,
}

impl fmt::Debug for AuthorizedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKeys")
            .field("count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl AuthorizedKeys {
    /// Loads and parses the `authorized_keys` file at `path`.
    ///
    /// Only `ssh-ed25519` keys are accepted. Lines starting with `#`
    /// and empty lines are ignored. Options preceding the key type are
    /// skipped (Phase 1 ignores options).
    ///
    /// # Errors
    ///
    /// [`AuthError::Io`] when the file cannot be read;
    /// [`AuthError::MalformedLine`] when a line's base64 blob cannot be
    /// decoded or its wire format is invalid;
    /// [`AuthError::UnsupportedKeyType`] when a non-Ed25519 key is
    /// encountered;
    /// [`AuthError::Empty`] when the file contains zero valid keys.
    #[must_use]
    #[allow(clippy::double_must_use)]
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let content = std::fs::read_to_string(path).map_err(|e| AuthError::Io(e.to_string()))?;

        let mut keys = Vec::new();
        for (line_no, raw_line) in content.lines().enumerate() {
            let line_no = line_no + 1; // 1-indexed for diagnostics
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Skip options: find the first token that looks like a key
            // type (starts with "ssh-").
            let Some(key_start) = trimmed.find("ssh-") else {
                return Err(AuthError::MalformedLine {
                    line: line_no,
                    reason: "no key type found".into(),
                });
            };
            let remainder = &trimmed[key_start..];
            let mut tokens = remainder.split_whitespace();

            let algo = tokens.next().ok_or_else(|| AuthError::MalformedLine {
                line: line_no,
                reason: "missing key type".into(),
            })?;
            if algo != KEY_ALGORITHM {
                return Err(AuthError::UnsupportedKeyType {
                    line: line_no,
                    found: algo.into(),
                });
            }

            let b64 = tokens.next().ok_or_else(|| AuthError::MalformedLine {
                line: line_no,
                reason: "missing base64 key".into(),
            })?;

            let blob = host_key::base64_decode(b64.as_bytes()).ok_or_else(|| {
                AuthError::MalformedLine {
                    line: line_no,
                    reason: "invalid base64".into(),
                }
            })?;

            // Parse the wire-format blob: string(algorithm) + string(key).
            let mut r = Reader::new(&blob);
            let parsed_algo = r
                .string(KEY_ALGO_BOUND)
                .map_err(|_| AuthError::MalformedLine {
                    line: line_no,
                    reason: "blob truncated or oversized".into(),
                })?;
            if parsed_algo != KEY_ALGORITHM.as_bytes() {
                return Err(AuthError::MalformedLine {
                    line: line_no,
                    reason: format!(
                        "blob algorithm is '{}', expected 'ssh-ed25519'",
                        String::from_utf8_lossy(parsed_algo)
                    ),
                });
            }
            let key_bytes = r.string(64).map_err(|_| AuthError::MalformedLine {
                line: line_no,
                reason: "missing key bytes in blob".into(),
            })?;
            r.finish().map_err(|e| AuthError::MalformedLine {
                line: line_no,
                reason: format!("trailing data in blob: {e}"),
            })?;

            if key_bytes.len() != 32 {
                return Err(AuthError::MalformedLine {
                    line: line_no,
                    reason: format!(
                        "expected 32-byte Ed25519 key, got {} bytes",
                        key_bytes.len()
                    ),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(key_bytes);
            let verifying_key =
                VerifyingKey::from_bytes(&arr).map_err(|_| AuthError::MalformedLine {
                    line: line_no,
                    reason: "invalid Ed25519 key bytes".into(),
                })?;

            let digest = Sha256::digest(&blob);
            let fingerprint = format!("SHA256:{}", host_key::base64_encode_nopad(&digest));

            keys.push(AuthorizedKey {
                blob,
                fingerprint,
                verifying_key,
            });
        }

        if keys.is_empty() {
            return Err(AuthError::Empty);
        }

        Ok(Self { keys })
    }

    /// Looks up a key blob (the exact wire-format blob the client sends
    /// in `SSH_MSG_USERAUTH_REQUEST`). Returns the matching key with
    /// its fingerprint and verifying key.
    #[must_use]
    pub fn lookup(&self, key_blob: &[u8]) -> Option<&AuthorizedKey> {
        self.keys.iter().find(|k| k.blob == key_blob)
    }
}

/// Builds the data over which the `publickey` signature is computed
/// (RFC 4252 §7):
///
/// ```text
///   string   session_id
///   <payload of SSH_MSG_USERAUTH_REQUEST up to, but not including, the signature field>
/// ```
///
/// `payload_without_sig` is the raw wire bytes from byte 0
/// (`SSH_MSG_USERAUTH_REQUEST`) through the end of the `key_blob`
/// field, exactly as the peer sent them. The caller obtains this by
/// parsing the request with [`Reader`] and noting the offset before
/// reading the signature string.
#[must_use]
pub fn auth_signed_data(session_id: &[u8; 32], payload_without_sig: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(session_id);
    w.put_bytes(payload_without_sig);
    w.into_bytes()
}

/// Verifies an Ed25519 signature over the `publickey` auth request.
///
/// # Errors
///
/// Returns `Err(())` when the signature is invalid (forged, tampered,
/// wrong key, or non-canonical).
#[must_use]
#[allow(clippy::double_must_use, clippy::result_unit_err)]
pub fn verify_auth_signature(
    session_id: &[u8; 32],
    payload_without_sig: &[u8],
    signature_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), ()> {
    let signed = auth_signed_data(session_id, payload_without_sig);
    let sig = Signature::from_slice(signature_bytes).map_err(|_| ())?;
    verifying_key.verify(&signed, &sig).map_err(|_| ())
}

/// Builds the `SSH_MSG_USERAUTH_FAILURE` payload naming the only
/// method we accept.
#[must_use]
pub fn build_failure_payload(partial_success: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_USERAUTH_FAILURE);
    w.put_name_list(AUTH_METHOD);
    w.put_boolean(partial_success);
    w.into_bytes()
}

/// Builds the `SSH_MSG_USERAUTH_PK_OK` payload (RFC 4252 §7).
#[must_use]
pub fn build_pk_ok(key_algorithm: &str, key_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_USERAUTH_PK_OK);
    w.put_string(key_algorithm.as_bytes());
    w.put_string(key_blob);
    w.into_bytes()
}

/// Builds the `SSH_MSG_USERAUTH_SUCCESS` payload.
#[must_use]
pub fn build_success_payload() -> Vec<u8> {
    vec![SSH_MSG_USERAUTH_SUCCESS]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Writes a temporary `authorized_keys` file with the given content.
    fn temp_authorized_keys(content: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("quantumssh-test-ak-{n}.txt"));
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(content.as_bytes()).expect("write");
        path
    }

    #[test]
    fn parse_single_valid_key() {
        let signing = SigningKey::from_bytes(&[22u8; 32]);
        let verifying = signing.verifying_key();
        let blob = build_ed25519_blob(&verifying);
        let b64 = host_key::base64_encode_nopad(&blob);
        let path = temp_authorized_keys(&format!("ssh-ed25519 {b64} test@host\n"));

        let keys = AuthorizedKeys::load(&path).expect("load");
        assert_eq!(keys.keys.len(), 1);
        assert_eq!(keys.keys[0].blob, blob);
        assert!(keys.keys[0].fingerprint.starts_with("SHA256:"));
        assert!(!keys.keys[0].fingerprint.ends_with('='));
        assert!(keys.lookup(&blob).is_some());
    }

    #[test]
    fn ignore_comments_and_empty_lines() {
        let signing = SigningKey::from_bytes(&[33u8; 32]);
        let verifying = signing.verifying_key();
        let blob = build_ed25519_blob(&verifying);
        let b64 = host_key::base64_encode_nopad(&blob);
        let content =
            format!("# This is a comment\n\nssh-ed25519 {b64} test\n\n# Another comment\n");
        let path = temp_authorized_keys(&content);
        let keys = AuthorizedKeys::load(&path).expect("load");
        assert_eq!(keys.keys.len(), 1);
    }

    #[test]
    fn ignore_options_before_key() {
        let signing = SigningKey::from_bytes(&[44u8; 32]);
        let verifying = signing.verifying_key();
        let blob = build_ed25519_blob(&verifying);
        let b64 = host_key::base64_encode_nopad(&blob);
        let content = format!("command=\"dump\",no-agent-forwarding ssh-ed25519 {b64} test\n");
        let path = temp_authorized_keys(&content);
        let keys = AuthorizedKeys::load(&path).expect("load");
        assert_eq!(keys.keys.len(), 1);
        assert_eq!(keys.keys[0].blob, blob);
    }

    #[test]
    fn multiple_keys() {
        let s1 = SigningKey::from_bytes(&[1u8; 32]);
        let s2 = SigningKey::from_bytes(&[2u8; 32]);
        let blob1 = build_ed25519_blob(&s1.verifying_key());
        let blob2 = build_ed25519_blob(&s2.verifying_key());
        let b64_1 = host_key::base64_encode_nopad(&blob1);
        let b64_2 = host_key::base64_encode_nopad(&blob2);
        let path = temp_authorized_keys(&format!(
            "ssh-ed25519 {b64_1} user1\nssh-ed25519 {b64_2} user2\n"
        ));
        let keys = AuthorizedKeys::load(&path).expect("load");
        assert_eq!(keys.keys.len(), 2);
        assert!(keys.lookup(&blob1).is_some());
        assert!(keys.lookup(&blob2).is_some());
        assert!(keys.lookup(b"nonexistent").is_none());
    }

    #[test]
    fn reject_rsa_key() {
        let path = temp_authorized_keys("ssh-rsa AAAA nonsense\n");
        let err = AuthorizedKeys::load(&path).unwrap_err();
        assert!(matches!(err, AuthError::UnsupportedKeyType { .. }));
    }

    #[test]
    fn reject_malformed_base64() {
        let path = temp_authorized_keys("ssh-ed25519 !!!invalid!!! comment\n");
        let err = AuthorizedKeys::load(&path).unwrap_err();
        assert!(matches!(err, AuthError::MalformedLine { .. }));
    }

    #[test]
    fn reject_invalid_blob_structure() {
        let path = temp_authorized_keys("ssh-ed25519 aGVsbG8= comment\n");
        let err = AuthorizedKeys::load(&path).unwrap_err();
        assert!(matches!(err, AuthError::MalformedLine { .. }));
    }

    #[test]
    fn reject_empty_file() {
        let path = temp_authorized_keys("# just a comment\n");
        let err = AuthorizedKeys::load(&path).unwrap_err();
        assert!(matches!(err, AuthError::Empty));
    }

    #[test]
    fn lookup_rejects_unknown_blob() {
        let signing = SigningKey::from_bytes(&[55u8; 32]);
        let blob = build_ed25519_blob(&signing.verifying_key());
        let b64 = host_key::base64_encode_nopad(&blob);
        let path = temp_authorized_keys(&format!("ssh-ed25519 {b64} x\n"));
        let keys = AuthorizedKeys::load(&path).expect("load");
        assert!(keys.lookup(b"not-a-real-blob").is_none());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let signing = SigningKey::from_bytes(&[66u8; 32]);
        let blob = build_ed25519_blob(&signing.verifying_key());
        let b64 = host_key::base64_encode_nopad(&blob);
        let path = temp_authorized_keys(&format!("ssh-ed25519 {b64} x\n"));
        let keys = AuthorizedKeys::load(&path).expect("load");
        let debug = format!("{keys:?}");
        assert!(debug.contains("count"));
        assert!(!debug.contains("blob"));
        assert!(!debug.contains("verifying"));
    }

    #[test]
    fn auth_signed_data_matches_known_vector() {
        let session_id = [0xabu8; 32];
        let payload: &[u8] = &[
            SSH_MSG_USERAUTH_REQUEST,
            0x00,
            0x00,
            0x00,
            0x04,
            b't',
            b'e',
            b's',
            b't',
            0x00,
            0x00,
            0x00,
            0x0e,
            b's',
            b's',
            b'h',
            b'-',
            b'c',
            b'o',
            b'n',
            b'n',
            b'e',
            b'c',
            b't',
            b'i',
            b'o',
            b'n',
            0x00,
            0x00,
            0x00,
            0x09,
            b'p',
            b'u',
            b'b',
            b'l',
            b'i',
            b'c',
            b'k',
            b'e',
            b'y',
            0x01,
            0x00,
            0x00,
            0x00,
            0x0b,
            b's',
            b's',
            b'h',
            b'-',
            b'e',
            b'd',
            b'2',
            b'5',
            b'5',
            b'1',
            b'9',
            0x00,
            0x00,
            0x00,
            0x02,
            0xaa,
            0xbb,
        ];

        let signed = auth_signed_data(&session_id, payload);
        let mut r = Reader::new(&signed);
        let parsed_sid = r.string(32).expect("session_id string");
        assert_eq!(parsed_sid, session_id.as_slice());
        assert_eq!(r.remaining(), payload.len());
        assert_eq!(&signed[signed.len() - payload.len()..], payload);
    }

    #[test]
    fn signature_roundtrip() {
        let signing = SigningKey::from_bytes(&[77u8; 32]);
        let verifying = signing.verifying_key();
        let session_id = [0x13u8; 32];

        let payload: &[u8] = &[
            SSH_MSG_USERAUTH_REQUEST,
            0x00,
            0x00,
            0x00,
            0x04,
            b'u',
            b's',
            b'e',
            b'r',
            0x00,
            0x00,
            0x00,
            0x0e,
            b's',
            b's',
            b'h',
            b'-',
            b'c',
            b'o',
            b'n',
            b'n',
            b'e',
            b'c',
            b't',
            b'i',
            b'o',
            b'n',
            0x00,
            0x00,
            0x00,
            0x09,
            b'p',
            b'u',
            b'b',
            b'l',
            b'i',
            b'c',
            b'k',
            b'e',
            b'y',
            0x01,
            0x00,
            0x00,
            0x00,
            0x0b,
            b's',
            b's',
            b'h',
            b'-',
            b'e',
            b'd',
            b'2',
            b'5',
            b'5',
            b'1',
            b'9',
            0x00,
            0x00,
            0x00,
            0x02,
            0xcc,
            0xdd,
        ];

        let signed_data = auth_signed_data(&session_id, payload);
        let sig = signing.sign(&signed_data);

        let result =
            verify_auth_signature(&session_id, payload, sig.to_bytes().as_ref(), &verifying);
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_signature_fails() {
        let signing = SigningKey::from_bytes(&[88u8; 32]);
        let other = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
        let session_id = [0x42u8; 32];

        let payload: &[u8] = &[
            SSH_MSG_USERAUTH_REQUEST,
            0x00,
            0x00,
            0x00,
            0x04,
            b'u',
            b's',
            b'e',
            b'r',
            0x00,
            0x00,
            0x00,
            0x0e,
            b's',
            b's',
            b'h',
            b'-',
            b'c',
            b'o',
            b'n',
            b'n',
            b'e',
            b'c',
            b't',
            b'i',
            b'o',
            b'n',
            0x00,
            0x00,
            0x00,
            0x09,
            b'p',
            b'u',
            b'b',
            b'l',
            b'i',
            b'c',
            b'k',
            b'e',
            b'y',
            0x01,
            0x00,
            0x00,
            0x00,
            0x0b,
            b's',
            b's',
            b'h',
            b'-',
            b'e',
            b'd',
            b'2',
            b'5',
            b'5',
            b'1',
            b'9',
            0x00,
            0x00,
            0x00,
            0x02,
            0xcc,
            0xdd,
        ];

        let signed_data = auth_signed_data(&session_id, payload);
        let sig = signing.sign(&signed_data);

        let result = verify_auth_signature(&session_id, payload, sig.to_bytes().as_ref(), &other);
        assert!(result.is_err());
    }

    #[test]
    fn build_failure_names_only_publickey() {
        let payload = build_failure_payload(false);
        let mut r = Reader::new(&payload);
        assert_eq!(r.byte().unwrap(), SSH_MSG_USERAUTH_FAILURE);
        let methods = r.name_list(64).unwrap();
        let names: Vec<&str> = methods.names().collect();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "publickey");
        assert!(!r.boolean().unwrap());
    }

    #[test]
    fn build_pk_ok_roundtrips() {
        let algo = "ssh-ed25519";
        let key_bytes = [0xffu8; 32];
        let mut kb = Writer::new();
        kb.put_string(&key_bytes);
        let key_blob = kb.into_bytes();
        let payload = build_pk_ok(algo, &key_blob);
        let mut r = Reader::new(&payload);
        assert_eq!(r.byte().unwrap(), SSH_MSG_USERAUTH_PK_OK);
        assert_eq!(r.string(64).unwrap(), algo.as_bytes());
        assert_eq!(r.string(64).unwrap(), key_blob.as_slice());
    }

    // ---- helpers ----

    fn build_ed25519_blob(vk: &VerifyingKey) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(b"ssh-ed25519");
        w.put_string(vk.as_bytes());
        w.into_bytes()
    }
}
