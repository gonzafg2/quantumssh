//! OpenSSH user certificates (ADR-0050): the `trusted_user_ca_keys`
//! file and the checks a `publickey` request naming [`CERT_ALGORITHM`]
//! passes in the userauth stage.
//!
//! The format is `draft-ietf-sshm-cert` §2.1, under OpenSSH's name
//! `ssh-ed25519-cert-v01@openssh.com` for the draft's `ssh-ed25519-cert`.
//! The blob is attacker-supplied and parsed before authentication
//! (threat model §4.1): every length is bounded, nothing is allocated
//! for it beyond the principal list (at most 256 entries), and [`verify`]
//! is a pure function of its inputs, so it can be fuzzed.

use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::auth::{self, AuthError, AuthorizedKey};
use crate::host_key;
use crate::wire::{Reader, Writer};

/// The certificate key algorithm a `publickey` request may name
/// (ADR-0050 §2).
pub const CERT_ALGORITHM: &str = "ssh-ed25519-cert-v01@openssh.com";

/// Bound on the certificate blob (ADR-0050 §5). A composite CA brings a
/// certificate to about 4 KB.
pub(crate) const CERT_BLOB_BOUND: usize = 16 * 1024;

/// OpenSSH's `SSHKEY_CERT_MAX_PRINCIPALS`.
const MAX_PRINCIPALS: usize = 256;

/// `draft-ietf-sshm-cert` §2.1.1: the nonce is at least 16 bytes.
const MIN_NONCE_LEN: usize = 16;

/// `SSH2_CERT_TYPE_USER` (`draft-ietf-sshm-cert` §4.1).
const ROLE_USER: u32 = 1;

/// The extension that permits a PTY (ADR-0050 §6, ADR-0038 §3).
const PERMIT_PTY: &[u8] = b"permit-pty";

/// The CAs `[auth] trusted_user_ca_keys` lists (ADR-0050 §3).
///
/// `Debug` never exposes key material (threat model §4.3).
pub struct TrustedUserCaKeys {
    keys: Vec<AuthorizedKey>,
}

impl fmt::Debug for TrustedUserCaKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedUserCaKeys")
            .field("count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl TrustedUserCaKeys {
    /// Loads the file at `path` under the `authorized_keys` rules
    /// (ADR-0050 §3): one `ssh-ed25519` CA key per line, an options
    /// field refused (ADR-0040), and at least one key.
    ///
    /// # Errors
    ///
    /// The [`AuthError`]s of [`auth::AuthorizedKeys::load`].
    #[must_use]
    #[allow(clippy::double_must_use)]
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        auth::load_key_file(path).map(|keys| Self { keys })
    }
}

/// The ADR-0051 audit fields of a certificate authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertIdentity {
    /// `cert_key_id`: the certificate's identifier field.
    pub(crate) key_id: String,
    /// `cert_serial`: the serial number, in decimal.
    pub(crate) serial: String,
    /// `cert_ca_fingerprint`: the CA key's `SHA256:` fingerprint.
    pub(crate) ca_fingerprint: String,
    /// `cert_principal`: the principal that matched, which is the
    /// requested user name.
    pub(crate) principal: String,
}

/// A certificate that passed every ADR-0050 §5 check.
///
/// `Debug` shows the fingerprint, never the key (threat model §4.3).
pub(crate) struct Certificate {
    /// The certified key, which signs the userauth request.
    pub(crate) key: VerifyingKey,
    /// The certified key's fingerprint, over its plain `ssh-ed25519`
    /// blob as OpenSSH computes it: `authenticated_identity` (RFC-0014
    /// §6).
    pub(crate) fingerprint: String,
    pub(crate) identity: CertIdentity,
    /// The certificate carries `permit-pty`.
    pub(crate) permit_pty: bool,
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("fingerprint", &self.fingerprint)
            .field("identity", &self.identity)
            .field("permit_pty", &self.permit_pty)
            .finish_non_exhaustive()
    }
}

/// Why a certificate was refused: the fixed reason of ADR-0050 §5's
/// diagnostic record. The client learns none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Check 1: the blob does not parse within its bounds.
    Malformed,
    /// Check 2: the signature key is not a trusted CA.
    UntrustedCa,
    /// Check 3: the CA signature does not verify.
    BadCaSignature,
    /// Check 4: a host certificate, or an unknown role.
    NotUserCertificate,
    /// Check 5: before `valid after`.
    NotYetValid,
    /// Check 5: at or after `valid before`.
    Expired,
    /// Check 6: the requested user name is not a listed principal.
    PrincipalMismatch,
    /// Check 7: the certificate carries a critical option.
    CriticalOption,
}

impl Refusal {
    /// The diagnostic record's `reason` value.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UntrustedCa => "untrusted_ca",
            Self::BadCaSignature => "bad_ca_signature",
            Self::NotUserCertificate => "not_user_certificate",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::PrincipalMismatch => "principal_mismatch",
            Self::CriticalOption => "critical_option",
        }
    }
}

/// Runs ADR-0050 §5's checks, in its order, on the certificate `blob` a
/// `publickey` request carries for `user`, at `now` (seconds since the
/// Unix epoch).
pub(crate) fn verify(
    blob: &[u8],
    cas: &TrustedUserCaKeys,
    user: &str,
    now: u64,
) -> Result<Certificate, Refusal> {
    let cert = Parsed::parse(blob).ok_or(Refusal::Malformed)?;
    let ca = auth::lookup(&cas.keys, cert.ca_key).ok_or(Refusal::UntrustedCa)?;
    if cert.ca_signature_algorithm != auth::KEY_ALGORITHM.as_bytes() {
        return Err(Refusal::BadCaSignature);
    }
    let signature =
        Signature::from_slice(cert.ca_signature).map_err(|_| Refusal::BadCaSignature)?;
    ca.verifying_key
        .verify_strict(cert.signed, &signature)
        .map_err(|_| Refusal::BadCaSignature)?;
    if cert.role != ROLE_USER {
        return Err(Refusal::NotUserCertificate);
    }
    if now < cert.valid_after {
        return Err(Refusal::NotYetValid);
    }
    if now >= cert.valid_before {
        return Err(Refusal::Expired);
    }
    if !cert.principals.contains(&user.as_bytes()) {
        return Err(Refusal::PrincipalMismatch);
    }
    if cert.has_critical_options {
        return Err(Refusal::CriticalOption);
    }
    let mut plain = Writer::new();
    plain.put_string(auth::KEY_ALGORITHM.as_bytes());
    plain.put_string(cert.key.as_bytes());
    Ok(Certificate {
        key: cert.key,
        fingerprint: host_key::fingerprint_sha256(&plain.into_bytes()),
        identity: CertIdentity {
            key_id: cert.key_id.to_string(),
            serial: cert.serial.to_string(),
            ca_fingerprint: ca.fingerprint.clone(),
            principal: user.to_string(),
        },
        permit_pty: cert.permit_pty,
    })
}

/// A certificate blob split into its fields (`draft-ietf-sshm-cert`
/// §2.1.1, §2.1.4), with every structural rule of check 1 applied.
struct Parsed<'a> {
    key: VerifyingKey,
    serial: u64,
    role: u32,
    key_id: &'a str,
    principals: Vec<&'a [u8]>,
    valid_after: u64,
    valid_before: u64,
    has_critical_options: bool,
    permit_pty: bool,
    ca_key: &'a [u8],
    /// Every field up to and including the signature key: what the CA
    /// signed.
    signed: &'a [u8],
    ca_signature_algorithm: &'a [u8],
    ca_signature: &'a [u8],
}

impl<'a> Parsed<'a> {
    fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() > CERT_BLOB_BOUND {
            return None;
        }
        let mut r = Reader::new(blob);
        if r.string(auth::KEY_ALGO_BOUND).ok()? != CERT_ALGORITHM.as_bytes() {
            return None;
        }
        if r.string(CERT_BLOB_BOUND).ok()?.len() < MIN_NONCE_LEN {
            return None;
        }
        let key = VerifyingKey::from_bytes(r.string(32).ok()?.try_into().ok()?).ok()?;
        // A small-order key accepts forged signatures under the
        // non-strict check; refused like one in `authorized_keys`.
        if key.is_weak() {
            return None;
        }
        let serial = r.uint64().ok()?;
        let role = r.uint32().ok()?;
        let key_id = std::str::from_utf8(r.string(CERT_BLOB_BOUND).ok()?).ok()?;
        let principals = parse_principals(r.string(CERT_BLOB_BOUND).ok()?)?;
        let valid_after = r.uint64().ok()?;
        let valid_before = r.uint64().ok()?;
        let critical_options = r.string(CERT_BLOB_BOUND).ok()?;
        let extensions = r.string(CERT_BLOB_BOUND).ok()?;
        // Reserved: ignored even when not empty (draft §2.1.1).
        r.string(CERT_BLOB_BOUND).ok()?;
        let ca_key = r.string(CERT_BLOB_BOUND).ok()?;
        let signed = &blob[..blob.len() - r.remaining()];
        let mut sig = Reader::new(r.string(CERT_BLOB_BOUND).ok()?);
        r.finish().ok()?;
        let ca_signature_algorithm = sig.string(auth::KEY_ALGO_BOUND).ok()?;
        let ca_signature = sig.string(auth::SIGNATURE_BOUND).ok()?;
        sig.finish().ok()?;

        let mut has_critical_options = false;
        for_each_option(critical_options, |_, _| has_critical_options = true)?;
        let mut permit_pty = false;
        let mut corrupt_flag = false;
        // Every other extension is ignored (draft §2.1.1, ADR-0050 §6).
        for_each_option(extensions, |name, data| {
            if name == PERMIT_PTY {
                permit_pty = true;
                // A flag extension's data is empty (draft §2.2).
                corrupt_flag |= !data.is_empty();
            }
        })?;
        if corrupt_flag {
            return None;
        }

        Some(Self {
            key,
            serial,
            role,
            key_id,
            principals,
            valid_after,
            valid_before,
            has_critical_options,
            permit_pty,
            ca_key,
            signed,
            ca_signature_algorithm,
            ca_signature,
        })
    }
}

/// The principals field: a sequence of strings, at most
/// [`MAX_PRINCIPALS`] of them.
fn parse_principals(field: &[u8]) -> Option<Vec<&[u8]>> {
    let mut r = Reader::new(field);
    let mut principals = Vec::new();
    while r.remaining() > 0 {
        if principals.len() == MAX_PRINCIPALS {
            return None;
        }
        principals.push(r.string(field.len()).ok()?);
    }
    Some(principals)
}

/// Calls `f` with each name and data string of an options or extensions
/// field (draft §2.2). `None` when the field is not a sequence of such
/// pairs.
fn for_each_option(field: &[u8], mut f: impl FnMut(&[u8], &[u8])) -> Option<()> {
    let mut r = Reader::new(field);
    while r.remaining() > 0 {
        let name = r.string(field.len()).ok()?;
        let data = r.string(field.len()).ok()?;
        f(name, data);
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NOW: u64 = 1_800_000_000;
    const USER: &str = "alice";

    fn ca() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn user_key() -> SigningKey {
        SigningKey::from_bytes(&[8u8; 32])
    }

    fn plain_blob(key: &VerifyingKey) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(b"ssh-ed25519");
        w.put_string(key.as_bytes());
        w.into_bytes()
    }

    fn options(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut w = Writer::new();
        for (name, data) in pairs {
            w.put_string(name);
            w.put_string(data);
        }
        w.into_bytes()
    }

    /// The fields of a test certificate, defaulting to one `verify`
    /// accepts.
    struct Spec {
        key_type: &'static [u8],
        nonce: Vec<u8>,
        role: u32,
        key_id: Vec<u8>,
        principals: Vec<Vec<u8>>,
        valid_after: u64,
        valid_before: u64,
        critical: Vec<u8>,
        extensions: Vec<u8>,
        reserved: Vec<u8>,
        ca: SigningKey,
        sig_algorithm: &'static [u8],
        trailing: Vec<u8>,
    }

    impl Default for Spec {
        fn default() -> Self {
            Self {
                key_type: CERT_ALGORITHM.as_bytes(),
                nonce: vec![0x5a; 32],
                role: ROLE_USER,
                key_id: b"alice@example".to_vec(),
                principals: vec![b"alice".to_vec()],
                valid_after: NOW - 60,
                valid_before: NOW + 60,
                critical: Vec::new(),
                extensions: options(&[(b"permit-pty", b"")]),
                reserved: Vec::new(),
                ca: ca(),
                sig_algorithm: b"ssh-ed25519",
                trailing: Vec::new(),
            }
        }
    }

    impl Spec {
        fn blob(&self) -> Vec<u8> {
            let mut principals = Writer::new();
            for p in &self.principals {
                principals.put_string(p);
            }
            let mut w = Writer::new();
            w.put_string(self.key_type);
            w.put_string(&self.nonce);
            w.put_string(user_key().verifying_key().as_bytes());
            w.put_uint64(0xfedc_ba98_7654_3210);
            w.put_uint32(self.role);
            w.put_string(&self.key_id);
            w.put_string(&principals.into_bytes());
            w.put_uint64(self.valid_after);
            w.put_uint64(self.valid_before);
            w.put_string(&self.critical);
            w.put_string(&self.extensions);
            w.put_string(&self.reserved);
            w.put_string(&plain_blob(&self.ca.verifying_key()));
            let signed = w.into_bytes();
            let mut sig = Writer::new();
            sig.put_string(self.sig_algorithm);
            sig.put_string(&self.ca.sign(&signed).to_bytes());
            let mut w = Writer::new();
            w.put_bytes(&signed);
            w.put_string(&sig.into_bytes());
            w.put_bytes(&self.trailing);
            w.into_bytes()
        }
    }

    fn trusted(keys: &[&SigningKey]) -> TrustedUserCaKeys {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("quantumssh-test-ca-{}-{n}.txt", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create temp file");
        for key in keys {
            let b64 = host_key::base64_encode_nopad(&plain_blob(&key.verifying_key()));
            writeln!(f, "ssh-ed25519 {b64} ca").expect("write");
        }
        TrustedUserCaKeys::load(&path).expect("load")
    }

    fn check(spec: &Spec) -> Result<Certificate, Refusal> {
        verify(&spec.blob(), &trusted(&[&ca()]), USER, NOW)
    }

    #[test]
    fn accepts_a_valid_certificate_and_reports_its_identity() {
        let cert = check(&Spec::default()).expect("accepted");
        assert_eq!(cert.key, user_key().verifying_key());
        let plain_fingerprint =
            host_key::fingerprint_sha256(&plain_blob(&user_key().verifying_key()));
        assert_eq!(cert.fingerprint, plain_fingerprint);
        assert_eq!(
            cert.identity,
            CertIdentity {
                key_id: "alice@example".into(),
                serial: "18364758544493064720".into(),
                ca_fingerprint: host_key::fingerprint_sha256(&plain_blob(&ca().verifying_key())),
                principal: USER.into(),
            }
        );
        assert!(cert.permit_pty);
    }

    #[test]
    fn principal_is_one_of_several() {
        let spec = Spec {
            principals: vec![b"bob".to_vec(), b"alice".to_vec()],
            ..Spec::default()
        };
        assert!(check(&spec).is_ok());
    }

    #[test]
    fn untrusted_ca_is_refused() {
        let spec = Spec {
            ca: SigningKey::from_bytes(&[9u8; 32]),
            ..Spec::default()
        };
        assert_eq!(check(&spec).unwrap_err(), Refusal::UntrustedCa);
    }

    #[test]
    fn a_second_trusted_ca_is_accepted() {
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let spec = Spec {
            ca: other.clone(),
            ..Spec::default()
        };
        assert!(verify(&spec.blob(), &trusted(&[&ca(), &other]), USER, NOW).is_ok());
    }

    #[test]
    fn tampered_certificate_fails_the_ca_signature() {
        let mut blob = Spec::default().blob();
        // The last byte of the key id: still well-formed, no longer signed.
        let at = blob
            .windows(b"alice@example".len())
            .position(|w| w == b"alice@example")
            .expect("key id present")
            + b"alice@example".len()
            - 1;
        blob[at] ^= 1;
        assert_eq!(
            verify(&blob, &trusted(&[&ca()]), USER, NOW).unwrap_err(),
            Refusal::BadCaSignature
        );
    }

    #[test]
    fn wrong_ca_signature_algorithm_is_refused() {
        let spec = Spec {
            sig_algorithm: b"ssh-mldsa44-ed25519",
            ..Spec::default()
        };
        assert_eq!(check(&spec).unwrap_err(), Refusal::BadCaSignature);
    }

    #[test]
    fn host_certificate_is_refused() {
        let spec = Spec {
            role: 2,
            ..Spec::default()
        };
        assert_eq!(check(&spec).unwrap_err(), Refusal::NotUserCertificate);
    }

    #[test]
    fn validity_window_includes_valid_after_and_excludes_valid_before() {
        let at_start = Spec {
            valid_after: NOW,
            ..Spec::default()
        };
        assert!(check(&at_start).is_ok());
        let early = Spec {
            valid_after: NOW + 1,
            ..Spec::default()
        };
        assert_eq!(check(&early).unwrap_err(), Refusal::NotYetValid);
        let at_end = Spec {
            valid_before: NOW,
            ..Spec::default()
        };
        assert_eq!(check(&at_end).unwrap_err(), Refusal::Expired);
    }

    #[test]
    fn certificate_without_expiry_is_accepted() {
        // `ssh-keygen -s` without `-V` (ADR-0050 Consequences).
        let spec = Spec {
            valid_after: 0,
            valid_before: u64::MAX,
            ..Spec::default()
        };
        assert!(check(&spec).is_ok());
    }

    #[test]
    fn principal_must_match_exactly() {
        for principals in [
            vec![b"bob".to_vec()],
            vec![b"alic*".to_vec()],
            vec![b"Alice".to_vec()],
            Vec::new(),
        ] {
            let spec = Spec {
                principals,
                ..Spec::default()
            };
            assert_eq!(check(&spec).unwrap_err(), Refusal::PrincipalMismatch);
        }
    }

    #[test]
    fn every_critical_option_is_refused() {
        for name in [
            &b"force-command"[..],
            b"source-address",
            b"verify-required",
            b"x",
        ] {
            let spec = Spec {
                critical: options(&[(name, b"")]),
                ..Spec::default()
            };
            assert_eq!(check(&spec).unwrap_err(), Refusal::CriticalOption);
        }
    }

    #[test]
    fn unknown_extensions_are_ignored_and_permit_pty_is_optional() {
        let spec = Spec {
            extensions: options(&[(b"permit-X11-forwarding", b""), (b"x@example.com", b"data")]),
            ..Spec::default()
        };
        assert!(!check(&spec).expect("accepted").permit_pty);
    }

    #[test]
    fn reserved_field_is_ignored() {
        let spec = Spec {
            reserved: b"future".to_vec(),
            ..Spec::default()
        };
        assert!(check(&spec).is_ok());
    }

    #[test]
    fn malformed_certificates_are_refused() {
        let refused = [
            Spec {
                key_type: b"ssh-ed25519",
                ..Spec::default()
            },
            Spec {
                nonce: vec![0; MIN_NONCE_LEN - 1],
                ..Spec::default()
            },
            Spec {
                key_id: vec![0xff, 0xfe],
                ..Spec::default()
            },
            Spec {
                principals: vec![b"p".to_vec(); MAX_PRINCIPALS + 1],
                ..Spec::default()
            },
            Spec {
                critical: b"\x00\x00\x00\x05short".to_vec(),
                ..Spec::default()
            },
            Spec {
                extensions: options(&[(b"permit-pty", b"x")]),
                ..Spec::default()
            },
            Spec {
                trailing: vec![0],
                ..Spec::default()
            },
        ];
        for spec in &refused {
            assert_eq!(check(spec).unwrap_err(), Refusal::Malformed);
        }
    }

    #[test]
    fn bounds_hold_at_their_edges() {
        let at_limit = Spec {
            nonce: vec![0; MIN_NONCE_LEN],
            principals: vec![b"alice".to_vec(); MAX_PRINCIPALS],
            ..Spec::default()
        };
        assert!(check(&at_limit).is_ok());
        let oversized = Spec {
            reserved: vec![0; CERT_BLOB_BOUND],
            ..Spec::default()
        };
        assert_eq!(check(&oversized).unwrap_err(), Refusal::Malformed);
    }

    #[test]
    fn every_truncation_is_refused() {
        let blob = Spec::default().blob();
        let cas = trusted(&[&ca()]);
        for len in 0..blob.len() {
            assert_eq!(
                verify(&blob[..len], &cas, USER, NOW).unwrap_err(),
                Refusal::Malformed,
                "length {len}"
            );
        }
    }

    #[test]
    fn ca_file_refuses_cert_authority_lines() {
        // ADR-0040 stays in force for the CA file (ADR-0050 §3).
        let path = std::env::temp_dir().join(format!(
            "quantumssh-test-ca-options-{}.txt",
            std::process::id()
        ));
        let b64 = host_key::base64_encode_nopad(&plain_blob(&ca().verifying_key()));
        std::fs::write(&path, format!("cert-authority ssh-ed25519 {b64}\n")).expect("write");
        assert!(matches!(
            TrustedUserCaKeys::load(&path).unwrap_err(),
            AuthError::KeyOptions { line: 1 }
        ));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let debug = format!("{:?}", trusted(&[&ca()]));
        assert!(debug.contains("count"));
        assert!(!debug.contains("blob"));
        let cert = check(&Spec::default()).expect("accepted");
        let debug = format!("{cert:?}");
        assert!(debug.contains(&cert.fingerprint));
        assert!(!debug.contains("VerifyingKey"));
    }
}
