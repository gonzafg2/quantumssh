//! Entry points for the fuzz targets in `fuzz/` (ADR-0060 §3).
//!
//! The module is compiled only under `--cfg fuzzing`, which cargo-fuzz
//! sets and no other build does. Each function is a thin call into the
//! crate's own parsers, for those the public API does not reach. None
//! holds parsing logic of its own, and none touches the filesystem or the
//! network.

use crate::auth::{self, AuthorizedKeys, UserauthRequest};
use crate::cert::{self, TrustedUserCaKeys};
use crate::wire::Reader;
use crate::{pty, sftp, transport};

/// Parses an `SSH_MSG_SERVICE_REQUEST` payload.
pub fn service_request(payload: &[u8]) {
    let _ = transport::parse_service_request(payload);
}

/// A fixed `authorized_keys` set and session id for
/// `SSH_MSG_USERAUTH_REQUEST` payloads.
pub struct Userauth {
    keys: AuthorizedKeys,
    session_id: [u8; 32],
}

impl Userauth {
    /// Builds the fixture from `authorized_keys` content.
    ///
    /// # Panics
    ///
    /// When `authorized_keys` does not parse: the fixture is a constant
    /// of the fuzz target.
    #[must_use]
    pub fn new(authorized_keys: &str, session_id: [u8; 32]) -> Self {
        Self {
            keys: AuthorizedKeys::parse(authorized_keys).expect("fixture authorized_keys"),
            session_id,
        }
    }

    /// Parses `payload` as the `authenticate` stage does. A request that
    /// names a key of the set is resolved, and a signed one goes on to
    /// signature verification. Certificates are left to
    /// [`UserCertificate`], whose clock is fixed.
    pub fn check(&self, payload: &[u8]) {
        let Ok(UserauthRequest::PublicKey {
            user,
            key_algorithm,
            key_blob,
            signature,
        }) = auth::parse_userauth_request(payload)
        else {
            return;
        };
        let Some(candidate) = auth::resolve(key_algorithm, key_blob, user, &self.keys, None) else {
            return;
        };
        if let Some(signed) = signature {
            let _ = auth::verify_auth_signature(
                &self.session_id,
                signed.data,
                signed.signature,
                &candidate.verifying_key,
            );
        }
    }
}

/// A fixed `trusted_user_ca_keys` set, user and clock for certificate
/// blobs.
pub struct UserCertificate {
    cas: TrustedUserCaKeys,
}

impl UserCertificate {
    /// The user a certificate is checked for.
    pub const USER: &'static str = "fuzz";
    /// The clock a certificate is checked at, in seconds since the Unix
    /// epoch.
    pub const NOW: u64 = 1_800_000_000;

    /// Builds the fixture from `trusted_user_ca_keys` content.
    ///
    /// # Panics
    ///
    /// When `trusted_user_ca_keys` does not parse: the fixture is a
    /// constant of the fuzz target.
    #[must_use]
    pub fn new(trusted_user_ca_keys: &str) -> Self {
        Self {
            cas: TrustedUserCaKeys::parse(trusted_user_ca_keys)
                .expect("fixture trusted_user_ca_keys"),
        }
    }

    /// Runs ADR-0050 §5's checks on a certificate blob.
    pub fn check(&self, blob: &[u8]) {
        let _ = cert::verify(blob, &self.cas, Self::USER, Some(Self::NOW));
    }
}

/// Reads SFTP packets from `input` with the helper's framing, and runs
/// the field parsers over the fields after each packet's type byte and
/// request id, in the two layouts that carry them: OPEN's path, flags and
/// attributes, and SETSTAT's and MKDIR's path and attributes. No request
/// handler runs (ADR-0060 §4).
pub fn sftp(mut input: &[u8]) {
    let mut packet = Vec::new();
    while let Ok(true) = sftp::read_packet(&mut input, &mut packet) {
        let Some(fields) = packet.get(5..) else {
            continue;
        };
        let mut open = Reader::new(fields);
        if sftp::path_arg(&mut open).is_ok()
            && let Ok(pflags) = open.uint32()
        {
            let _ = sftp::open_flags(pflags);
            let _ = sftp::read_attrs(&mut open);
        }
        let mut setstat = Reader::new(fields);
        if sftp::path_arg(&mut setstat).is_ok() {
            let _ = sftp::read_attrs(&mut setstat);
        }
    }
}

/// Parses a `pty-req` terminal-modes blob, and checks the same bytes as a
/// `TERM` value.
pub fn pty_modes(blob: &[u8]) {
    let _ = pty::Modes::parse(blob);
    let _ = pty::valid_term(blob);
}
