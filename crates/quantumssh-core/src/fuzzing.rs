//! Entry points for the fuzz targets in `fuzz/` (ADR-0060 §3).
//!
//! The module is compiled only under `--cfg fuzzing`, which cargo-fuzz
//! sets and no other build does. Each function is a thin call into the
//! crate's own parsers, for those the public API does not reach. None
//! holds parsing logic of its own, and none touches the filesystem or the
//! network.

use crate::auth::{self, AuthorizedKeys, UserauthRequest};
use crate::cert::{self, TrustedUserCaKeys};
use crate::wire::{self, Reader};
use crate::{channel, pty, sftp, transport};

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
    /// The user the connection's first request named: the seeds' user.
    pub const BOUND_USER: &'static str = "alice";

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

    /// Parses `payload` as the `authenticate` stage does, as a later
    /// request on a connection whose first request named
    /// [`Userauth::BOUND_USER`]. A request for another user ends there, as
    /// RFC-0019 §2 ends the connection; the rest goes on. A request that
    /// names a key of the set is resolved, and a signed one goes on to
    /// signature verification. Certificates are left to
    /// [`UserCertificate`], whose clock is fixed.
    pub fn check(&self, payload: &[u8]) {
        let Ok(request) = auth::parse_userauth_request(payload) else {
            return;
        };
        if !auth::same_user(Some(Self::BOUND_USER), request.user()) {
            return;
        }
        let UserauthRequest::PublicKey {
            user,
            key_algorithm,
            key_blob,
            signature,
        } = request
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

/// Reads channel-layer payloads from `input`, each as an SSH `string`, as
/// the session loop receives them after authentication (#271). Each one
/// goes through the parsers its message type reaches in `channel.rs`, and
/// for a request, the parser of its request type. The parsed windows then
/// go through the window arithmetic, with one outbound packet as large as
/// the windows allow after each message. No handler runs: they spawn
/// processes (ADR-0060 §4). A peer that overdraws or overflows a window
/// ends the input, as it ends the connection.
pub fn channel(input: &[u8]) {
    let mut payloads = Reader::new(input);
    let mut in_window = channel::INITIAL_WINDOW;
    let mut out_window = 0_u64;
    let mut out_max_packet = 0_u32;
    while let Ok(payload) = payloads.string(wire::MAX_PACKET as usize) {
        let mut r = Reader::new(payload);
        let Ok(message) = r.byte() else {
            continue;
        };
        match message {
            channel::SSH_MSG_CHANNEL_OPEN => {
                if let Ok(open) = channel::parse_channel_open(&mut r)
                    && open.max_packet != 0
                {
                    out_window = u64::from(open.window);
                    out_max_packet = open.max_packet;
                }
            }
            channel::SSH_MSG_CHANNEL_REQUEST => {
                if let Ok(head) = channel::parse_request_head(&mut r) {
                    match head.request_type {
                        b"exec" => drop(channel::parse_exec(&mut r)),
                        b"pty-req" => drop(channel::parse_pty_req(&mut r)),
                        b"subsystem" => drop(channel::parse_subsystem(&mut r)),
                        b"window-change" => drop(channel::parse_window_change(&mut r)),
                        _ => {}
                    }
                }
            }
            channel::SSH_MSG_CHANNEL_DATA => {
                if let Ok((_, data)) = channel::parse_channel_data(&mut r) {
                    let Some(left) = channel::take_inbound(in_window, data.len()) else {
                        return;
                    };
                    in_window = left;
                }
            }
            channel::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                if let Ok((_, add)) = channel::parse_window_adjust(&mut r) {
                    let Some(window) = channel::add_out_window(out_window, add) else {
                        return;
                    };
                    out_window = window;
                }
            }
            channel::SSH_MSG_CHANNEL_EOF => {
                let _ = channel::parse_recipient(&mut r, "malformed-channel-eof");
            }
            channel::SSH_MSG_CHANNEL_CLOSE => {
                let _ = channel::parse_recipient(&mut r, "malformed-channel-close");
            }
            channel::SSH_MSG_GLOBAL_REQUEST => {
                let _ = channel::parse_global_request(&mut r);
            }
            _ => {}
        }
        let sent = channel::send_size(out_window, out_max_packet, channel::MAX_PACKET as usize);
        out_window -= sent as u64;
    }
}

/// Parses a `pty-req` terminal-modes blob, and checks the same bytes as a
/// `TERM` value.
pub fn pty_modes(blob: &[u8]) {
    let _ = pty::Modes::parse(blob);
    let _ = pty::valid_term(blob);
}
