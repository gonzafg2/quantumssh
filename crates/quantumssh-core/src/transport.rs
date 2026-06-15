//! The transport type-state machine (RFC-0003).
//!
//! An [`Expect`] stage type exposes **only** the messages valid in
//! that stage, so out-of-sequence acceptance is a compile error, not
//! a runtime bug — the property that made rustls resistant to the
//! Terrapin bug class.
//!
//! The stages, in order:
//!
//! 1. [`version_exchange`] → [`Expect<KexInit>`]
//! 2. [`Expect<KexInit>::exchange_kexinit`] → [`Expect<HybridInit>`]
//! 3. [`Expect<HybridInit>::run_hybrid`] → [`Expect<NewKeys>`]
//! 4. [`Expect<NewKeys>::exchange_newkeys`] → [`Expect<ServiceRequest>`]
//!    — from here every byte is encrypted.
//! 5. [`Expect<ServiceRequest>::read_service_request`] →
//!    [`Expect<ServiceResponse>`], which can
//!    [`Expect<ServiceResponse>::deny`] unknown services or
//!    [`Expect<ServiceResponse>::accept`] `ssh-userauth` (M4).
//! 6. [`Expect<UserAuth>::authenticate`] → [`Expect<AuthAccepted>`],
//!    running the RFC 4252 §7 publickey loop.
//! 7. [`Expect<AuthAccepted>::reject_channel_open`] — the M4 terminal
//!    (M5 replaces this with a full channel layer).
//!
//! Each transition consumes the machine; there is no way to read a
//! message a stage does not expect, and an unexpected message on the
//! wire terminates the connection (strict-kex; ADR-0021).
//!
//! Strict-kex sequence-number discipline: both directions count from
//! zero after the identification exchange and reset to zero after
//! NEWKEYS — the send counter when we send ours, the receive counter
//! when the peer's arrives. The `ChaCha20` nonce *is* this counter, so
//! a reset bug cannot ship: the first encrypted packet would not
//! decrypt and every integration test would fail.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::auth::{self, AuthorizedKeys};
use crate::cipher::PacketCipher;
use crate::host_key::HostKey;
use crate::kex::{
    self, ExchangeHashInputs, KexError, Negotiated, Rejection, SSH_MSG_DISCONNECT,
    SSH_MSG_EXT_INFO, SSH_MSG_KEX_HYBRID_INIT, SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS,
};
use crate::wire::{self, Reader, Writer};

/// `SSH_MSG_SERVICE_REQUEST` (RFC 4253 §10).
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// `SSH_MSG_SERVICE_ACCEPT` (RFC 4253 §10).
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE` (RFC 4253 §11.1).
pub const DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
/// `SSH_DISCONNECT_BY_APPLICATION` (RFC 4253 §11.1) — used when
/// `MAX_AUTH_ATTEMPTS` is exhausted (ADR-0024).
pub const DISCONNECT_BY_APPLICATION: u32 = 11;

// Channel protocol constants used by `AuthAccepted` in M4 (prelude to
// M5, which implements the full RFC 4254 channel layer — ADR-0023).
/// `SSH_MSG_CHANNEL_OPEN` (RFC 4254 §5.1).
const SSH_MSG_CHANNEL_OPEN: u8 = 90;
/// `SSH_MSG_CHANNEL_OPEN_FAILURE` (RFC 4254 §5.1).
const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` (RFC 4254 §5.1).
const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
/// `SSH_MSG_GLOBAL_REQUEST` (RFC 4254 §4).
const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// `SSH_MSG_REQUEST_FAILURE` (RFC 4254 §4).
const SSH_MSG_REQUEST_FAILURE: u8 = 82;

/// Bound on a service name (RFC 4253 §10 defines two, both short).
const SERVICE_NAME_BOUND: usize = 64;

/// How a transport stage ended without reaching the next stage.
#[derive(Debug)]
pub enum TransportError {
    /// The peer was rejected: the audit event is logged and the
    /// `SSH_MSG_DISCONNECT` already sent. The reason is the structured
    /// `kex.failed` / disconnect reason string.
    Rejected(&'static str),
    /// I/O failed mid-stage (peer vanished, write error, …).
    Io(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) => write!(f, "peer rejected: {reason}"),
            Self::Io(e) => write!(f, "transport i/o failed: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The transport machine: stream, strict-kex sequence counters, and
/// the data of the stage `St` — the only stage whose messages exist.
pub struct Expect<S, St> {
    stream: S,
    seq_tx: u32,
    seq_rx: u32,
    stage: St,
}

/// Stage 1: the first packet must be the peer's `SSH_MSG_KEXINIT`.
pub struct KexInit {
    peer_id_line: Vec<u8>,
}

/// Stage 2: the only acceptable packet is `SSH_MSG_KEX_HYBRID_INIT`.
pub struct HybridInit {
    peer_id_line: Vec<u8>,
    /// Peer's exact KEXINIT payload (`I_C`).
    i_c: Vec<u8>,
    /// Our exact KEXINIT payload (`I_S`).
    i_s: Vec<u8>,
    negotiated: Negotiated,
}

/// Stage 3: the only acceptable packet is `SSH_MSG_NEWKEYS`.
pub struct NewKeys {
    negotiated: Negotiated,
    shared_secret: Zeroizing<[u8; 32]>,
    /// `H` — also the session identifier (RFC 4253 §7.2). Derived
    /// with `K` as input, so it gets the same erase-on-drop handling
    /// as the secret itself (threat model §4.3).
    exchange_hash: Zeroizing<[u8; 32]>,
}

/// Stage 4 — first encrypted stage: the only acceptable packet is
/// `SSH_MSG_SERVICE_REQUEST`.
pub struct ServiceRequest {
    rx: PacketCipher,
    tx: PacketCipher,
    /// The exchange hash `H` — also the session identifier (RFC 4253
    /// §7.2). Flows through every encrypted stage so `authenticate()`
    /// can verify signatures without plumbing the caller.
    session_id: Zeroizing<[u8; 32]>,
}

/// Stage 5: a service was requested; the machine can answer it.
/// M3 shipped [`Expect::deny`]; M4 adds the `ssh-userauth` accept arm.
pub struct ServiceResponse {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
}

/// Stage 6 (M4): the transport is ready to authenticate. The only
/// acceptable message is `SSH_MSG_USERAUTH_REQUEST` (50).
pub struct UserAuth {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
}

/// Stage 7 (M4 terminal): authentication succeeded.
/// Holds the authenticated identity; channels land in M5.
/// For now, [`Expect::reject_channel_open`] cleanly denies any
/// channel-open attempt.
pub struct AuthAccepted {
    rx: PacketCipher,
    tx: PacketCipher,
    /// Stored for M5 re-keying (issue #60) and channel integration.
    #[expect(dead_code)]
    session_id: Zeroizing<[u8; 32]>,
    /// The SHA256 fingerprint of the authenticated key. Used by M5
    /// for audit events (`exec.started` / `exec.finished`).
    #[expect(dead_code)]
    authenticated_identity: String,
}

/// Performs the RFC 4253 §4.2 identification exchange and produces
/// the machine in its first stage.
///
/// # Errors
///
/// [`TransportError::Io`] when writing our line fails;
/// [`TransportError::Rejected`] when the peer's line is overlong,
/// malformed, or names a protocol other than 2.0 (no DISCONNECT is
/// sent — the peer is not speaking SSH).
pub async fn version_exchange<S>(mut stream: S) -> Result<Expect<S, KexInit>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut our_id_line = Vec::with_capacity(64);
    our_id_line.extend_from_slice(wire::SERVER_ID.as_bytes());
    our_id_line.extend_from_slice(b"\r\n");
    stream
        .write_all(&our_id_line)
        .await
        .map_err(|e| TransportError::Io(format!("identification write failed: {e}")))?;

    let peer_id_line = read_id_line(&mut stream).await?;
    let peer_id = wire::parse_peer_id(&peer_id_line)
        .map_err(|_| TransportError::Rejected("bad-identification"))?;
    debug!(peer_software = %peer_id.softwareversion, "peer identification accepted");

    Ok(Expect {
        stream,
        seq_tx: 0,
        seq_rx: 0,
        stage: KexInit { peer_id_line },
    })
}

impl<S> Expect<S, KexInit>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Sends our KEXINIT, requires the peer's first packet to be its
    /// KEXINIT (strict-kex: anything else — `SSH_MSG_IGNORE` included
    /// — terminates), negotiates per ADR-0021, and skips the peer's
    /// guessed packet when `first_kex_packet_follows` guessed wrong.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] on any negotiation failure (the
    /// `kex.failed` audit event and DISCONNECT are emitted before
    /// returning); [`TransportError::Io`] when the connection breaks.
    pub async fn exchange_kexinit(mut self) -> Result<Expect<S, HybridInit>, TransportError> {
        let i_s = kex::build_kexinit()
            .map_err(|e| TransportError::Io(format!("kexinit build failed: {e}")))?;
        self.write_plain(&i_s).await?;

        let i_c = self.read_plain().await?;
        if i_c.first() != Some(&SSH_MSG_KEXINIT) {
            return Err(self
                .reject_plain(protocol_error("first-packet-not-kexinit"))
                .await);
        }

        let negotiated = match kex::parse_kexinit(&i_c).and_then(|peer| kex::negotiate(&peer, true))
        {
            Ok(n) => n,
            Err(KexError::Rejected(r)) => return Err(self.reject_plain(r).await),
            Err(KexError::Wire(e)) => {
                debug!(error = %e, "malformed peer KEXINIT");
                return Err(self.reject_plain(protocol_error("malformed-kexinit")).await);
            }
        };

        // Wrong guess from a first_kex_packet_follows peer: silently
        // skip exactly one KEX packet (RFC 4253 §7.1; ADR-0021). It
        // still counts against the receive sequence number.
        if negotiated.skip_guessed_packet {
            let _skipped = self.read_plain().await?;
            debug!("skipped wrong-guess KEX packet");
        }

        let peer_id_line = self.stage.peer_id_line;
        Ok(Expect {
            stream: self.stream,
            seq_tx: self.seq_tx,
            seq_rx: self.seq_rx,
            stage: HybridInit {
                peer_id_line,
                i_c,
                i_s,
                negotiated,
            },
        })
    }
}

impl<S> Expect<S, HybridInit>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Reads `SSH_MSG_KEX_HYBRID_INIT` — the only message this stage
    /// accepts — runs the hybrid exchange (abort if **either** half
    /// fails; ADR-0019), and replies with the signed
    /// `SSH_MSG_KEX_HYBRID_REPLY`.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] when the init is malformed or a
    /// hybrid half fails (audit event + DISCONNECT already sent);
    /// [`TransportError::Io`] when the connection breaks.
    pub async fn run_hybrid(
        mut self,
        host_key: &HostKey,
    ) -> Result<Expect<S, NewKeys>, TransportError> {
        let init_payload = self.read_plain().await?;
        let mut r = Reader::new(&init_payload);
        if r.byte().unwrap_or(0) != SSH_MSG_KEX_HYBRID_INIT {
            return Err(self
                .reject_plain(protocol_error("expected-hybrid-init"))
                .await);
        }
        let Ok(client_init) = r
            .string(kex::CLIENT_INIT_LEN)
            .and_then(|ci| r.finish().map(|()| ci))
        else {
            return Err(self
                .reject_plain(protocol_error("malformed-hybrid-init"))
                .await);
        };

        let outcome = match kex::hybrid_exchange(client_init) {
            Ok(o) => o,
            Err(KexError::Rejected(r)) => return Err(self.reject_plain(r).await),
            Err(KexError::Wire(_)) => {
                return Err(self
                    .reject_plain(protocol_error("malformed-hybrid-init"))
                    .await);
            }
        };

        let host_key_blob = host_key.public_key_blob();
        let exchange_hash = Zeroizing::new(kex::exchange_hash(&ExchangeHashInputs {
            client_id: &self.stage.peer_id_line,
            server_id: wire::SERVER_ID.as_bytes(),
            client_kexinit: &self.stage.i_c,
            server_kexinit: &self.stage.i_s,
            host_key_blob: &host_key_blob,
            client_init,
            server_reply: &outcome.server_reply,
            shared_secret: &outcome.shared_secret,
        }));
        let signature = host_key.sign(exchange_hash.as_ref());

        let mut reply = Writer::new();
        reply.put_byte(kex::SSH_MSG_KEX_HYBRID_REPLY);
        reply.put_string(&host_key_blob);
        reply.put_string(&outcome.server_reply);
        reply.put_string(&signature);
        self.write_plain(&reply.into_bytes()).await?;

        Ok(Expect {
            stream: self.stream,
            seq_tx: self.seq_tx,
            seq_rx: self.seq_rx,
            stage: NewKeys {
                negotiated: self.stage.negotiated,
                shared_secret: outcome.shared_secret,
                exchange_hash,
            },
        })
    }
}

impl<S> Expect<S, NewKeys>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Exchanges `SSH_MSG_NEWKEYS` (the only message this stage
    /// accepts), resets both sequence counters (strict-kex), installs
    /// the negotiated AEAD ciphers, and — when the client offered
    /// `ext-info-c` — sends the encrypted `SSH_MSG_EXT_INFO` carrying
    /// `server-sig-algs = ssh-ed25519` (ADR-0021; RFC 8308).
    ///
    /// Returns the negotiation summary for the `kex.completed` event
    /// alongside the encrypted machine.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] when the peer's packet is not
    /// NEWKEYS (DISCONNECT sent); [`TransportError::Io`] when the
    /// connection breaks.
    pub async fn exchange_newkeys(
        mut self,
    ) -> Result<(Negotiated, Expect<S, ServiceRequest>), TransportError> {
        self.write_plain(&[SSH_MSG_NEWKEYS]).await?;
        // strict-kex: our NEWKEYS is on the wire — outgoing counter
        // resets; the first encrypted packet we send is sequence 0.
        self.seq_tx = 0;

        let peer_newkeys = self.read_plain().await?;
        if peer_newkeys.as_slice() != [SSH_MSG_NEWKEYS] {
            return Err(self.reject_plain(protocol_error("expected-newkeys")).await);
        }
        // strict-kex: peer NEWKEYS received — incoming counter resets.
        self.seq_rx = 0;

        // Key schedule (RFC 4253 §7.2; HASH = SHA-256). The first
        // exchange hash is the session identifier.
        let session_id = &self.stage.exchange_hash;
        let k = &self.stage.shared_secret;
        let h = &self.stage.exchange_hash;
        let derive = |letter: u8, len: usize| -> Zeroizing<Vec<u8>> {
            let mut out = kex::derive_key(k, h, letter, session_id, len);
            out.truncate(len);
            out
        };

        let c2s = &self.stage.negotiated.cipher_c2s;
        let s2c = &self.stage.negotiated.cipher_s2c;
        let rx = PacketCipher::new(
            c2s,
            &derive(b'C', PacketCipher::key_len(c2s)),
            &derive(b'A', PacketCipher::iv_len(c2s)),
        )
        .map_err(|e| TransportError::Io(format!("cipher install failed: {e}")))?;
        let tx = PacketCipher::new(
            s2c,
            &derive(b'D', PacketCipher::key_len(s2c)),
            &derive(b'B', PacketCipher::iv_len(s2c)),
        )
        .map_err(|e| TransportError::Io(format!("cipher install failed: {e}")))?;

        let negotiated = self.stage.negotiated;
        let mut next = Expect {
            stream: self.stream,
            seq_tx: self.seq_tx,
            seq_rx: self.seq_rx,
            stage: ServiceRequest {
                rx,
                tx,
                session_id: self.stage.exchange_hash,
            },
        };

        // EXT_INFO rides the new keys: RFC 8308 §2.3 places it
        // immediately after our first NEWKEYS, which makes it the
        // first encrypted packet of the connection.
        if negotiated.ext_info {
            let mut w = Writer::new();
            w.put_byte(SSH_MSG_EXT_INFO);
            w.put_uint32(1);
            w.put_string(b"server-sig-algs");
            w.put_string(kex::HOST_KEY_LIST.as_bytes());
            next.write_sealed(&w.into_bytes()).await?;
        }

        Ok((negotiated, next))
    }
}

impl<S> Expect<S, ServiceRequest>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Reads the encrypted `SSH_MSG_SERVICE_REQUEST` — the only
    /// message this stage accepts — and returns the requested service
    /// name with the machine advanced to its response stage.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] when the packet fails
    /// authentication or is not a well-formed service request
    /// (DISCONNECT sent where the channel is still trustworthy);
    /// [`TransportError::Io`] when the connection breaks.
    pub async fn read_service_request(
        mut self,
    ) -> Result<(String, Expect<S, ServiceResponse>), TransportError> {
        let payload = self.read_sealed().await?;
        let mut r = Reader::new(&payload);
        let parsed: Result<String, wire::WireError> = (|| {
            let msg = r.byte()?;
            if msg != SSH_MSG_SERVICE_REQUEST {
                return Err(wire::WireError::Truncated);
            }
            let name = r.string(SERVICE_NAME_BOUND)?;
            r.finish()?;
            String::from_utf8(name.to_vec()).map_err(|_| wire::WireError::Truncated)
        })();
        let Ok(service) = parsed else {
            return Err(self
                .reject_sealed(protocol_error("expected-service-request"))
                .await);
        };

        let stage = ServiceResponse {
            rx: self.stage.rx,
            tx: self.stage.tx,
            session_id: self.stage.session_id,
        };
        Ok((
            service,
            Expect {
                stream: self.stream,
                seq_tx: self.seq_tx,
                seq_rx: self.seq_rx,
                stage,
            },
        ))
    }
}

impl<S> Expect<S, ServiceResponse>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Denies the requested service with
    /// `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE` (RFC 4253 §10) and
    /// consumes the machine. The only M3 answer: `ssh-userauth`
    /// arrives with the auth milestone (M4), which adds the accept
    /// arm beside this one.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] always — that is this method's
    /// outcome — or [`TransportError::Io`] if even the disconnect
    /// cannot be written.
    pub async fn deny(mut self) -> TransportError {
        let rejection = Rejection {
            reason: "service-not-available",
            disconnect_code: DISCONNECT_SERVICE_NOT_AVAILABLE,
        };
        // General tier, not `audit`: the ADR-0024 event vocabulary is
        // closed and this is not one of its events — the schema's
        // `connection.closed` carries the reason for the record.
        warn!(
            reason = rejection.reason,
            disconnect_code = rejection.disconnect_code,
            "service denied"
        );
        let packet = disconnect_payload(&rejection);
        if let Err(e) = self.write_sealed(&packet).await {
            return e;
        }
        TransportError::Rejected(rejection.reason)
    }

    /// Accepts the requested service with `SSH_MSG_SERVICE_ACCEPT`
    /// (RFC 4253 §10) and advances the machine to the `UserAuth` stage,
    /// ready to authenticate.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] when the accept packet cannot be written.
    pub async fn accept(mut self) -> Result<Expect<S, UserAuth>, TransportError> {
        let mut w = Writer::new();
        w.put_byte(SSH_MSG_SERVICE_ACCEPT);
        self.write_sealed(&w.into_bytes()).await?;

        let stage = UserAuth {
            rx: self.stage.rx,
            tx: self.stage.tx,
            session_id: self.stage.session_id,
        };
        Ok(Expect {
            stream: self.stream,
            seq_tx: self.seq_tx,
            seq_rx: self.seq_rx,
            stage,
        })
    }
}

impl<S> Expect<S, UserAuth>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Runs the RFC 4252 §7 `publickey` authentication loop.
    ///
    /// Reads `SSH_MSG_USERAUTH_REQUEST` messages until a valid Ed25519
    /// signature authenticates the peer, and advances the machine to
    /// [`AuthAccepted`]. Every other method or non-Ed25519 key type is
    /// refused with `SSH_MSG_USERAUTH_FAILURE`; unknown keys get a
    /// `SSH_MSG_USERAUTH_PK_OK` probe. After
    /// [`auth::MAX_AUTH_ATTEMPTS`] failures, the connection is
    /// terminated with `SSH_DISCONNECT_BY_APPLICATION` (11).
    ///
    /// Audit events (`auth.succeeded` / `auth.failed`) are emitted on
    /// the `audit` target (ADR-0024).
    ///
    /// Returns the authenticated key's fingerprint and the machine
    /// advanced to [`AuthAccepted`].
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] when the attempt budget is
    /// exhausted, a wire-level parse fails, or the peer sends an
    /// unexpected message; [`TransportError::Io`] when the connection
    /// breaks.
    #[allow(clippy::too_many_lines)]
    pub async fn authenticate(
        mut self,
        authorized_keys: &AuthorizedKeys,
    ) -> Result<(String, Expect<S, AuthAccepted>), TransportError> {
        let mut failure_count: u32 = 0;

        loop {
            let payload = self.read_sealed().await?;
            let payload_len = payload.len();
            let mut r = Reader::new(&payload);

            let msg = r.byte().unwrap_or(0);
            if msg != auth::SSH_MSG_USERAUTH_REQUEST {
                return Err(self
                    .reject_sealed(protocol_error("expected-userauth-request"))
                    .await);
            }

            let Ok(user_name) = r
                .string(auth::USER_NAME_BOUND)
                .and_then(|s| std::str::from_utf8(s).map_err(|_| wire::WireError::Truncated))
            else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

            let Ok(_service_name) = r
                .string(auth::SERVICE_NAME_BOUND)
                .and_then(|s| std::str::from_utf8(s).map_err(|_| wire::WireError::Truncated))
            else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

            let Ok(method) = r
                .string(auth::METHOD_NAME_BOUND)
                .and_then(|s| std::str::from_utf8(s).map_err(|_| wire::WireError::Truncated))
            else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

            if method != auth::AUTH_METHOD {
                failure_count += 1;
                if failure_count >= auth::MAX_AUTH_ATTEMPTS {
                    return Err(self
                        .reject_sealed(Rejection {
                            reason: "too-many-auth-attempts",
                            disconnect_code: DISCONNECT_BY_APPLICATION,
                        })
                        .await);
                }
                warn!(
                    target: "audit",
                    auth_method = method,
                    failure_count,
                    "auth.failed"
                );
                let failure = auth::build_failure_payload(false);
                self.write_sealed(&failure).await?;
                continue;
            }

            let sig_present = r.boolean().unwrap_or(false);

            let Ok(key_algorithm) = r
                .string(auth::KEY_ALGO_BOUND)
                .and_then(|s| std::str::from_utf8(s).map_err(|_| wire::WireError::Truncated))
            else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

            if key_algorithm != auth::KEY_ALGORITHM {
                failure_count += 1;
                if failure_count >= auth::MAX_AUTH_ATTEMPTS {
                    return Err(self
                        .reject_sealed(Rejection {
                            reason: "too-many-auth-attempts",
                            disconnect_code: DISCONNECT_BY_APPLICATION,
                        })
                        .await);
                }
                warn!(
                    target: "audit",
                    auth_method = method,
                    failure_count,
                    "auth.failed"
                );
                let failure = auth::build_failure_payload(false);
                self.write_sealed(&failure).await?;
                continue;
            }

            let Ok(key_blob) = r.string(auth::KEY_BLOB_BOUND) else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

            // Snapshot the position: bytes consumed so far (everything
            // up to, but not including, the signature field).
            let consumed_before_sig = payload_len - r.remaining();
            let payload_without_sig = &payload[..consumed_before_sig];

            if sig_present {
                let Ok(signature) = r.string(auth::SIGNATURE_BOUND) else {
                    return Err(self
                        .reject_sealed(protocol_error("malformed-userauth-request"))
                        .await);
                };
                if r.finish().is_err() {
                    return Err(self
                        .reject_sealed(protocol_error("malformed-userauth-request"))
                        .await);
                }

                let Some(ak) = authorized_keys.lookup(key_blob) else {
                    failure_count += 1;
                    if failure_count >= auth::MAX_AUTH_ATTEMPTS {
                        return Err(self
                            .reject_sealed(Rejection {
                                reason: "too-many-auth-attempts",
                                disconnect_code: DISCONNECT_BY_APPLICATION,
                            })
                            .await);
                    }
                    warn!(
                        target: "audit",
                        auth_method = method,
                        failure_count,
                        "auth.failed"
                    );
                    let failure = auth::build_failure_payload(false);
                    self.write_sealed(&failure).await?;
                    continue;
                };

                let session_id = &*self.stage.session_id;
                if auth::verify_auth_signature(
                    session_id,
                    payload_without_sig,
                    signature,
                    &ak.verifying_key,
                ) == Ok(())
                {
                    let success = auth::build_success_payload();
                    self.write_sealed(&success).await?;
                    info!(
                        target: "audit",
                        user = %user_name,
                        authenticated_identity = %ak.fingerprint,
                        auth_method = method,
                        "auth.succeeded"
                    );
                    let stage = AuthAccepted {
                        rx: self.stage.rx,
                        tx: self.stage.tx,
                        session_id: self.stage.session_id,
                        authenticated_identity: ak.fingerprint.clone(),
                    };
                    return Ok((
                        ak.fingerprint.clone(),
                        Expect {
                            stream: self.stream,
                            seq_tx: self.seq_tx,
                            seq_rx: self.seq_rx,
                            stage,
                        },
                    ));
                }
                failure_count += 1;
                if failure_count >= auth::MAX_AUTH_ATTEMPTS {
                    return Err(self
                        .reject_sealed(Rejection {
                            reason: "too-many-auth-attempts",
                            disconnect_code: DISCONNECT_BY_APPLICATION,
                        })
                        .await);
                }
                warn!(
                    target: "audit",
                    auth_method = method,
                    failure_count,
                    "auth.failed"
                );
                let failure = auth::build_failure_payload(false);
                self.write_sealed(&failure).await?;
                continue;
            }

            // No signature present: probe whether the key is known.
            if r.finish().is_err() {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            }

            if authorized_keys.lookup(key_blob).is_some() {
                let pk_ok = auth::build_pk_ok(auth::KEY_ALGORITHM, key_blob);
                self.write_sealed(&pk_ok).await?;
            } else {
                failure_count += 1;
                if failure_count >= auth::MAX_AUTH_ATTEMPTS {
                    return Err(self
                        .reject_sealed(Rejection {
                            reason: "too-many-auth-attempts",
                            disconnect_code: DISCONNECT_BY_APPLICATION,
                        })
                        .await);
                }
                warn!(
                    target: "audit",
                    auth_method = method,
                    failure_count,
                    "auth.failed"
                );
                let failure = auth::build_failure_payload(false);
                self.write_sealed(&failure).await?;
            }
        }
    }
}

impl<S> Expect<S, AuthAccepted>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// M4 terminal: reads the next post-auth packet and rejects channel
    /// opens cleanly. Channels land in M5 (ADR-0023).
    ///
    /// - `SSH_MSG_CHANNEL_OPEN` → `SSH_MSG_CHANNEL_OPEN_FAILURE` with
    ///   `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
    /// - `SSH_MSG_GLOBAL_REQUEST` → `SSH_MSG_REQUEST_FAILURE`.
    /// - `SSH_MSG_DISCONNECT` → returns `Rejected` without reply.
    /// - Anything else → `SSH_DISCONNECT_PROTOCOL_ERROR`.
    ///
    /// # Errors
    ///
    /// Always returns [`TransportError::Rejected`] (the M4 terminus) or
    /// [`TransportError::Io`] if writing fails.
    pub async fn reject_channel_open(mut self) -> TransportError {
        let Ok(payload) = self.read_sealed().await else {
            return TransportError::Io("packet read failed".into());
        };
        let mut r = Reader::new(&payload);
        let msg = r.byte().unwrap_or(0);

        match msg {
            SSH_MSG_CHANNEL_OPEN => {
                let rejection = Rejection {
                    reason: "channels land in M5",
                    disconnect_code: kex::DISCONNECT_PROTOCOL_ERROR,
                };
                // Parse the sender channel from the peer's message
                // (RFC 4254 §5.1: recipient_channel must echo sender_channel).
                let _channel_type = r.string(64).unwrap_or(b"");
                let sender_channel = r.uint32().unwrap_or(0);
                let mut w = Writer::new();
                w.put_byte(SSH_MSG_CHANNEL_OPEN_FAILURE);
                w.put_uint32(sender_channel);
                w.put_uint32(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
                w.put_string(b"channels land in M5");
                w.put_string(b""); // language tag
                if let Err(e) = self.write_sealed(&w.into_bytes()).await {
                    return e;
                }
                warn!(
                    reason = rejection.reason,
                    disconnect_code = rejection.disconnect_code,
                    "channels land in M5"
                );
                TransportError::Rejected(rejection.reason)
            }
            SSH_MSG_GLOBAL_REQUEST => {
                let mut w = Writer::new();
                w.put_byte(SSH_MSG_REQUEST_FAILURE);
                if let Err(e) = self.write_sealed(&w.into_bytes()).await {
                    return e;
                }
                warn!(reason = "global-request-refused", "connection.closed");
                TransportError::Rejected("global-request-refused")
            }
            SSH_MSG_DISCONNECT => {
                warn!(reason = "peer-disconnected", "connection.closed");
                TransportError::Rejected("peer-disconnected")
            }
            _ => {
                let rejection = protocol_error("unexpected-post-auth-message");
                if let Err(e) = self.write_sealed(&disconnect_payload(&rejection)).await {
                    return e;
                }
                TransportError::Rejected(rejection.reason)
            }
        }
    }
}

/// ---- shared plumbing (private: stages cannot be bypassed) ----
///
/// A protocol-error rejection (code 2) with the given reason.
const fn protocol_error(reason: &'static str) -> Rejection {
    Rejection {
        reason,
        disconnect_code: kex::DISCONNECT_PROTOCOL_ERROR,
    }
}

/// The `SSH_MSG_DISCONNECT` payload for a rejection.
fn disconnect_payload(rejection: &Rejection) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_DISCONNECT);
    w.put_uint32(rejection.disconnect_code);
    w.put_string(rejection.reason.as_bytes());
    w.put_string(b""); // language tag
    w.into_bytes()
}

impl<S, St> Expect<S, St>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Reads one plaintext packet, validating the declared length
    /// against the hard cap **before** the body is allocated or read.
    async fn read_plain(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut len_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| TransportError::Io(format!("packet read failed: {e}")))?;
        let declared = u32::from_be_bytes(len_bytes);
        let body_len = wire::validate_packet_length(declared)
            .map_err(|_| TransportError::Rejected("malformed-packet"))?;
        let mut body = vec![0u8; body_len];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| TransportError::Io(format!("packet read failed: {e}")))?;
        let payload = wire::decode_packet_body(&body)
            .map_err(|_| TransportError::Rejected("malformed-packet"))?
            .to_vec();
        self.seq_rx = self.seq_rx.wrapping_add(1);
        Ok(payload)
    }

    /// Writes one plaintext packet around `payload`.
    async fn write_plain(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let packet = wire::encode_packet(payload)
            .map_err(|e| TransportError::Io(format!("packet encode failed: {e}")))?;
        self.stream
            .write_all(&packet)
            .await
            .map_err(|e| TransportError::Io(format!("packet write failed: {e}")))?;
        self.seq_tx = self.seq_tx.wrapping_add(1);
        Ok(())
    }

    /// Sends the plaintext DISCONNECT and consumes the machine.
    ///
    /// The `kex.failed` audit event fires only for ADR-0021's
    /// negotiation rejections — the paths ADR-0024 scopes it to,
    /// always `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3). Wire-level
    /// protocol violations (code 2) log on the general tier; the
    /// schema's `connection.closed` carries their reason.
    async fn reject_plain(mut self, rejection: Rejection) -> TransportError {
        if rejection.disconnect_code == kex::DISCONNECT_KEY_EXCHANGE_FAILED {
            warn!(
                target: "audit",
                reason = rejection.reason,
                disconnect_code = rejection.disconnect_code,
                "kex.failed"
            );
        } else {
            warn!(
                reason = rejection.reason,
                disconnect_code = rejection.disconnect_code,
                "kex protocol violation"
            );
        }
        if let Err(e) = self.write_plain(&disconnect_payload(&rejection)).await {
            debug!(error = %e, "disconnect write failed");
        }
        TransportError::Rejected(rejection.reason)
    }
}

/// Encrypted I/O capabilities, sealed in a private module: only the
/// stages defined here can grant access to a cipher, and only in the
/// direction their wire discipline allows — there is no runtime
/// branch to get it wrong (the anti-accept-and-branch property,
/// RFC-0003).
mod sealed {
    use crate::cipher::PacketCipher;

    /// Encrypted *receive* capability.
    pub trait SealedRead {
        fn rx(&mut self) -> &mut PacketCipher;
    }

    /// Encrypted *send* capability.
    pub trait SealedWrite {
        fn tx(&mut self) -> &mut PacketCipher;
    }
}

use sealed::{SealedRead, SealedWrite};

impl SealedRead for ServiceRequest {
    fn rx(&mut self) -> &mut PacketCipher {
        &mut self.rx
    }
}

impl SealedWrite for ServiceRequest {
    fn tx(&mut self) -> &mut PacketCipher {
        &mut self.tx
    }
}

impl SealedWrite for ServiceResponse {
    fn tx(&mut self) -> &mut PacketCipher {
        &mut self.tx
    }
}

impl SealedRead for ServiceResponse {
    fn rx(&mut self) -> &mut PacketCipher {
        &mut self.rx
    }
}

impl SealedRead for UserAuth {
    fn rx(&mut self) -> &mut PacketCipher {
        &mut self.rx
    }
}

impl SealedWrite for UserAuth {
    fn tx(&mut self) -> &mut PacketCipher {
        &mut self.tx
    }
}

impl SealedRead for AuthAccepted {
    fn rx(&mut self) -> &mut PacketCipher {
        &mut self.rx
    }
}

impl SealedWrite for AuthAccepted {
    fn tx(&mut self) -> &mut PacketCipher {
        &mut self.tx
    }
}

impl<S, St> Expect<S, St>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    St: SealedRead,
{
    /// Reads one encrypted packet: the cipher validates the (possibly
    /// encrypted) length **before** the body is allocated, and the
    /// tag before anything is decrypted. Any failure terminates the
    /// connection without a response — an unauthenticated peer earns
    /// no diagnostic.
    async fn read_sealed(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut length_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut length_bytes)
            .await
            .map_err(|e| TransportError::Io(format!("packet read failed: {e}")))?;
        let seqnr = self.seq_rx;
        let body_len = self
            .stage
            .rx()
            .body_len(seqnr, length_bytes)
            .map_err(|_| TransportError::Rejected("packet-auth-failed"))?;
        let mut body = vec![0u8; body_len];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| TransportError::Io(format!("packet read failed: {e}")))?;
        let payload = self
            .stage
            .rx()
            .open(seqnr, length_bytes, &mut body)
            .map_err(|_| TransportError::Rejected("packet-auth-failed"))?;
        self.seq_rx = self.seq_rx.wrapping_add(1);
        Ok(payload)
    }
}

impl<S, St> Expect<S, St>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    St: SealedWrite,
{
    /// Seals and writes one packet.
    async fn write_sealed(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let seqnr = self.seq_tx;
        let packet = self
            .stage
            .tx()
            .seal(seqnr, payload)
            .map_err(|e| TransportError::Io(format!("packet seal failed: {e}")))?;
        self.stream
            .write_all(&packet)
            .await
            .map_err(|e| TransportError::Io(format!("packet write failed: {e}")))?;
        self.seq_tx = self.seq_tx.wrapping_add(1);
        Ok(())
    }

    /// Sends the encrypted DISCONNECT and consumes the machine.
    ///
    /// Logged on the general tier, not as `kex.failed`: ADR-0024
    /// scopes that audit event to ADR-0021's negotiation rejection
    /// paths, and a post-NEWKEYS protocol violation is not one — the
    /// schema's `connection.closed` carries the reason for the record.
    async fn reject_sealed(mut self, rejection: Rejection) -> TransportError {
        warn!(
            reason = rejection.reason,
            disconnect_code = rejection.disconnect_code,
            "post-kex protocol violation"
        );
        if let Err(e) = self.write_sealed(&disconnect_payload(&rejection)).await {
            debug!(error = %e, "disconnect write failed");
        }
        TransportError::Rejected(rejection.reason)
    }
}

/// Reads the peer's identification line (one line, byte-bounded at
/// [`wire::MAX_ID_LINE`]), returning the raw line without CRLF.
async fn read_id_line<S>(stream: &mut S) -> Result<Vec<u8>, TransportError>
where
    S: AsyncRead + Unpin + Send,
{
    let mut line = Vec::with_capacity(64);
    loop {
        if line.len() >= wire::MAX_ID_LINE {
            return Err(TransportError::Rejected("bad-identification"));
        }
        let byte = stream
            .read_u8()
            .await
            .map_err(|_| TransportError::Rejected("bad-identification"))?;
        if byte == b'\n' {
            break;
        }
        line.push(byte);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(line)
}
