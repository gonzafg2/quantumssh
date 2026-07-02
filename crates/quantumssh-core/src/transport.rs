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
//! 7. [`Expect<AuthAccepted>::serve`] → transitions to [`Session`] and
//!    runs the M5 channel layer: one `session` channel carrying one
//!    `exec`, then a clean close (ADR-0023).
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

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
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
    /// Peer identification line (no CRLF). Carried forward so a re-key
    /// can rebuild the exchange hash, which binds it (ADR-0026).
    client_id: Vec<u8>,
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
    client_id: Vec<u8>,
}

/// Stage 5: a service was requested; the machine can answer it.
/// M3 shipped [`Expect::deny`]; M4 adds the `ssh-userauth` accept arm.
pub struct ServiceResponse {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
    client_id: Vec<u8>,
}

/// Stage 6 (M4): the transport is ready to authenticate. The only
/// acceptable message is `SSH_MSG_USERAUTH_REQUEST` (50).
pub struct UserAuth {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
    client_id: Vec<u8>,
}

/// Stage 7 (M4): authentication succeeded. [`Expect::serve`] transitions
/// this into [`Session`] and runs the channel layer (M5).
pub struct AuthAccepted {
    rx: PacketCipher,
    tx: PacketCipher,
    /// The authenticated key fingerprint (`SHA256:…`), threaded from
    /// `authenticate()` so the `exec.*` audit events can attribute the
    /// command to the key that authorised it (ADR-0024).
    identity: String,
    /// The session id (first `H`) and peer id line, carried for re-keying
    /// (ADR-0026): a re-key derives keys with this session id and binds
    /// `client_id` into the new exchange hash.
    session_id: Zeroizing<[u8; 32]>,
    client_id: Vec<u8>,
}

/// Stage 8 (M5): the connection-protocol phase.
///
/// Carries the cipher pair, the authenticated identity, and a
/// **resumable** receive buffer (`inbuf`) so [`Expect::read_packet`] is
/// cancel-safe — the channel driver `select!`s the read against
/// blocking-thread child output, and a cancelled read must not desync
/// the stream (ADR-0023).
pub struct Session {
    rx: PacketCipher,
    tx: PacketCipher,
    identity: String,
    /// Bytes read from the wire but not yet framed into a packet.
    /// Bounded to one full frame (`4 + body_len`) at a time; progress
    /// survives `select!` cancellation.
    inbuf: Vec<u8>,
    /// Host key — re-signs the exchange hash on every re-key (ADR-0026).
    host_key: Arc<HostKey>,
    /// Peer id line, bound into each re-key's exchange hash.
    client_id: Vec<u8>,
    /// The session id (first `H`), invariant for the connection's life
    /// (RFC 4253 §7.2); re-key key derivation uses it. `session_id` is the
    /// RFC term, so the struct-name-prefix lint does not apply.
    #[allow(clippy::struct_field_names)]
    session_id: Zeroizing<[u8; 32]>,
    /// Re-keying accounting and sub-state machine (ADR-0026).
    rekey: RekeyState,
}

/// Thresholds that trigger a re-key (ADR-0026). Injectable so tests can
/// fire at a few KiB instead of 1 GiB.
#[derive(Clone, Copy, Debug)]
pub struct RekeyThresholds {
    /// Re-key when either direction reaches this many payload bytes.
    pub max_bytes: u64,
    /// Re-key when this much wall-clock elapses since the last exchange.
    pub max_interval: Duration,
    /// A started re-key must finish within this budget, else disconnect.
    pub completion_deadline: Duration,
}

impl RekeyThresholds {
    /// BSI TR-02102-4 §3.3.1 defaults: 1 GiB / 1 hour; the re-key
    /// completion budget mirrors the handshake budget (ADR-0022).
    #[must_use]
    pub const fn bsi_defaults(handshake_budget: Duration) -> Self {
        Self {
            max_bytes: 1024 * 1024 * 1024,
            max_interval: Duration::from_hours(1),
            completion_deadline: handshake_budget,
        }
    }
}

/// Re-key accounting + the sub-state machine for one connection.
struct RekeyState {
    bytes_rx: u64,
    bytes_tx: u64,
    /// When the last exchange completed — drives the interval trigger and
    /// the inter-re-key rate limit.
    last_kex: Instant,
    /// When the current re-key began — drives the completion deadline.
    /// Meaningful only while `phase != Idle`.
    started: Instant,
    /// Who started the current re-key (`server`|`peer`) and what triggered
    /// it (`bytes`|`time`|`peer`) — for the `rekey.completed` audit event.
    initiator: &'static str,
    trigger: &'static str,
    thresholds: RekeyThresholds,
    phase: RekeyPhase,
}

/// The re-key handshake's position. `Idle` between exchanges.
enum RekeyPhase {
    Idle,
    /// We sent our KEXINIT; awaiting the peer's.
    SentKexInit {
        i_s: Vec<u8>,
    },
    /// KEXINITs exchanged; awaiting `SSH_MSG_KEX_HYBRID_INIT`.
    AwaitHybridInit {
        i_c: Vec<u8>,
        i_s: Vec<u8>,
        negotiated: Negotiated,
        skip_guessed: bool,
    },
    /// We sent our NEWKEYS (tx installed); awaiting the peer's NEWKEYS to
    /// install the staged receive cipher.
    AwaitNewKeys {
        new_rx: PacketCipher,
    },
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
                client_id: self.stage.peer_id_line,
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

        // Key schedule (RFC 4253 §7.2). On the initial KEX the session id
        // *is* the exchange hash; both are the same `H` here.
        let (rx, tx) = derive_cipher_pair(
            &self.stage.shared_secret,
            &self.stage.exchange_hash,
            &self.stage.exchange_hash,
            &self.stage.negotiated.cipher_c2s,
            &self.stage.negotiated.cipher_s2c,
        )?;

        let negotiated = self.stage.negotiated;
        let mut next = Expect {
            stream: self.stream,
            seq_tx: self.seq_tx,
            seq_rx: self.seq_rx,
            stage: ServiceRequest {
                rx,
                tx,
                session_id: self.stage.exchange_hash,
                client_id: self.stage.client_id,
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
            client_id: self.stage.client_id,
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
            client_id: self.stage.client_id,
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
    /// Returns the machine advanced to [`AuthAccepted`].
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
    ) -> Result<Expect<S, AuthAccepted>, TransportError> {
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

            let Ok(_user_name) = r
                .string(auth::USER_NAME_BOUND)
                .and_then(|s| std::str::from_utf8(s).map_err(|_| wire::WireError::Truncated))
            else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

            let Ok(service_name) = r
                .string(auth::SERVICE_NAME_BOUND)
                .and_then(|s| std::str::from_utf8(s).map_err(|_| wire::WireError::Truncated))
            else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };
            if service_name != "ssh-connection" {
                return Err(self
                    .reject_sealed(protocol_error("unexpected-service-name"))
                    .await);
            }

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

            let Ok(sig_present) = r.boolean() else {
                return Err(self
                    .reject_sealed(protocol_error("malformed-userauth-request"))
                    .await);
            };

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

                // Unwrap the nested signature encoding (RFC 4252 §7 / RFC 8709 §6):
                //   string("ssh-ed25519") + string(<64-byte raw sig>)
                let mut sig_reader = Reader::new(signature);
                let Ok(parsed_sig_algo) = sig_reader.string(auth::KEY_ALGO_BOUND) else {
                    return Err(self
                        .reject_sealed(protocol_error("malformed-userauth-request"))
                        .await);
                };
                if parsed_sig_algo != auth::KEY_ALGORITHM.as_bytes() {
                    return Err(self
                        .reject_sealed(protocol_error("malformed-userauth-request"))
                        .await);
                }
                let Ok(raw_sig) = sig_reader.string(auth::SIGNATURE_BOUND) else {
                    return Err(self
                        .reject_sealed(protocol_error("malformed-userauth-request"))
                        .await);
                };
                if sig_reader.finish().is_err() {
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
                    raw_sig,
                    &ak.verifying_key,
                ) == Ok(())
                {
                    let success = auth::build_success_payload();
                    self.write_sealed(&success).await?;
                    info!(
                        target: "audit",
                        authenticated_identity = %ak.fingerprint,
                        auth_method = method,
                        "auth.succeeded"
                    );
                    let stage = AuthAccepted {
                        rx: self.stage.rx,
                        tx: self.stage.tx,
                        identity: ak.fingerprint.clone(),
                        session_id: self.stage.session_id,
                        client_id: self.stage.client_id,
                    };
                    return Ok(Expect {
                        stream: self.stream,
                        seq_tx: self.seq_tx,
                        seq_rx: self.seq_rx,
                        stage,
                    });
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
    /// Transitions into the [`Session`] stage and runs the M5 channel
    /// layer (ADR-0023): one `session` channel carrying one `exec`, then
    /// a clean close.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] on a protocol violation (the
    /// `SSH_MSG_DISCONNECT` is already sent), or [`TransportError::Io`]
    /// if the connection fails mid-session. Returns `Ok(())` on a clean
    /// session close.
    pub async fn serve(
        self,
        host_key: Arc<HostKey>,
        thresholds: RekeyThresholds,
    ) -> Result<(), TransportError> {
        let mut session = Expect {
            stream: self.stream,
            seq_tx: self.seq_tx,
            seq_rx: self.seq_rx,
            stage: Session {
                rx: self.stage.rx,
                tx: self.stage.tx,
                identity: self.stage.identity,
                inbuf: Vec::new(),
                host_key,
                client_id: self.stage.client_id,
                session_id: self.stage.session_id,
                rekey: RekeyState {
                    bytes_rx: 0,
                    bytes_tx: 0,
                    last_kex: Instant::now(),
                    started: Instant::now(),
                    initiator: "server",
                    trigger: "bytes",
                    thresholds,
                    phase: RekeyPhase::Idle,
                },
            },
        };
        crate::channel::drive(&mut session).await
    }
}

impl<S> Expect<S, Session>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Reads one decrypted packet, **cancel-safe**: partial progress
    /// lives in `self.stage.inbuf` and survives `select!` cancellation,
    /// so a read dropped mid-frame never desyncs the stream. Shares the
    /// length-bound + tag-verify discipline of [`Self::read_sealed`] via
    /// the [`frame_body_len`]/[`open_frame`] helpers — there is no second
    /// framing path that could diverge.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] on EOF or a read error;
    /// [`TransportError::Rejected`] (`packet-auth-failed`) on a length or
    /// tag violation.
    pub(crate) async fn read_packet(&mut self) -> Result<Vec<u8>, TransportError> {
        // 1. Ensure the 4 length bytes are buffered.
        while self.stage.inbuf.len() < 4 {
            self.fill_inbuf(4).await?;
        }
        let len4: [u8; 4] = self.stage.inbuf[..4].try_into().expect("4 bytes present");
        let seqnr = self.seq_rx;
        let body_len = frame_body_len(&self.stage.rx, seqnr, len4)?;
        let total = 4 + body_len;
        // 2. Ensure the whole frame is buffered (bounded: total ≤ 4 + MAX_PACKET).
        while self.stage.inbuf.len() < total {
            self.fill_inbuf(total).await?;
        }
        // 3. Split off exactly one frame; the remainder (if any) stays
        //    buffered for the next call.
        let mut frame: Vec<u8> = self.stage.inbuf.drain(..total).collect();
        let payload = open_frame(&mut self.stage.rx, seqnr, len4, &mut frame[4..])?;
        self.seq_rx = self.seq_rx.wrapping_add(1);
        // Re-key accounting (ADR-0026): inbound payload bytes under this key.
        self.stage.rekey.bytes_rx = self
            .stage
            .rekey
            .bytes_rx
            .saturating_add(payload.len() as u64);
        Ok(payload)
    }

    /// Reads more bytes into `inbuf`, never past `want` total bytes (so
    /// `inbuf` is bounded by one frame). Cancel-safe:
    /// [`AsyncReadExt::read`] guarantees no bytes are consumed if the
    /// future is dropped while pending, so a cancelled fill leaves
    /// `inbuf` intact.
    async fn fill_inbuf(&mut self, want: usize) -> Result<(), TransportError> {
        let need = want.saturating_sub(self.stage.inbuf.len());
        let mut scratch = [0u8; 8192];
        let take = need.min(scratch.len());
        let n = self
            .stream
            .read(&mut scratch[..take])
            .await
            .map_err(|e| TransportError::Io(format!("packet read failed: {e}")))?;
        if n == 0 {
            return Err(TransportError::Io("peer closed connection".into()));
        }
        self.stage.inbuf.extend_from_slice(&scratch[..n]);
        Ok(())
    }

    /// Writes one sealed packet. Delegates to the inherited
    /// [`Self::write_sealed`]; only ever called **after** a `select!`
    /// returns, never inside one, so it is never cancelled.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] if sealing or writing fails.
    pub(crate) async fn write_packet(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        // Re-key accounting (ADR-0026): outbound payload bytes under this key.
        self.stage.rekey.bytes_tx = self
            .stage
            .rekey
            .bytes_tx
            .saturating_add(payload.len() as u64);
        self.write_sealed(payload).await
    }

    /// The authenticated key fingerprint, for `exec.*` audit events.
    pub(crate) fn identity(&self) -> &str {
        &self.stage.identity
    }

    /// Sends an encrypted `SSH_MSG_DISCONNECT` with `PROTOCOL_ERROR`
    /// (code 2) and consumes the rejection reason. Used by the channel
    /// driver to fail closed on a malformed or unknown-channel frame.
    pub(crate) async fn protocol_disconnect(&mut self, reason: &'static str) -> TransportError {
        let rejection = protocol_error(reason);
        warn!(
            reason = rejection.reason,
            disconnect_code = rejection.disconnect_code,
            "channel protocol violation"
        );
        if let Err(e) = self.write_sealed(&disconnect_payload(&rejection)).await {
            debug!(error = %e, "disconnect write failed");
        }
        TransportError::Rejected(rejection.reason)
    }

    // ---- re-keying (ADR-0026) ----

    /// A re-key handshake is in progress.
    pub(crate) const fn rekey_active(&self) -> bool {
        !matches!(self.stage.rekey.phase, RekeyPhase::Idle)
    }

    /// The session is settled and a threshold has been crossed, so the
    /// server should initiate a re-key.
    pub(crate) fn rekey_due(&self) -> bool {
        matches!(self.stage.rekey.phase, RekeyPhase::Idle)
            && rekey_due(
                self.stage.rekey.bytes_rx,
                self.stage.rekey.bytes_tx,
                self.stage.rekey.last_kex.elapsed(),
                &self.stage.rekey.thresholds,
            )
    }

    /// While a re-key is active, the instant it must finish by.
    pub(crate) fn rekey_deadline(&self) -> Option<Instant> {
        self.rekey_active()
            .then(|| self.stage.rekey.started + self.stage.rekey.thresholds.completion_deadline)
    }

    /// While idle, the instant the interval trigger fires (so a quiet
    /// connection still re-keys on schedule).
    pub(crate) fn rekey_wake_at(&self) -> Option<Instant> {
        matches!(self.stage.rekey.phase, RekeyPhase::Idle)
            .then(|| self.stage.rekey.last_kex + self.stage.rekey.thresholds.max_interval)
    }

    /// Server-initiated re-key: send our KEXINIT and enter `SentKexInit`.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] if building or writing the KEXINIT fails.
    pub(crate) async fn begin_rekey(&mut self) -> Result<(), TransportError> {
        let i_s = kex::build_rekey_kexinit()
            .map_err(|e| TransportError::Io(format!("rekey kexinit build failed: {e}")))?;
        self.write_packet(&i_s).await?;
        self.stage.rekey.started = Instant::now();
        self.stage.rekey.initiator = "server";
        self.stage.rekey.trigger =
            if self.stage.rekey.last_kex.elapsed() >= self.stage.rekey.thresholds.max_interval {
                "time"
            } else {
                "bytes"
            };
        self.stage.rekey.phase = RekeyPhase::SentKexInit { i_s };
        Ok(())
    }

    /// Feeds one inbound packet to the re-key sub-state machine (RFC 4253
    /// §9). Total and fail-closed: only the message expected in the current
    /// phase advances it; anything else past the peer's KEXINIT terminates
    /// the connection.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rejected`] on a protocol/negotiation violation
    /// (DISCONNECT already sent); [`TransportError::Io`] on a write failure.
    pub(crate) async fn step_rekey(&mut self, payload: &[u8]) -> Result<RekeyStep, TransportError> {
        let msg = payload.first().copied().unwrap_or(0);
        let phase = std::mem::replace(&mut self.stage.rekey.phase, RekeyPhase::Idle);
        match (phase, msg) {
            // Client-initiated re-key (we were idle). RFC 4253 §9 lets a
            // peer re-key whenever it likes (e.g. a low client `RekeyLimit`,
            // which can fire sub-second); the only abuse bound is the
            // one-re-key-at-a-time the phase machine already enforces — each
            // re-key is a full handshake, so a flood costs the peer too.
            (RekeyPhase::Idle, SSH_MSG_KEXINIT) => {
                self.stage.rekey.started = Instant::now();
                self.stage.rekey.initiator = "peer";
                self.stage.rekey.trigger = "peer";
                let i_s = kex::build_rekey_kexinit()
                    .map_err(|e| TransportError::Io(format!("rekey kexinit build failed: {e}")))?;
                self.write_packet(&i_s).await?;
                let negotiated = self.negotiate_rekey(payload).await?;
                self.stage.rekey.phase = RekeyPhase::AwaitHybridInit {
                    i_c: payload.to_vec(),
                    i_s,
                    skip_guessed: negotiated.skip_guessed_packet,
                    negotiated,
                };
                Ok(RekeyStep::Continued)
            }
            // Peer's KEXINIT in response to ours (or simultaneous).
            (RekeyPhase::SentKexInit { i_s }, SSH_MSG_KEXINIT) => {
                let negotiated = self.negotiate_rekey(payload).await?;
                self.stage.rekey.phase = RekeyPhase::AwaitHybridInit {
                    i_c: payload.to_vec(),
                    i_s,
                    skip_guessed: negotiated.skip_guessed_packet,
                    negotiated,
                };
                Ok(RekeyStep::Continued)
            }
            // We've sent our KEXINIT but the peer hasn't yet; it may still
            // send channel data (RFC 4253 §9: we MAY receive higher-layer
            // messages until we send NEWKEYS). Hand it to the channel layer.
            (phase @ RekeyPhase::SentKexInit { .. }, _) => {
                self.stage.rekey.phase = phase;
                Ok(RekeyStep::PassToChannel)
            }
            // The guessed/optimistic KEX packet (rare); drop it.
            (
                RekeyPhase::AwaitHybridInit {
                    i_c,
                    i_s,
                    negotiated,
                    skip_guessed: true,
                },
                _,
            ) => {
                self.stage.rekey.phase = RekeyPhase::AwaitHybridInit {
                    i_c,
                    i_s,
                    negotiated,
                    skip_guessed: false,
                };
                Ok(RekeyStep::Continued)
            }
            (
                RekeyPhase::AwaitHybridInit {
                    i_c,
                    i_s,
                    negotiated,
                    skip_guessed: false,
                },
                SSH_MSG_KEX_HYBRID_INIT,
            ) => {
                self.complete_rekey_reply(payload, &i_c, &i_s, &negotiated)
                    .await
            }
            // Peer's NEWKEYS: install the staged receive cipher; done.
            (RekeyPhase::AwaitNewKeys { new_rx }, SSH_MSG_NEWKEYS) => {
                if payload != [SSH_MSG_NEWKEYS] {
                    return Err(self.protocol_disconnect("expected-newkeys").await);
                }
                self.stage.rx = new_rx;
                self.seq_rx = 0;
                let seconds = self.stage.rekey.last_kex.elapsed().as_secs();
                info!(
                    target: "audit",
                    kex_algorithm = kex::KEX_ALGORITHM,
                    host_key_algorithm = kex::HOST_KEY_LIST,
                    initiator = self.stage.rekey.initiator,
                    trigger = self.stage.rekey.trigger,
                    bytes_rx = self.stage.rekey.bytes_rx,
                    bytes_tx = self.stage.rekey.bytes_tx,
                    seconds,
                    "rekey.completed"
                );
                self.stage.rekey.bytes_rx = 0;
                self.stage.rekey.bytes_tx = 0;
                self.stage.rekey.last_kex = Instant::now();
                self.stage.rekey.phase = RekeyPhase::Idle;
                Ok(RekeyStep::Completed)
            }
            // Anything else once we are past the peer's KEXINIT is illegal.
            _ => Err(self.protocol_disconnect("unexpected-during-rekey").await),
        }
    }

    /// Parses + negotiates a peer re-key KEXINIT; rejects (code 3) on a bad
    /// offer, protocol-errors (code 2) on a malformed one.
    async fn negotiate_rekey(&mut self, payload: &[u8]) -> Result<Negotiated, TransportError> {
        match kex::parse_kexinit(payload).and_then(|peer| kex::negotiate(&peer, false)) {
            Ok(n) => Ok(n),
            Err(KexError::Rejected(r)) => Err(self.rekey_reject(r).await),
            Err(KexError::Wire(_)) => {
                Err(self.protocol_disconnect("malformed-rekey-kexinit").await)
            }
        }
    }

    /// Runs the hybrid exchange for a re-key, sends the signed
    /// `HYBRID_REPLY` and our `NEWKEYS`, installs the new send cipher, and
    /// stages the receive cipher in `AwaitNewKeys`.
    async fn complete_rekey_reply(
        &mut self,
        init_payload: &[u8],
        i_c: &[u8],
        i_s: &[u8],
        negotiated: &Negotiated,
    ) -> Result<RekeyStep, TransportError> {
        let mut r = Reader::new(init_payload);
        let _ = r.byte();
        let Ok(client_init) = r
            .string(kex::CLIENT_INIT_LEN)
            .and_then(|ci| r.finish().map(|()| ci))
        else {
            return Err(self.protocol_disconnect("malformed-hybrid-init").await);
        };
        let outcome = match kex::hybrid_exchange(client_init) {
            Ok(o) => o,
            Err(KexError::Rejected(rej)) => return Err(self.rekey_reject(rej).await),
            Err(KexError::Wire(_)) => {
                return Err(self.protocol_disconnect("malformed-hybrid-init").await);
            }
        };
        let host_key_blob = self.stage.host_key.public_key_blob();
        let h_r = Zeroizing::new(kex::exchange_hash(&ExchangeHashInputs {
            client_id: &self.stage.client_id,
            server_id: wire::SERVER_ID.as_bytes(),
            client_kexinit: i_c,
            server_kexinit: i_s,
            host_key_blob: &host_key_blob,
            client_init,
            server_reply: &outcome.server_reply,
            shared_secret: &outcome.shared_secret,
        }));
        let signature = self.stage.host_key.sign(h_r.as_ref());

        // Derive the new pair with the ORIGINAL session id and the NEW H_r.
        let (new_rx, new_tx) = derive_cipher_pair(
            &outcome.shared_secret,
            &h_r,
            &self.stage.session_id,
            &negotiated.cipher_c2s,
            &negotiated.cipher_s2c,
        )?;

        let mut reply = Writer::new();
        reply.put_byte(kex::SSH_MSG_KEX_HYBRID_REPLY);
        reply.put_string(&host_key_blob);
        reply.put_string(&outcome.server_reply);
        reply.put_string(&signature);
        self.write_packet(&reply.into_bytes()).await?;

        // Send NEWKEYS under the OLD send cipher, then switch tx (strict-kex
        // resets the send counter on our NEWKEYS).
        self.write_packet(&[SSH_MSG_NEWKEYS]).await?;
        self.stage.tx = new_tx;
        self.seq_tx = 0;

        self.stage.rekey.phase = RekeyPhase::AwaitNewKeys { new_rx };
        Ok(RekeyStep::Continued)
    }

    /// Sends an encrypted `SSH_MSG_DISCONNECT` with `KEY_EXCHANGE_FAILED`
    /// (3) for a re-key negotiation rejection, logging `kex.failed`.
    async fn rekey_reject(&mut self, rejection: Rejection) -> TransportError {
        warn!(
            target: "audit",
            reason = rejection.reason,
            disconnect_code = rejection.disconnect_code,
            "kex.failed"
        );
        if let Err(e) = self.write_sealed(&disconnect_payload(&rejection)).await {
            debug!(error = %e, "disconnect write failed");
        }
        TransportError::Rejected(rejection.reason)
    }

    /// A re-key did not complete within the deadline (ADR-0026).
    pub(crate) async fn rekey_timeout(&mut self) -> TransportError {
        self.rekey_reject(Rejection {
            reason: "rekey-timeout",
            disconnect_code: kex::DISCONNECT_KEY_EXCHANGE_FAILED,
        })
        .await
    }
}

/// Outcome of feeding one packet to [`Expect::step_rekey`].
pub(crate) enum RekeyStep {
    /// The re-key advanced; consume the next packet.
    Continued,
    /// The re-key finished; new keys are installed.
    Completed,
    /// Not a re-key message — the channel layer should handle it (the peer
    /// is still allowed to send channel data until it sends its KEXINIT).
    PassToChannel,
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

/// Derives the RFC 4253 §7.2 key schedule and builds the AEAD cipher
/// pair: `rx` (client→server, keys `C`/`A`), `tx` (server→client, `D`/`B`).
/// `session_id` is the connection's first `H` (invariant for its life);
/// `h` is the current exchange hash — equal to `session_id` on the initial
/// KEX, a fresh `H_r` on a re-key (ADR-0026). Shared by `exchange_newkeys`
/// and the re-key routine.
fn derive_cipher_pair(
    k: &[u8; 32],
    h: &[u8; 32],
    session_id: &[u8; 32],
    c2s: &str,
    s2c: &str,
) -> Result<(PacketCipher, PacketCipher), TransportError> {
    let derive = |letter: u8, len: usize| -> Zeroizing<Vec<u8>> {
        let mut out = kex::derive_key(k, h, letter, session_id, len);
        out.truncate(len);
        out
    };
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
    Ok((rx, tx))
}

/// Whether a re-key is due given the per-direction byte counts and the
/// elapsed time since the last completed exchange (ADR-0026: 1 GiB in
/// either direction, or `max_interval`, whichever first). Pure for unit
/// testing.
fn rekey_due(bytes_rx: u64, bytes_tx: u64, elapsed: Duration, t: &RekeyThresholds) -> bool {
    bytes_rx >= t.max_bytes || bytes_tx >= t.max_bytes || elapsed >= t.max_interval
}

/// Validates the sealed length field and returns the body length (body
/// plus tag), the bound applied **before** any body is allocated or
/// read. Shared by [`Expect::read_sealed`] (`read_exact`) and
/// [`Expect::read_packet`] so the length discipline has a single source.
fn frame_body_len(
    cipher: &PacketCipher,
    seqnr: u32,
    length_bytes: [u8; 4],
) -> Result<usize, TransportError> {
    cipher
        .body_len(seqnr, length_bytes)
        .map_err(|_| TransportError::Rejected("packet-auth-failed"))
}

/// Opens one sealed frame body in place (verify tag, decrypt, strip
/// padding). Shared by the two read paths so the decrypt discipline has
/// a single source — there is no second framing path that could diverge.
fn open_frame(
    cipher: &mut PacketCipher,
    seqnr: u32,
    length_bytes: [u8; 4],
    body: &mut [u8],
) -> Result<Vec<u8>, TransportError> {
    cipher
        .open(seqnr, length_bytes, body)
        .map_err(|_| TransportError::Rejected("packet-auth-failed"))
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

impl SealedRead for Session {
    fn rx(&mut self) -> &mut PacketCipher {
        &mut self.rx
    }
}

impl SealedWrite for Session {
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
        let body_len = frame_body_len(self.stage.rx(), seqnr, length_bytes)?;
        let mut body = vec![0u8; body_len];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| TransportError::Io(format!("packet read failed: {e}")))?;
        let payload = open_frame(self.stage.rx(), seqnr, length_bytes, &mut body)?;
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

#[cfg(test)]
mod tests {
    use super::{RekeyThresholds, rekey_due};
    use std::time::Duration;

    #[test]
    fn rekey_due_thresholds() {
        let t = RekeyThresholds {
            max_bytes: 1000,
            max_interval: Duration::from_hours(1),
            completion_deadline: Duration::from_secs(30),
        };
        // Below every threshold.
        assert!(!rekey_due(500, 500, Duration::from_secs(0), &t));
        // Either byte direction crossing is enough.
        assert!(rekey_due(1000, 0, Duration::from_secs(0), &t));
        assert!(rekey_due(0, 1000, Duration::from_secs(0), &t));
        // The interval alone is enough.
        assert!(rekey_due(0, 0, Duration::from_hours(1), &t));
    }
}
