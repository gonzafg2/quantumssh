//! TCP accept loop and the Phase 1 connection flow (ADR-0022,
//! ADR-0024).
//!
//! Connections are served **sequentially** in the spawn-and-join
//! shape ADR-0022 fixes, each bounded by the handshake budget. The M2
//! flow: version exchange (RFC 4253 §4.2) → KEXINIT negotiation
//! (ADR-0021) → hybrid `mlkem768x25519-sha256` exchange → NEWKEYS.
//! The encrypted transport (M3) picks up immediately after NEWKEYS;
//! until it lands the server closes there, having completed the full
//! post-quantum handshake.
//!
//! Strict-kex posture (ADR-0021): during this initial key exchange
//! any unexpected message — including `SSH_MSG_IGNORE`/`DEBUG`, or a
//! first packet that is not KEXINIT — terminates the connection.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::host_key::HostKey;
use crate::kex::{
    self, ExchangeHashInputs, KexError, Rejection, SSH_MSG_DISCONNECT, SSH_MSG_KEX_HYBRID_INIT,
    SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS,
};
use crate::wire::{self, Reader, WireError, Writer};

/// Server configuration assembled by the binary from its CLI.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the TCP listener binds to.
    pub listen: SocketAddr,
    /// Budget from TCP accept to handshake completion (ADR-0022:
    /// 30 seconds by default, configurable via `--handshake-timeout`).
    pub handshake_timeout: Duration,
    /// The Ed25519 host key (ADR-0021: `ssh-ed25519` only).
    pub host_key: Arc<HostKey>,
}

/// A bound, not-yet-serving server.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    handshake_timeout: Duration,
    host_key: Arc<HostKey>,
}

impl Server {
    /// Binds the TCP listener and emits the ADR-0024 `server.started`
    /// event — schema-complete now that a host key exists.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the address cannot be
    /// bound (in use, permission denied, …).
    pub async fn bind(config: &Config) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        let listen_addr = listener.local_addr()?;
        info!(
            listen_addr = %listen_addr,
            host_key_fingerprint = %config.host_key.fingerprint_sha256(),
            "server.started"
        );
        Ok(Self {
            listener,
            handshake_timeout: config.handshake_timeout,
            host_key: Arc::clone(&config.host_key),
        })
    }

    /// The address the listener is actually bound to.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the socket's local address
    /// cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Runs the accept loop until the listener fails.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when accepting a connection
    /// fails at the listener level.
    pub async fn serve(self) -> io::Result<()> {
        let budget = self.handshake_timeout;
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let host_key = Arc::clone(&self.host_key);
            let span = info_span!("connection", peer_addr = %peer_addr);
            let connection = async move {
                info!("connection.accepted");
                if tokio::time::timeout(budget, handle(stream, host_key))
                    .await
                    .is_err()
                {
                    warn!(reason = "handshake-timeout", "connection.closed");
                }
            };
            if let Err(join_err) = tokio::spawn(connection.instrument(span)).await {
                warn!(peer_addr = %peer_addr, reason = %join_err, "connection.closed");
            }
        }
    }
}

/// Why a connection ended; mapped to the `connection.closed` reason.
enum CloseReason {
    /// Handshake completed through NEWKEYS; the encrypted transport
    /// (M3) is not implemented yet.
    KexComplete,
    /// The peer was rejected (already logged as `kex.failed` or an
    /// identification failure).
    Rejected(String),
    /// I/O failed mid-handshake.
    Io(String),
}

/// Handles one connection within the handshake budget.
async fn handle(mut stream: TcpStream, host_key: Arc<HostKey>) {
    let reason = match run_handshake(&mut stream, &host_key).await {
        Ok(()) => CloseReason::KexComplete,
        Err(r) => r,
    };
    if let Err(e) = stream.shutdown().await {
        debug!(error = %e, "tcp shutdown failed");
    }
    match reason {
        CloseReason::KexComplete => {
            info!(reason = "kex-complete", "connection.closed");
        }
        CloseReason::Rejected(r) => {
            info!(reason = %r, "connection.closed");
        }
        CloseReason::Io(e) => {
            info!(reason = %e, "connection.closed");
        }
    }
}

/// The M2 handshake: version exchange, KEXINIT negotiation, hybrid
/// exchange, NEWKEYS.
async fn run_handshake(stream: &mut TcpStream, host_key: &HostKey) -> Result<(), CloseReason> {
    let peer_id_line = version_exchange(stream).await?;

    // --- KEXINIT exchange (ADR-0021) ---
    let our_kexinit =
        kex::build_kexinit().map_err(|e| CloseReason::Io(format!("kexinit build failed: {e}")))?;
    write_packet(stream, &our_kexinit)
        .await
        .map_err(|e| CloseReason::Io(format!("kexinit write failed: {e}")))?;

    let peer_kexinit_payload = read_packet(stream).await.map_err(io_or_rejected)?;
    // Strict-kex: the first packet must be KEXINIT — anything else,
    // SSH_MSG_IGNORE included, terminates the connection.
    if peer_kexinit_payload.first() != Some(&SSH_MSG_KEXINIT) {
        return Err(protocol_reject(stream, "first-packet-not-kexinit").await);
    }

    let negotiated = match kex::parse_kexinit(&peer_kexinit_payload)
        .and_then(|peer| kex::negotiate(&peer, true))
    {
        Ok(n) => n,
        Err(KexError::Rejected(r)) => return Err(reject(stream, &r).await),
        Err(KexError::Wire(e)) => {
            return Err(protocol_reject(stream, "malformed-kexinit")
                .await
                .tap_debug(&e));
        }
    };

    // Wrong guess from a first_kex_packet_follows peer: silently skip
    // exactly one KEX packet (RFC 4253 §7.1; ADR-0021).
    if negotiated.skip_guessed_packet {
        let _skipped = read_packet(stream).await.map_err(io_or_rejected)?;
        debug!("skipped wrong-guess KEX packet");
    }

    // --- Hybrid exchange (draft-ietf-sshm-mlkem-hybrid-kex) ---
    let client_init = read_hybrid_init(stream).await?;
    let outcome = match kex::hybrid_exchange(&client_init) {
        Ok(o) => o,
        Err(KexError::Rejected(r)) => return Err(reject(stream, &r).await),
        Err(KexError::Wire(_)) => {
            return Err(protocol_reject(stream, "malformed-hybrid-init").await);
        }
    };

    // --- Exchange hash, signature, reply ---
    let host_key_blob = host_key.public_key_blob();
    let hash = kex::exchange_hash(&ExchangeHashInputs {
        client_id: &peer_id_line,
        server_id: wire::SERVER_ID.as_bytes(),
        client_kexinit: &peer_kexinit_payload,
        server_kexinit: &our_kexinit,
        host_key_blob: &host_key_blob,
        client_init: &client_init,
        server_reply: &outcome.server_reply,
        shared_secret: &outcome.shared_secret,
    });
    let signature = host_key.sign(&hash);

    let mut reply = Writer::new();
    reply.put_byte(kex::SSH_MSG_KEX_HYBRID_REPLY);
    reply.put_string(&host_key_blob);
    reply.put_string(&outcome.server_reply);
    reply.put_string(&signature);
    write_packet(stream, &reply.into_bytes())
        .await
        .map_err(|e| CloseReason::Io(format!("hybrid reply write failed: {e}")))?;

    // --- NEWKEYS (RFC 4253 §7.3) ---
    write_packet(stream, &[SSH_MSG_NEWKEYS])
        .await
        .map_err(|e| CloseReason::Io(format!("newkeys write failed: {e}")))?;
    let peer_newkeys = read_packet(stream).await.map_err(io_or_rejected)?;
    if peer_newkeys.as_slice() != [SSH_MSG_NEWKEYS] {
        return Err(protocol_reject(stream, "expected-newkeys").await);
    }

    info!(
        kex_algorithm = negotiated.kex_algorithm,
        host_key_algorithm = negotiated.host_key_algorithm,
        "kex.completed"
    );
    // From this point every byte is encrypted (and, with strict-kex,
    // both sequence numbers reset to zero). The AEAD transport — and
    // the EXT_INFO send the negotiation may have enabled — is M3;
    // the handshake itself is complete.
    debug!(
        cipher_c2s = %negotiated.cipher_c2s,
        cipher_s2c = %negotiated.cipher_s2c,
        ext_info = negotiated.ext_info,
        "negotiated parameters (encrypted transport lands in M3)"
    );
    Ok(())
}

/// Version exchange (RFC 4253 §4.2): writes our identification line,
/// reads and validates the peer's, returning it raw (without CRLF) for
/// the exchange hash.
async fn version_exchange(stream: &mut TcpStream) -> Result<Vec<u8>, CloseReason> {
    let mut our_id_line = Vec::with_capacity(64);
    our_id_line.extend_from_slice(wire::SERVER_ID.as_bytes());
    our_id_line.extend_from_slice(b"\r\n");
    stream
        .write_all(&our_id_line)
        .await
        .map_err(|e| CloseReason::Io(format!("identification write failed: {e}")))?;

    let peer_id_line = read_id_line(stream)
        .await
        .map_err(|e| CloseReason::Rejected(format!("identification rejected: {e}")))?;
    let peer_id = wire::parse_peer_id(&peer_id_line)
        .map_err(|e| CloseReason::Rejected(format!("identification rejected: {e}")))?;
    debug!(peer_software = %peer_id.softwareversion, "peer identification accepted");
    Ok(peer_id_line)
}

/// Reads the `SSH_MSG_KEX_HYBRID_INIT` packet and returns the client's
/// `C_INIT` blob, rejecting anything malformed with a protocol-error
/// disconnect.
async fn read_hybrid_init(stream: &mut TcpStream) -> Result<Vec<u8>, CloseReason> {
    let init_payload = read_packet(stream).await.map_err(io_or_rejected)?;
    let mut r = Reader::new(&init_payload);
    if r.byte().unwrap_or(0) != SSH_MSG_KEX_HYBRID_INIT {
        return Err(protocol_reject(stream, "expected-hybrid-init").await);
    }
    let Ok(client_init) = r
        .string(kex::CLIENT_INIT_LEN)
        .and_then(|ci| r.finish().map(|()| ci))
    else {
        return Err(protocol_reject(stream, "malformed-hybrid-init").await);
    };
    Ok(client_init.to_vec())
}

/// Rejects with `SSH_DISCONNECT_PROTOCOL_ERROR` and the given reason.
async fn protocol_reject<W: AsyncWrite + Unpin>(
    stream: &mut W,
    reason: &'static str,
) -> CloseReason {
    reject(
        stream,
        &Rejection {
            reason,
            disconnect_code: kex::DISCONNECT_PROTOCOL_ERROR,
        },
    )
    .await
}

/// Sends `SSH_MSG_DISCONNECT`, emits the `kex.failed` audit event,
/// and produces the close reason.
async fn reject<W: AsyncWrite + Unpin>(stream: &mut W, rejection: &Rejection) -> CloseReason {
    warn!(
        target: "audit",
        reason = rejection.reason,
        disconnect_code = rejection.disconnect_code,
        "kex.failed"
    );
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_DISCONNECT);
    w.put_uint32(rejection.disconnect_code);
    w.put_string(rejection.reason.as_bytes());
    w.put_string(b""); // language tag
    if let Err(e) = write_packet(stream, &w.into_bytes()).await {
        debug!(error = %e, "disconnect write failed");
    }
    CloseReason::Rejected(format!("kex failed: {}", rejection.reason))
}

impl CloseReason {
    /// Attaches a wire error to the debug log without changing the
    /// close reason.
    fn tap_debug(self, e: &WireError) -> Self {
        debug!(error = %e, "wire-level parse failure");
        self
    }
}

fn io_or_rejected(e: PacketReadError) -> CloseReason {
    match e {
        PacketReadError::Io(e) => CloseReason::Io(format!("packet read failed: {e}")),
        PacketReadError::Wire(e) => CloseReason::Rejected(format!("malformed packet: {e}")),
    }
}

/// Errors reading one framed packet.
enum PacketReadError {
    Io(io::Error),
    Wire(WireError),
}

/// Reads one unencrypted Binary Packet Protocol packet, returning its
/// payload. The peer-declared length is validated against the hard
/// cap **before** the body is read or allocated.
async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, PacketReadError> {
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .map_err(PacketReadError::Io)?;
    let declared = u32::from_be_bytes(len_bytes);
    let body_len = wire::validate_packet_length(declared).map_err(PacketReadError::Wire)?;
    let mut body = vec![0u8; body_len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(PacketReadError::Io)?;
    let payload = wire::decode_packet_body(&body).map_err(PacketReadError::Wire)?;
    Ok(payload.to_vec())
}

/// Writes one unencrypted packet around `payload`.
async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let packet = wire::encode_packet(payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    writer.write_all(&packet).await
}

/// Reads the peer's identification line (one line, byte-bounded at
/// [`wire::MAX_ID_LINE`]), returning the raw line without CRLF.
async fn read_id_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, WireError> {
    let mut line = Vec::with_capacity(64);
    loop {
        if line.len() >= wire::MAX_ID_LINE {
            return Err(WireError::BadIdentification);
        }
        let byte = reader
            .read_u8()
            .await
            .map_err(|_| WireError::BadIdentification)?;
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
