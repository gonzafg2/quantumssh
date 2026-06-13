//! TCP accept loop and the Phase 1 connection flow (ADR-0022,
//! ADR-0024).
//!
//! Connections are served **sequentially** in the spawn-and-join
//! shape ADR-0022 fixes, each bounded by the handshake budget. The
//! connection itself is driven through the transport type-state
//! machine ([`crate::transport`]): version exchange → KEXINIT →
//! hybrid `mlkem768x25519-sha256` exchange → NEWKEYS → encrypted
//! service request. `ssh-userauth` lands in M4; until then every
//! requested service is denied with
//! `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE` (RFC 4253 §10) — over the
//! fully established AEAD transport.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::host_key::HostKey;
use crate::transport::{self, TransportError};

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

/// Handles one connection within the handshake budget, driving the
/// transport machine stage by stage.
async fn handle(mut stream: TcpStream, host_key: Arc<HostKey>) {
    let reason = match run_connection(&mut stream, &host_key).await {
        // Infallible: in M3 every connection ends in a denial — the
        // type records it, no unreachable!/panic needed.
        Ok(never) => match never {},
        Err(TransportError::Rejected(reason)) => format!("rejected: {reason}"),
        Err(TransportError::Io(e)) => e,
    };
    if let Err(e) = stream.shutdown().await {
        debug!(error = %e, "tcp shutdown failed");
    }
    info!(reason = %reason, "connection.closed");
}

/// One connection through the type-state machine. The `Infallible`
/// success type records that every M3 path ends in an error: the
/// final stage denies the requested service because `ssh-userauth`
/// arrives with the auth milestone (M4).
async fn run_connection(
    stream: &mut TcpStream,
    host_key: &HostKey,
) -> Result<Infallible, TransportError> {
    let t = transport::version_exchange(stream).await?;
    let t = t.exchange_kexinit().await?;
    let t = t.run_hybrid(host_key).await?;
    let (negotiated, t) = t.exchange_newkeys().await?;
    info!(
        kex_algorithm = negotiated.kex_algorithm,
        host_key_algorithm = negotiated.host_key_algorithm,
        "kex.completed"
    );
    debug!(
        cipher_c2s = %negotiated.cipher_c2s,
        cipher_s2c = %negotiated.cipher_s2c,
        ext_info = negotiated.ext_info,
        "encrypted transport established"
    );

    let (service, responder) = t.read_service_request().await?;
    info!(service = %service, "service requested (ssh-userauth lands in M4)");
    Err(responder.deny().await)
}
