//! TCP accept loop and the Phase 1 connection flow (ADR-0022,
//! ADR-0024).
//!
//! Connections are served **sequentially** in the spawn-and-join
//! shape ADR-0022 fixes, each bounded by the handshake budget. The
//! connection itself is driven through the transport type-state
//! machine ([`crate::transport`]): version exchange → KEXINIT →
//! hybrid `mlkem768x25519-sha256` exchange → NEWKEYS → encrypted
//! service request → `ssh-userauth` (publickey Ed25519, M4) → the
//! channel layer: one `session` channel, one `exec`, clean close (M5).
//! Unknown services are denied. The handshake budget bounds everything
//! up to authentication; the channel phase runs un-timed (ADR-0023).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::auth::AuthorizedKeys;
use crate::host_key::HostKey;
use crate::transport::{self, RekeyThresholds, TransportError};

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
    /// The parsed `authorized_keys` file (M4: publickey auth).
    pub authorized_keys: Arc<AuthorizedKeys>,
    /// Re-keying thresholds (ADR-0026: 1 GiB / 1 hour by default).
    pub rekey: RekeyThresholds,
}

/// A bound, not-yet-serving server.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    handshake_timeout: Duration,
    host_key: Arc<HostKey>,
    authorized_keys: Arc<AuthorizedKeys>,
    rekey: RekeyThresholds,
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
            authorized_keys: Arc::clone(&config.authorized_keys),
            rekey: config.rekey,
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
        let rekey = self.rekey;
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let host_key = Arc::clone(&self.host_key);
            let authorized_keys = Arc::clone(&self.authorized_keys);
            let span = info_span!("connection", peer_addr = %peer_addr);
            let connection = async move {
                info!("connection.accepted");
                handle(stream, host_key, authorized_keys, budget, rekey).await;
            };
            if let Err(join_err) = tokio::spawn(connection.instrument(span)).await {
                warn!(peer_addr = %peer_addr, reason = %join_err, "connection.closed");
            }
        }
    }
}

/// Handles one connection: the handshake under the budget, then the
/// channel phase un-timed.
async fn handle(
    mut stream: TcpStream,
    host_key: Arc<HostKey>,
    authorized_keys: Arc<AuthorizedKeys>,
    budget: Duration,
    rekey: RekeyThresholds,
) {
    let reason = match run_connection(&mut stream, host_key, &authorized_keys, budget, rekey).await
    {
        Ok(()) => "session closed".to_string(),
        Err(TransportError::Rejected(reason)) => format!("rejected: {reason}"),
        Err(TransportError::Io(e)) => e,
    };
    if let Err(e) = stream.shutdown().await {
        debug!(error = %e, "tcp shutdown failed");
    }
    info!(reason = %reason, "connection.closed");
}

/// One connection through the type-state machine. The handshake (up to
/// and including authentication) runs under `budget`; once a key
/// authenticates, the channel phase ([`Expect::serve`]) runs un-timed —
/// a command may legitimately take arbitrarily long (ADR-0023). Returns
/// `Ok(())` on a clean session close.
async fn run_connection(
    stream: &mut TcpStream,
    host_key: Arc<HostKey>,
    authorized_keys: &AuthorizedKeys,
    budget: Duration,
    rekey: RekeyThresholds,
) -> Result<(), TransportError> {
    let auth_phase = async {
        let t = transport::version_exchange(stream).await?;
        let t = t.exchange_kexinit().await?;
        let t = t.run_hybrid(&host_key).await?;
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
        if service.as_str() == "ssh-userauth" {
            let t = responder.accept().await?;
            Ok::<_, TransportError>(Some(t.authenticate(authorized_keys).await?))
        } else {
            info!(service = %service, "service denied (only ssh-userauth supported)");
            Err(responder.deny().await)
        }
    };

    let authed = tokio::time::timeout(budget, auth_phase)
        .await
        .map_err(|_| TransportError::Rejected("handshake-timeout"))??;

    match authed {
        // Authentication succeeded: run the channel layer un-timed.
        Some(t) => t.serve(host_key, rekey).await,
        // `responder.deny()` already returned `Err`, so this arm is
        // unreachable; kept total for the type.
        None => Ok(()),
    }
}
