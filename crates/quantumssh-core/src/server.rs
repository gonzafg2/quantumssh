//! TCP accept loop and server composition (ADR-0022, ADR-0024).
//!
//! Phase 1 serves connections **sequentially** in the spawn-and-join
//! shape ADR-0022 fixes: each connection is `tokio::spawn`ed and the
//! `JoinHandle` is awaited immediately. Effective concurrency stays at
//! one, the per-connection future is `Send`-checked by the compiler
//! from the first crate, and a panicking handler surfaces as a logged
//! `JoinError` instead of taking the server down.
//!
//! Every connection runs under the handshake budget ADR-0022 fixes
//! (default 30 seconds, configurable): a connection that does not
//! complete within it is closed with `reason = "handshake-timeout"`.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

/// Server configuration assembled by the binary from its CLI.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the TCP listener binds to.
    pub listen: SocketAddr,
    /// Budget from TCP accept to handshake completion (ADR-0022:
    /// 30 seconds by default, configurable via `--handshake-timeout`).
    pub handshake_timeout: Duration,
}

/// A bound, not-yet-serving server.
///
/// Binding is separated from serving so callers (the binary, but also
/// integration tests) can bind to an ephemeral port (`:0`), read the
/// actual address with [`Server::local_addr`], and only then start the
/// accept loop.
///
/// Note: the ADR-0024 `server.started` event is **not** emitted yet —
/// its schema mandates `host_key_fingerprint`, which cannot exist
/// before the host-key milestone. Per the schema-complete-or-nothing
/// posture, the event lands together with host-key loading.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    handshake_timeout: Duration,
}

impl Server {
    /// Binds the TCP listener.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the address cannot be
    /// bound (in use, permission denied, …).
    pub async fn bind(config: &Config) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            handshake_timeout: config.handshake_timeout,
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
    /// Per ADR-0022 the loop is sequential: one connection is handled
    /// to completion before the next is accepted. Each connection runs
    /// inside a `connection` span carrying `peer_addr` (ADR-0024), is
    /// spawned (enforcing `Send` on the per-connection future), is
    /// joined immediately, and is bounded by the handshake budget. A
    /// `JoinError` — a panicked handler — is logged as
    /// `connection.closed` with the panic as reason; it never
    /// terminates the accept loop.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when accepting a connection
    /// fails at the listener level.
    pub async fn serve(self) -> io::Result<()> {
        let budget = self.handshake_timeout;
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let span = info_span!("connection", peer_addr = %peer_addr);
            let connection = async move {
                info!("connection.accepted");
                if tokio::time::timeout(budget, handle(stream)).await.is_err() {
                    warn!(reason = "handshake-timeout", "connection.closed");
                }
            };
            if let Err(join_err) = tokio::spawn(connection.instrument(span)).await {
                warn!(peer_addr = %peer_addr, reason = %join_err, "connection.closed");
            }
        }
    }
}

/// Handles one connection within the handshake budget.
///
/// M0 behaviour: the connection is shut down cleanly (explicit FIN)
/// and its closure logged. The SSH protocol (version exchange onwards)
/// is introduced in the next milestone; until then the server's
/// observable contract is "accepts TCP, closes immediately", which is
/// exactly what the integration test asserts.
async fn handle(mut stream: TcpStream) {
    if let Err(e) = stream.shutdown().await {
        debug!(error = %e, "tcp shutdown failed");
    }
    info!(reason = "closed", "connection.closed");
}
