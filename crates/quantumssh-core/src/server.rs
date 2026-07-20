//! TCP accept loop and the connection flow — concurrent from Phase 2
//! (ADR-0028, extending ADR-0022; audit events per ADR-0024).
//!
//! Connections are served **concurrently**: the accept loop
//! `tokio::select!`s over `accept()`, task reaping
//! (`JoinSet::join_next`), and the shutdown broadcast. Before a
//! connection is spawned it passes the four ADR-0028 admission checks
//! ([`crate::admission`]); a refused connection is closed pre-banner
//! and logged as `connection.refused`. Each admitted connection is
//! driven through the transport type-state machine
//! ([`crate::transport`]): version exchange → KEXINIT → hybrid
//! `mlkem768x25519-sha256` exchange → NEWKEYS → encrypted service
//! request → `ssh-userauth` (publickey Ed25519) → the channel layer.
//! The handshake budget bounds everything up to authentication; the
//! channel phase runs un-timed (ADR-0023) except under shutdown.
//!
//! **Graceful shutdown** (ADR-0028): the broadcast carries the drain
//! deadline. A pre-auth connection disconnects immediately; a
//! connection in the channel phase lets its exec run until the
//! deadline, then its future is cancelled — the ADR-0023 backstops
//! (the owned-`Child` kill in [`crate::exec`] and the `exec.finished`
//! drop-guard in the channel driver) fire on the drop. The loop aborts
//! only the tasks still alive a small grace past the deadline, and a
//! second signal skips the remaining deadline entirely.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{Instrument, Span, debug, info, info_span, warn};

use crate::admission::{Admission, ConnectionGuard, Limits};
use crate::auth::AuthorizedKeys;
use crate::host_key::HostKey;
use crate::transport::{self, RekeyThresholds, TransportError};

/// Cooperative connections cancel themselves at the drain deadline;
/// the loop aborts the remainder this much later, so the abort is the
/// last resort for stuck tasks, not the routine path (ADR-0028).
const ABORT_GRACE: Duration = Duration::from_secs(2);

/// Server configuration assembled by the binary from its CLI and the
/// RFC-0010 config file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the TCP listener binds to.
    pub listen: SocketAddr,
    /// Budget from TCP accept to handshake completion (ADR-0022:
    /// 30 seconds by default, configurable).
    pub handshake_timeout: Duration,
    /// The Ed25519 host key (ADR-0021: `ssh-ed25519` only).
    pub host_key: Arc<HostKey>,
    /// The parsed `authorized_keys` file (publickey auth).
    pub authorized_keys: Arc<AuthorizedKeys>,
    /// Re-keying thresholds (ADR-0026: 1 GiB / 1 hour by default).
    pub rekey: RekeyThresholds,
    /// The ADR-0028 admission caps and per-source rate limit.
    pub limits: Limits,
}

/// A bound, not-yet-serving server.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    handshake_timeout: Duration,
    host_key: Arc<HostKey>,
    authorized_keys: Arc<AuthorizedKeys>,
    rekey: RekeyThresholds,
    limits: Limits,
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
            limits: config.limits,
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

    /// Runs the concurrent accept loop (ADR-0028) until the listener
    /// fails or a shutdown signal drains it.
    ///
    /// `shutdown` is the broadcast the OS-signal listener (or a test)
    /// sends the **drain deadline** on: on the first value the loop
    /// stops accepting and waits for connections to finish
    /// cooperatively, aborting the remainder shortly after the
    /// deadline; a second value skips the remaining deadline. Dropping
    /// every sender simply means no shutdown ever arrives.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when accepting a connection
    /// fails at the listener level. A drained shutdown returns
    /// `Ok(())`.
    pub async fn serve(self, shutdown: broadcast::Sender<Instant>) -> io::Result<()> {
        let budget = self.handshake_timeout;
        let rekey = self.rekey;
        let admission = Admission::new(self.limits);
        let mut tasks: JoinSet<()> = JoinSet::new();
        // Original connection spans, re-entered on JoinError so
        // `connection.closed` inherits `peer_addr` (ADR-0024) without
        // repeating it as an event field.
        let mut connection_spans: HashMap<tokio::task::Id, Span> = HashMap::new();
        let mut loop_rx = shutdown.subscribe();
        // Set on the first shutdown signal: when the remainder is
        // aborted. Accepting stops the moment it is `Some`.
        let mut abort_at: Option<Instant> = None;

        loop {
            tokio::select! {
                accepted = self.listener.accept(), if abort_at.is_none() => {
                    let (stream, peer_addr) = accepted?;
                    let span = info_span!("connection", peer_addr = %peer_addr);
                    match admission.try_admit(peer_addr.ip(), std::time::Instant::now()) {
                        Err(refusal) => {
                            // Closed pre-banner; `connection.refused`
                            // and `connection.accepted` are mutually
                            // exclusive within the span (ADR-0028).
                            let _entered = span.entered();
                            warn!(limit = refusal.as_str(), "connection.refused");
                            drop(stream);
                        }
                        Ok(guard) => {
                            let host_key = Arc::clone(&self.host_key);
                            let authorized_keys = Arc::clone(&self.authorized_keys);
                            let conn_rx = shutdown.subscribe();
                            let connection = async move {
                                info!("connection.accepted");
                                handle(stream, host_key, authorized_keys, budget, rekey, guard, conn_rx)
                                    .await;
                            };
                            let handle = tasks.spawn(connection.instrument(span.clone()));
                            connection_spans.insert(handle.id(), span);
                        }
                    }
                }
                joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    log_join(joined, &mut connection_spans);
                    if abort_at.is_some() && tasks.is_empty() {
                        return Ok(());
                    }
                }
                deadline = next_shutdown(&mut loop_rx) => {
                    if abort_at.is_some() {
                        // Second signal: skip the remaining deadline
                        // (ADR-0028) — abort now.
                        abort_at = Some(Instant::now());
                    } else if tasks.is_empty() {
                        return Ok(());
                    } else {
                        abort_at = Some(deadline + ABORT_GRACE);
                    }
                }
                () = tokio::time::sleep_until(abort_at.unwrap_or_else(Instant::now)),
                    if abort_at.is_some() =>
                {
                    tasks.abort_all();
                    while let Some(joined) = tasks.join_next_with_id().await {
                        log_join(Some(joined), &mut connection_spans);
                    }
                    return Ok(());
                }
            }
        }
    }
}

/// Logs a reaped task that did not close itself: a panic (`JoinError`,
/// with the reason as a structured field — ADR-0028) or an abort at
/// the drain deadline. Normal completions already emitted their own
/// `connection.closed` inside the connection span.
///
/// Re-enters the original `connection` span so `peer_addr` is inherited
/// (ADR-0024); the event itself carries only `reason`, at INFO.
fn log_join(
    joined: Option<Result<(tokio::task::Id, ()), tokio::task::JoinError>>,
    connection_spans: &mut HashMap<tokio::task::Id, Span>,
) {
    match joined {
        Some(Ok((id, ()))) => {
            connection_spans.remove(&id);
        }
        Some(Err(join_err)) => {
            // ADR-0028: abort → reason `shutdown`; panic → JoinError text.
            let reason = if join_err.is_cancelled() {
                "shutdown".to_string()
            } else {
                join_err.to_string()
            };
            match connection_spans.remove(&join_err.id()) {
                Some(span) => {
                    let _entered = span.entered();
                    info!(reason = %reason, "connection.closed");
                }
                // Unreachable when every spawn inserts its span; not an
                // ADR-0024 event — do not invent schema names here.
                None => {
                    warn!(reason = %reason, "join error without connection span");
                }
            }
        }
        None => {}
    }
}

/// Resolves to the next shutdown deadline. `Lagged` skips to the
/// freshest value; a closed channel (every sender dropped — e.g. a
/// test that never drives shutdown) never resolves.
async fn next_shutdown(rx: &mut broadcast::Receiver<Instant>) -> Instant {
    loop {
        match rx.recv().await {
            Ok(deadline) => return deadline,
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
        }
    }
}

/// Handles one connection: the handshake under the budget, the channel
/// phase un-timed — until a shutdown signal bounds what remains
/// (ADR-0028).
async fn handle(
    mut stream: TcpStream,
    host_key: Arc<HostKey>,
    authorized_keys: Arc<AuthorizedKeys>,
    budget: Duration,
    rekey: RekeyThresholds,
    guard: ConnectionGuard,
    mut shutdown: broadcast::Receiver<Instant>,
) {
    // The block scopes the (possibly cancelled) connection future: at
    // its end the `&mut stream` borrow is released and the channel
    // driver's drop-side effects (child kill, owed `exec.finished`)
    // have landed — before the close is logged.
    let result = {
        let conn = run_connection(
            &mut stream,
            host_key,
            &authorized_keys,
            budget,
            rekey,
            &guard,
        );
        tokio::pin!(conn);
        tokio::select! {
            r = &mut conn => r,
            deadline = next_shutdown(&mut shutdown) => {
                if guard.is_authenticated() {
                    // Channel phase: the in-flight exec runs until the
                    // drain deadline. Cancelling the future at the
                    // deadline fires the ADR-0023 backstops on drop —
                    // the owned-`Child` kill and the `exec.finished`
                    // drop-guard — so the audit invariant holds on the
                    // shutdown path (ADR-0028). Phase is a snapshot at
                    // signal receipt.
                    tokio::time::timeout_at(deadline, &mut conn)
                        .await
                        .unwrap_or(Err(TransportError::Rejected("shutdown")))
                } else {
                    // Pre-auth: disconnect immediately (ADR-0028).
                    Err(TransportError::Rejected("shutdown"))
                }
            }
        }
    };
    let reason = match result {
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
/// authenticates — which [`ConnectionGuard::mark_authenticated`]
/// records, ending the half-open span (ADR-0028) — the channel phase
/// ([`Expect::serve`]) runs un-timed: a command may legitimately take
/// arbitrarily long (ADR-0023). Returns `Ok(())` on a clean session
/// close.
async fn run_connection(
    stream: &mut TcpStream,
    host_key: Arc<HostKey>,
    authorized_keys: &AuthorizedKeys,
    budget: Duration,
    rekey: RekeyThresholds,
    guard: &ConnectionGuard,
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
        // Authentication succeeded: the half-open span ends here; run
        // the channel layer un-timed.
        Some(t) => {
            guard.mark_authenticated();
            t.serve(host_key, rekey).await
        }
        // `responder.deny()` already returned `Err`, so this arm is
        // unreachable; kept total for the type.
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};

    #[derive(Clone, Debug)]
    struct Rec {
        level: tracing::Level,
        message: String,
        fields: Vec<(String, String)>,
    }

    /// Records level, message, and structured field name/value pairs.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Rec>>>);

    impl Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &Event<'_>) {
            struct Collector {
                message: Option<String>,
                fields: Vec<(String, String)>,
            }
            impl Visit for Collector {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    let rendered = format!("{value:?}");
                    if field.name() == "message" {
                        self.message = Some(rendered);
                    } else {
                        self.fields.push((field.name().to_string(), rendered));
                    }
                }
                fn record_str(&mut self, field: &Field, value: &str) {
                    if field.name() == "message" {
                        self.message = Some(value.to_string());
                    } else {
                        self.fields
                            .push((field.name().to_string(), value.to_string()));
                    }
                }
            }
            let mut c = Collector {
                message: None,
                fields: Vec::new(),
            };
            event.record(&mut c);
            let message = c.message.unwrap_or_default();
            // `record_debug` quotes the message; strip for stable asserts.
            let message = message
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&message)
                .to_string();
            self.0.lock().expect("capture lock").push(Rec {
                level: *event.metadata().level(),
                message,
                fields: c.fields,
            });
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn field_value<'a>(rec: &'a Rec, name: &str) -> Option<&'a str> {
        rec.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn closed_events(seen: &Mutex<Vec<Rec>>) -> Vec<Rec> {
        seen.lock()
            .expect("capture lock")
            .iter()
            .filter(|r| r.message == "connection.closed")
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn join_panic_emits_connection_closed_at_info_with_reason_only() {
        let mut tasks: JoinSet<()> = JoinSet::new();
        let mut spans = HashMap::new();
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let span = info_span!("connection", peer_addr = %peer);
        let handle = tasks.spawn(
            async {
                panic!("boom");
            }
            .instrument(span.clone()),
        );
        spans.insert(handle.id(), span);
        let joined = tasks.join_next_with_id().await;

        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            log_join(joined, &mut spans);
        });

        let closed = closed_events(&seen);
        assert_eq!(
            closed.len(),
            1,
            "expected one connection.closed: {closed:?}"
        );
        assert_eq!(closed[0].level, tracing::Level::INFO);
        assert!(
            field_value(&closed[0], "reason").is_some(),
            "missing reason: {:?}",
            closed[0].fields
        );
        assert!(
            field_value(&closed[0], "peer_addr").is_none(),
            "peer_addr must live on the span, not the event: {:?}",
            closed[0].fields
        );
    }

    #[tokio::test]
    async fn join_abort_emits_connection_closed_reason_shutdown() {
        let mut tasks: JoinSet<()> = JoinSet::new();
        let mut spans = HashMap::new();
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let span = info_span!("connection", peer_addr = %peer);
        let handle = tasks.spawn(
            async {
                std::future::pending::<()>().await;
            }
            .instrument(span.clone()),
        );
        spans.insert(handle.id(), span);
        tasks.abort_all();
        let joined = tasks.join_next_with_id().await;

        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            log_join(joined, &mut spans);
        });

        let closed = closed_events(&seen);
        assert_eq!(
            closed.len(),
            1,
            "expected one connection.closed: {closed:?}"
        );
        assert_eq!(closed[0].level, tracing::Level::INFO);
        assert_eq!(
            field_value(&closed[0], "reason"),
            Some("shutdown"),
            "ADR-0028 abort reason"
        );
        assert!(
            field_value(&closed[0], "peer_addr").is_none(),
            "peer_addr must live on the span, not the event: {:?}",
            closed[0].fields
        );
    }

    #[tokio::test]
    async fn join_without_span_does_not_emit_connection_closed() {
        let mut tasks: JoinSet<()> = JoinSet::new();
        let mut spans: HashMap<tokio::task::Id, Span> = HashMap::new();
        tasks.spawn(async {
            panic!("orphan");
        });
        let joined = tasks.join_next_with_id().await;

        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            log_join(joined, &mut spans);
        });

        assert!(
            closed_events(&seen).is_empty(),
            "must not emit schema event without a connection span"
        );
        let all = seen.lock().expect("capture lock").clone();
        assert!(
            all.iter()
                .any(|r| r.message == "join error without connection span"),
            "expected diagnostic warn: {all:?}"
        );
    }
}
