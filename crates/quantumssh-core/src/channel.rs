//! The RFC 4254 connection layer, scoped by ADR-0023 to exactly **one
//! `session` channel running one child**, then a clean close. The child is
//! an `exec` or a `shell`, on pipes or, after a `pty-req`, on a
//! pseudo-terminal (ADR-0038).
//!
//! The [`drive`] loop is the single owner of all wire I/O for the
//! post-auth phase. The child process runs under `tokio::process`
//! ([`crate::exec`]); the driver multiplexes inbound packets against the
//! child's stdout/stderr/exit and stdin-consumption acks with a
//! `tokio::select!`, never holding two `&mut` borrows of the wire at
//! once. The inbound read ([`Expect::read_packet`]) is cancel-safe, so a
//! read the `select!` cancels never desyncs the stream.
//!
//! Flow control is real in both directions (ADR-0023): the server never
//! sends past the client's advertised window, and never buffers inbound
//! beyond its own — a peer exceeding it is disconnected, and inbound
//! credit is returned only as the child consumes stdin, so a stalled
//! child backpressures the wire instead of growing a queue.

// This module is private to the crate; its `pub(crate)` items are the
// surface other modules (transport, tests) drive it through. The
// `redundant_pub_crate` lint would have us write `pub`, but `pub(crate)`
// states the intent — nothing here is part of the public API.
#![allow(clippy::redundant_pub_crate)]

use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::info;

use crate::auth::Authenticated;
use crate::exec::{self, ChildChunk, ChildIo, ChildScope, Program};
use crate::launcher;
use crate::pty::{self, PtyPair, Size};
use crate::transport::{Expect, RekeyStep, Session, TransportError};
use crate::wire::{Reader, Writer};

// ---- transport messages that may still appear post-auth ----
/// `SSH_MSG_DISCONNECT` (RFC 4253 §11.1).
const SSH_MSG_DISCONNECT: u8 = 1;
/// `SSH_MSG_IGNORE` (RFC 4253 §11.2) — MUST be accepted at any time.
const SSH_MSG_IGNORE: u8 = 2;
/// `SSH_MSG_UNIMPLEMENTED` (RFC 4253 §11.4).
const SSH_MSG_UNIMPLEMENTED: u8 = 3;
/// `SSH_MSG_DEBUG` (RFC 4253 §11.3) — MUST be allowed at any time.
const SSH_MSG_DEBUG: u8 = 4;
/// `SSH_MSG_KEXINIT` (RFC 4253 §7.1) — a client-initiated re-key (ADR-0026).
const SSH_MSG_KEXINIT: u8 = 20;

// ---- connection-protocol messages (RFC 4254 §4, §5) ----
pub(crate) const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
const SSH_MSG_REQUEST_FAILURE: u8 = 82;
pub(crate) const SSH_MSG_CHANNEL_OPEN: u8 = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub(crate) const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub(crate) const SSH_MSG_CHANNEL_DATA: u8 = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub(crate) const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub(crate) const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub(crate) const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` (RFC 4254 §5.1) — a second
/// `session` open: a type we understand but refuse by policy.
const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
/// `SSH_OPEN_UNKNOWN_CHANNEL_TYPE` (RFC 4254 §5.1) — a non-`session` type.
const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
/// `SSH_EXTENDED_DATA_STDERR` (RFC 4254 §5.2).
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// Phase 1 inbound window (ADR-0023): un-consumed inbound bytes are
/// bounded by this.
pub(crate) const INITIAL_WINDOW: u32 = 2 * 1024 * 1024;
/// Phase 1 max packet payload (ADR-0023).
pub(crate) const MAX_PACKET: u32 = 32 * 1024;
/// Batch inbound credit before sending `WINDOW_ADJUST`, so we do not emit
/// one per data packet.
const CREDIT_BATCH: u32 = 1024 * 1024;
/// Our single channel's id; every inbound frame's recipient must equal it.
const LOCAL_CHANNEL: u32 = 0;
/// Conventional exit status when the child could not be spawned.
const EXIT_SPAWN_FAILED: i32 = 127;
/// Cap on reply-generating connection-protocol messages buffered during a
/// re-key's half-duplex window (RFC 4253 §9) before it is treated as abuse.
const MAX_DEFERRED: usize = 64;

/// Bound on a channel-type name (RFC 4254 §5.1).
const CHANNEL_TYPE_BOUND: usize = 64;
/// Bound on a request-type name (RFC 4254 §5.4).
const REQUEST_TYPE_BOUND: usize = 64;
/// Bound on an `exec` command string — one packet's payload.
const COMMAND_BOUND: usize = MAX_PACKET as usize;
/// Bound on a `subsystem` name (ADR-0041 §1).
const SUBSYSTEM_BOUND: usize = 64;

/// Which child stream a pending output chunk came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stream {
    Stdout,
    Stderr,
}

/// One output chunk in flight to the client, with a cursor so it can be
/// split across several `CHANNEL_DATA`/`EXTENDED_DATA` packets as the
/// window allows.
struct PendingOut {
    kind: Stream,
    buf: Vec<u8>,
    off: usize,
}

impl PendingOut {
    const fn new(kind: Stream, buf: Vec<u8>) -> Self {
        Self { kind, buf, off: 0 }
    }
    const fn remaining(&self) -> usize {
        self.buf.len() - self.off
    }
    const fn is_empty(&self) -> bool {
        self.off >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> &[u8] {
        let slice = &self.buf[self.off..self.off + n];
        self.off += n;
        slice
    }
}

/// The session channel's lifecycle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChannelState {
    /// No channel yet; the next legal message is `CHANNEL_OPEN`.
    BeforeOpen,
    /// Channel open, no `exec` accepted yet.
    Idle,
    /// The `exec`'d child is running.
    Running,
    /// The child exited (or failed/was killed); flushing remaining output.
    Draining,
    /// We sent our `CHANNEL_CLOSE`; awaiting the client's (half-close).
    ServerClosed,
    /// Both `CHANNEL_CLOSE`s exchanged; the connection is done.
    Closed,
}

impl ChannelState {
    const fn may_emit_output(self) -> bool {
        matches!(self, Self::Running | Self::Draining)
    }
}

/// The driver's accounting for the one channel. Owns nothing on the
/// wire — every byte goes through the borrowed [`Expect`].
///
/// The several `bool`s are independent lifecycle latches (client EOF,
/// early close, output drained, …) that do not collapse into a single
/// enum without losing orthogonal state; the `ChannelState` enum carries
/// the primary phase.
#[allow(clippy::struct_excessive_bools)]
struct Driver<'a> {
    /// The connection's children (ADR-0038 §6); the child spawns into it,
    /// and a PTY child through its helper executable (ADR-0038 §5).
    children: &'a ChildScope,
    /// A pair allocated by `pty-req`, waiting for the child that starts
    /// on it.
    pty: Option<PendingPty>,
    /// Who authenticated: the `exec.*` identity fields (ADR-0024,
    /// ADR-0051) and the PTY permission (ADR-0050 §6).
    authenticated: Authenticated,
    uid: u32,
    state: ChannelState,
    /// The client's channel id (recipient of every frame we send).
    peer_chan: u32,
    /// Bytes we may still send the client (`u64` to detect `WINDOW_ADJUST`
    /// overflow before it wraps a `u32`).
    out_window: u64,
    /// The client's max packet size; we never send a larger payload.
    out_max_pkt: u32,
    /// Bytes the client may still send us (`granted - received`).
    in_window: u32,
    /// Child-consumed inbound bytes not yet returned as `WINDOW_ADJUST`.
    credit_pending: u32,
    /// Output chunk being sent, if any.
    pending_out: Option<PendingOut>,
    /// One inbound chunk awaiting handoff to the child's stdin.
    pending_stdin: Option<Vec<u8>>,
    /// Inbound data that arrived before `exec` was accepted (bounded by
    /// the window).
    pre_exec_stdin: VecDeque<Vec<u8>>,
    /// The client sent `CHANNEL_EOF` (no more stdin).
    client_eof: bool,
    /// The client closed before we did (early close).
    early_close: bool,
    /// The child's exit status, once known.
    exit_status: Option<i32>,
    /// The listed signal that killed the child, with its core-dumped flag:
    /// sent as `exit-signal` instead of `exit-status` (ADR-0038 §8).
    exit_signal: Option<(&'static str, bool)>,
    /// Both child output pumps have hit EOF (and the reap reported exit).
    child_out_closed: bool,
    /// The consumed-acks channel has closed (stdin pump finished).
    consumed_closed: bool,
    /// The accepted `exec` command, or the empty string for a `shell` —
    /// `Some` once a child is accepted (so an `exec.finished` audit event
    /// is owed) and the value the `exec.*` events carry as the structured
    /// `command` field (ADR-0024).
    command: Option<String>,
    /// The `request_type` audit field: `"exec"` or `"shell"` (ADR-0038 §9).
    request_type: &'static str,
    /// The `pty` audit field: the child runs on a pseudo-terminal.
    on_pty: bool,
    /// Channel payload bytes the child consumed from the client, for
    /// `exec.finished` (ADR-0042).
    bytes_received: u64,
    /// Channel payload bytes of the child's output sent to the client.
    bytes_sent: u64,
    /// `exec.started` has been emitted (emit exactly once).
    started_emitted: bool,
    /// `exec.finished` has been emitted (emit exactly once).
    finished_emitted: bool,
    /// Reply-generating inbound messages buffered during a re-key's
    /// half-duplex window (RFC 4253 §9), processed once it completes.
    deferred: Vec<Vec<u8>>,
    /// The spawned child, once `exec` is accepted.
    child: Option<ChildIo>,
}

/// Backstop for the ADR-0023 audit invariant: every `exec.started` is
/// followed by exactly one `exec.finished`. The normal close path emits
/// it explicitly; this covers the paths that never get there — a panic
/// unwinding the connection task (and the Phase-2 task aborts, ADR-0028)
/// — so the audit trail cannot lose its terminal record. Runs before the
/// fields drop, so the event precedes the child teardown that
/// [`ChildIo`]'s own `Drop` triggers. No-op when already emitted.
impl Drop for Driver<'_> {
    fn drop(&mut self) {
        self.emit_finished();
    }
}

impl<'a> Driver<'a> {
    fn new(authenticated: Authenticated, children: &'a ChildScope) -> Self {
        Self {
            children,
            pty: None,
            uid: authenticated
                .account
                .as_ref()
                .map_or_else(exec::executing_uid, |a| a.uid),
            authenticated,
            state: ChannelState::BeforeOpen,
            peer_chan: 0,
            out_window: 0,
            out_max_pkt: 0,
            in_window: 0,
            credit_pending: 0,
            pending_out: None,
            pending_stdin: None,
            pre_exec_stdin: VecDeque::new(),
            client_eof: false,
            early_close: false,
            exit_status: None,
            exit_signal: None,
            child_out_closed: false,
            consumed_closed: false,
            command: None,
            request_type: "exec",
            on_pty: false,
            bytes_received: 0,
            bytes_sent: 0,
            started_emitted: false,
            finished_emitted: false,
            deferred: Vec::new(),
            child: None,
        }
    }

    /// During a re-key's half-duplex window (RFC 4253 §9, after we sent our
    /// KEXINIT), inbound channel data that needs no reply is handled inline;
    /// anything that would make us send a reply is deferred until after our
    /// NEWKEYS, so we never emit a non-KEX packet in the window
    /// (Terrapin-class; CLAUDE.md transport rule).
    async fn pass_to_channel<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        payload: Vec<u8>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Inbound-only (stdin data, window credit, EOF) sends no reply, so it
        // is safe in the window; anything else is deferred past our NEWKEYS.
        if matches!(
            payload.first().copied(),
            Some(SSH_MSG_CHANNEL_DATA | SSH_MSG_CHANNEL_WINDOW_ADJUST | SSH_MSG_CHANNEL_EOF)
        ) {
            self.handle_inbound(session, &payload).await
        } else {
            if self.deferred.len() >= MAX_DEFERRED {
                return Err(session
                    .protocol_disconnect("too-many-deferred-during-rekey")
                    .await);
            }
            self.deferred.push(payload);
            Ok(())
        }
    }

    /// Processes the messages buffered during the re-key window, now that
    /// we may reply again.
    async fn drain_deferred<S>(
        &mut self,
        session: &mut Expect<S, Session>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        for payload in std::mem::take(&mut self.deferred) {
            self.handle_inbound(session, &payload).await?;
        }
        Ok(())
    }
}

/// Runs the channel layer for one connection. Returns `Ok(())` on a
/// clean close.
///
/// # Errors
///
/// [`TransportError::Rejected`] on a protocol violation (the
/// `SSH_MSG_DISCONNECT` is already sent), or [`TransportError::Io`] on a
/// connection failure.
pub(crate) async fn drive<S>(
    session: &mut Expect<S, Session>,
    children: &ChildScope,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut d = Driver::new(session.authenticated().clone(), children);

    loop {
        // Outbound channel work is suppressed during a re-key (RFC 4253 §9
        // half-duplex: once we've sent our KEXINIT we send no channel data
        // until our NEWKEYS). Feeding the child's stdin (B) is local and
        // always safe.
        if !session.rekey_active() {
            // (A) Flush child output while the client's window allows.
            d.flush_output(session).await?;
        }
        // (B) Hand one inbound chunk toward the child's stdin (non-blocking).
        d.handoff_stdin();
        if !session.rekey_active() {
            // (C) Return inbound credit once a batch has been consumed.
            d.replenish_window(session).await?;
            // (D) Initiate a re-key when a threshold is crossed (ADR-0026).
            // Include `Draining`: a fast exec can cross the byte/packet
            // limit during the final flush and become ready to close in
            // the same turn — checking only `Running`/`Idle` would skip
            // the re-key and close under the old keys.
            if session.rekey_due()
                && matches!(
                    d.state,
                    ChannelState::Running | ChannelState::Idle | ChannelState::Draining
                )
            {
                session.begin_rekey().await?;
            }
            // (E) Close sequence only when no re-key is in flight: the
            // half-duplex window must finish first.
            if !session.rekey_active() {
                if d.ready_to_close() {
                    d.send_terminal(session).await?;
                }
                if d.state == ChannelState::Closed {
                    d.emit_finished();
                    return Ok(());
                }
            }
        }

        // (F) Wait for the next event. Guards/timers are read into locals
        // first so they do not borrow `d`/`session` while the child
        // receivers are borrowed.
        let want_output =
            d.pending_out.is_none() && d.state.may_emit_output() && !session.rekey_active();
        let consumed_active = !d.consumed_closed;
        let rekey_deadline = session.rekey_deadline();
        // Only arm the idle interval-trigger in states where `begin_rekey`
        // could actually fire; otherwise a past wake instant would re-arm
        // every iteration and busy-spin (the timer never advances `last_kex`).
        let rekey_wake = if matches!(
            d.state,
            ChannelState::Running | ChannelState::Idle | ChannelState::Draining
        ) {
            session.rekey_wake_at()
        } else {
            None
        };
        let (out, consumed) = match d.child.as_mut() {
            Some(c) => (Some(&mut c.out_rx), Some(&mut c.consumed_rx)),
            None => (None, None),
        };

        tokio::select! {
            biased;
            pkt = session.read_packet() => {
                let payload = pkt?;
                if session.rekey_active() {
                    match session.step_rekey(&payload).await? {
                        RekeyStep::PassToChannel => d.pass_to_channel(session, payload).await?,
                        // The re-key finished: process anything the peer sent
                        // during the half-duplex window, now that we may reply.
                        RekeyStep::Completed => d.drain_deferred(session).await?,
                        RekeyStep::Continued => {}
                    }
                } else if payload.first() == Some(&SSH_MSG_KEXINIT) {
                    // Client-initiated re-key.
                    session.step_rekey(&payload).await?;
                } else {
                    d.handle_inbound(session, &payload).await?;
                }
            }
            chunk = recv_opt_out(out), if want_output => {
                match chunk {
                    // The client closed first: its output has no sink.
                    Some(ChildChunk::Stdout(_) | ChildChunk::Stderr(_)) if d.early_close => {}
                    Some(ChildChunk::Stdout(b)) => d.pending_out = Some(PendingOut::new(Stream::Stdout, b)),
                    Some(ChildChunk::Stderr(b)) => d.pending_out = Some(PendingOut::new(Stream::Stderr, b)),
                    Some(ChildChunk::Exited(exit)) => {
                        if d.exit_status.is_none() {
                            d.exit_status = Some(exit.code);
                            d.exit_signal = exit.signal;
                        }
                        if d.state == ChannelState::Running {
                            d.state = ChannelState::Draining;
                        }
                    }
                    None => d.child_out_closed = true,
                }
            }
            credit = recv_opt_consumed(consumed), if consumed_active => {
                match credit {
                    Some(n) => {
                        d.credit_pending = d.credit_pending.saturating_add(n);
                        d.bytes_received = d.bytes_received.saturating_add(u64::from(n));
                    }
                    None => d.consumed_closed = true,
                }
            }
            // A started re-key must finish within the deadline (ADR-0026).
            () = sleep_until_opt(rekey_deadline), if rekey_deadline.is_some() => {
                return Err(session.rekey_timeout().await);
            }
            // Idle interval trigger: wake so the next iteration re-keys.
            () = sleep_until_opt(rekey_wake), if rekey_wake.is_some() => {}
        }
    }
}

/// Sleeps until `at`, or never resolves if `None` — the `select!` guard
/// pattern for an optional timer.
async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Receives one child-output message, or never resolves if the child is
/// not spawned yet. Cancel-safe (`mpsc::Receiver::recv`).
async fn recv_opt_out(rx: Option<&mut mpsc::Receiver<ChildChunk>>) -> Option<ChildChunk> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Receives one stdin-consumed ack, or never resolves if absent.
async fn recv_opt_consumed(rx: Option<&mut mpsc::UnboundedReceiver<u32>>) -> Option<u32> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

impl Driver<'_> {
    /// (A) Sends as much pending output as the client window and max
    /// packet allow, splitting one chunk across packets as needed.
    async fn flush_output<S>(
        &mut self,
        session: &mut Expect<S, Session>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        while self.state.may_emit_output() {
            let Some(p) = self.pending_out.as_mut() else {
                break;
            };
            if self.out_window == 0 {
                break;
            }
            let n = send_size(self.out_window, self.out_max_pkt, p.remaining());
            if n == 0 {
                break;
            }
            let kind = p.kind;
            let frame = build_data_frame(self.peer_chan, kind, p.take(n));
            session.write_packet(&frame).await?;
            self.out_window -= n as u64;
            self.bytes_sent = self.bytes_sent.saturating_add(n as u64);
            if self.pending_out.as_ref().is_some_and(PendingOut::is_empty) {
                self.pending_out = None;
            }
        }
        Ok(())
    }

    /// (B) Hands one buffered inbound chunk to the child's stdin without
    /// blocking, refilling from the pre-exec buffer first. A full pump
    /// queue leaves the chunk stashed, which keeps the inbound arm gated
    /// and backpressures the wire — nothing is dropped. Once all buffered
    /// stdin is delivered and the client has sent EOF, the child's stdin
    /// is closed.
    fn handoff_stdin(&mut self) {
        if self.child.is_none() {
            return;
        }
        // Refill the single pending slot from the pre-exec buffer (stdin
        // that arrived before the exec was accepted).
        if self.pending_stdin.is_none() {
            self.pending_stdin = self.pre_exec_stdin.pop_front();
        }
        if let Some(chunk) = self.pending_stdin.take()
            && let Err(returned) = self.child.as_ref().unwrap().try_send_stdin(chunk)
        {
            // Pump full: keep it for the next pass (wire backpressure).
            self.pending_stdin = Some(returned);
            return;
        }
        // All buffered stdin delivered; honour a pending client EOF now.
        if self.client_eof
            && self.pending_stdin.is_none()
            && self.pre_exec_stdin.is_empty()
            && let Some(child) = self.child.as_mut()
        {
            child.close_stdin();
        }
    }

    /// (C) Returns inbound credit to the client once a batch has been
    /// consumed by the child.
    async fn replenish_window<S>(
        &mut self,
        session: &mut Expect<S, Session>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.credit_pending >= CREDIT_BATCH {
            let credit = self.credit_pending;
            let frame = build_window_adjust(self.peer_chan, credit);
            session.write_packet(&frame).await?;
            self.in_window = self.in_window.saturating_add(credit);
            self.credit_pending = 0;
        }
        Ok(())
    }

    /// The child is finished and all its output is on the wire.
    fn ready_to_close(&self) -> bool {
        self.state == ChannelState::Draining && self.child_out_closed && self.pending_out.is_none()
    }

    /// (D) Sends the terminal sequence. On a normal exit: `exit-status`
    /// (or `exit-signal` for a death by a listed signal), `CHANNEL_EOF`,
    /// `CHANNEL_CLOSE`, then awaits the client's close. On an early client
    /// close: just our `CHANNEL_CLOSE`, and we are done.
    async fn send_terminal<S>(
        &mut self,
        session: &mut Expect<S, Session>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.early_close {
            session.write_packet(&build_close(self.peer_chan)).await?;
            self.state = ChannelState::Closed;
            return Ok(());
        }
        if let Some((name, core_dumped)) = self.exit_signal {
            session
                .write_packet(&build_exit_signal(self.peer_chan, name, core_dumped))
                .await?;
        } else if let Some(code) = self.exit_status {
            let status = u32::from_ne_bytes(code.to_ne_bytes());
            session
                .write_packet(&build_exit_status(self.peer_chan, status))
                .await?;
        }
        session.write_packet(&build_eof(self.peer_chan)).await?;
        session.write_packet(&build_close(self.peer_chan)).await?;
        self.state = ChannelState::ServerClosed;
        Ok(())
    }

    /// Emits `exec.started` exactly once, for the command `start` set.
    fn emit_started(&mut self) {
        let Some(command) = self.command.as_deref() else {
            return;
        };
        if self.started_emitted {
            return;
        }
        self.started_emitted = true;
        let cert = self.authenticated.certificate.as_ref();
        info!(
            target: "audit",
            authenticated_identity = %self.authenticated.fingerprint,
            executing_uid = self.uid,
            command = %command,
            request_type = self.request_type,
            pty = self.on_pty,
            cert_key_id = cert.map(|c| c.key_id.as_str()),
            cert_serial = cert.map(|c| c.serial.as_str()),
            cert_ca_fingerprint = cert.map(|c| c.ca_fingerprint.as_str()),
            cert_principal = cert.map(|c| c.principal.as_str()),
            account = self.authenticated.account.as_ref().map(|a| a.name.as_str()),
            "exec.started"
        );
    }

    /// Emits `exec.finished` exactly once, if an `exec` was started. A
    /// start cancelled while it waited for the launcher, at the drain
    /// deadline, never wrote `exec.started`: it is written first, with the
    /// UID read at authentication, as for a refused start (ADR-0064 §2),
    /// so the records stay a pair.
    fn emit_finished(&mut self) {
        if let Some(command) = self.command.clone()
            && !self.finished_emitted
        {
            self.emit_started();
            self.finished_emitted = true;
            // Credits still queued when the channel closes are bytes the
            // child received before it did: count them (ADR-0042).
            if let Some(child) = self.child.as_mut() {
                while let Ok(n) = child.consumed_rx.try_recv() {
                    self.bytes_received = self.bytes_received.saturating_add(u64::from(n));
                }
            }
            let exit_status = self.exit_status.unwrap_or(EXIT_SPAWN_FAILED);
            let cert = self.authenticated.certificate.as_ref();
            info!(
                target: "audit",
                authenticated_identity = %self.authenticated.fingerprint,
                executing_uid = self.uid,
                command = %command,
                request_type = self.request_type,
                pty = self.on_pty,
                exit_status,
                bytes_received = self.bytes_received,
                bytes_sent = self.bytes_sent,
                cert_key_id = cert.map(|c| c.key_id.as_str()),
                cert_serial = cert.map(|c| c.serial.as_str()),
                cert_ca_fingerprint = cert.map(|c| c.ca_fingerprint.as_str()),
                cert_principal = cert.map(|c| c.principal.as_str()),
                account = self.authenticated.account.as_ref().map(|a| a.name.as_str()),
                "exec.finished"
            );
        }
    }

    /// Dispatches one inbound packet. Total and fail-closed: the eleven
    /// channel messages plus the post-auth transport messages RFC 4253
    /// §11 requires tolerating (`IGNORE`, `DEBUG`, `UNIMPLEMENTED`);
    /// everything else terminates the connection.
    async fn handle_inbound<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        payload: &[u8],
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut r = Reader::new(payload);
        let Ok(msg) = r.byte() else {
            return Err(session.protocol_disconnect("empty-packet").await);
        };
        match msg {
            SSH_MSG_CHANNEL_OPEN => self.on_channel_open(session, &mut r).await,
            // Before CHANNEL_OPEN no recipient id has meaning
            // (RFC 4254 §5.1 assigns them at open): answering CLOSE or
            // REQUEST for a channel that never existed is the
            // accept-and-branch shape the type-state discipline
            // forbids. Fail closed instead.
            SSH_MSG_CHANNEL_REQUEST
            | SSH_MSG_CHANNEL_DATA
            | SSH_MSG_CHANNEL_WINDOW_ADJUST
            | SSH_MSG_CHANNEL_EOF
            | SSH_MSG_CHANNEL_CLOSE
                if self.state == ChannelState::BeforeOpen =>
            {
                Err(session
                    .protocol_disconnect("channel-message-before-open")
                    .await)
            }
            SSH_MSG_CHANNEL_REQUEST => self.on_channel_request(session, &mut r).await,
            SSH_MSG_CHANNEL_DATA => self.on_channel_data(session, &mut r).await,
            SSH_MSG_CHANNEL_WINDOW_ADJUST => self.on_window_adjust(session, &mut r).await,
            SSH_MSG_CHANNEL_EOF => self.on_channel_eof(session, &mut r).await,
            SSH_MSG_CHANNEL_CLOSE => self.on_channel_close(session, &mut r).await,
            SSH_MSG_GLOBAL_REQUEST => {
                // RFC 4254 §4: reply only when `want_reply` is set —
                // a spurious reply to `want_reply = false` (OpenSSH's
                // `no-more-sessions@openssh.com`) desynchronises the
                // client's request/reply pairing. No global request
                // is recognised in Phase 1.
                let want_reply = match parse_global_request(&mut r) {
                    Ok(want_reply) => want_reply,
                    Err(reason) => return Err(session.protocol_disconnect(reason).await),
                };
                if want_reply {
                    session.write_packet(&[SSH_MSG_REQUEST_FAILURE]).await?;
                }
                Ok(())
            }
            // RFC 4253 §11.2–§11.4: IGNORE and DEBUG MUST be accepted
            // at any time (strict-kex bans them only during the KEX
            // handshake, which `step_rekey` still enforces); none of
            // the three generates a response. Discarded unread — and
            // still counted by the transport's byte and packet re-key
            // triggers, so they cannot stall the nonce schedule.
            SSH_MSG_IGNORE | SSH_MSG_UNIMPLEMENTED | SSH_MSG_DEBUG => Ok(()),
            SSH_MSG_DISCONNECT => Err(TransportError::Rejected("peer-disconnected")),
            SSH_MSG_CHANNEL_EXTENDED_DATA => {
                // No client→server extended-data type exists (RFC 4254 §5.2).
                Err(session.protocol_disconnect("inbound-extended-data").await)
            }
            _ => Err(session
                .protocol_disconnect("unexpected-channel-message")
                .await),
        }
    }

    async fn on_channel_open<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let ChannelOpen {
            channel_type: ctype,
            sender,
            window,
            max_packet: max_pkt,
        } = match parse_channel_open(r) {
            Ok(open) => open,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if self.state != ChannelState::BeforeOpen {
            // A second channel — refuse by policy, keep the first.
            let frame = build_open_failure(
                sender,
                SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "one channel only",
            );
            session.write_packet(&frame).await?;
            return Ok(());
        }
        if ctype != b"session" {
            let frame = build_open_failure(
                sender,
                SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                "unknown channel type",
            );
            session.write_packet(&frame).await?;
            return Ok(());
        }
        // A zero max-packet-size would make `flush_output` compute a send
        // size of 0 forever: output never drains, the close sequence never
        // fires, and the un-timed channel phase hangs while the child's
        // stdout pump pins a blocking thread. Fail closed (RFC 4254 §5.1
        // sets no minimum, so the server enforces one).
        if max_pkt == 0 {
            return Err(session.protocol_disconnect("zero-max-packet-size").await);
        }
        self.peer_chan = sender;
        self.out_window = u64::from(window);
        self.out_max_pkt = max_pkt;
        self.in_window = INITIAL_WINDOW;
        self.state = ChannelState::Idle;
        session
            .write_packet(&build_open_confirmation(sender))
            .await?;
        Ok(())
    }

    async fn on_channel_request<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let RequestHead {
            recipient,
            request_type: rtype,
            want_reply,
        } = match parse_request_head(r) {
            Ok(head) => head,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        match rtype {
            b"exec" if self.state == ChannelState::Idle => {
                let command = match parse_exec(r) {
                    Ok(command) => command,
                    Err(reason) => return Err(session.protocol_disconnect(reason).await),
                };
                self.start(session, Start::Program(Program::Exec(command)), want_reply)
                    .await
            }
            b"shell" if self.state == ChannelState::Idle => {
                self.start(session, Start::Program(Program::Shell), want_reply)
                    .await
            }
            b"subsystem" => self.on_subsystem(session, r, want_reply).await,
            b"pty-req" => self.on_pty_req(session, r, want_reply).await,
            b"window-change" => self.on_window_change(session, r, want_reply).await,
            // Any other request (env, subsystem, x11-req, agent forwarding,
            // signal, break, or a second exec/shell) is refused.
            _ => self.reply(session, want_reply, false).await,
        }
    }

    /// Replies `SSH_MSG_CHANNEL_SUCCESS` or `_FAILURE`, only when
    /// `want_reply` is set (RFC 4254 §5.4).
    async fn reply<S>(
        &self,
        session: &mut Expect<S, Session>,
        want_reply: bool,
        success: bool,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if want_reply {
            let msg = if success {
                SSH_MSG_CHANNEL_SUCCESS
            } else {
                SSH_MSG_CHANNEL_FAILURE
            };
            session
                .write_packet(&build_channel_msg(msg, self.peer_chan))
                .await?;
        }
        Ok(())
    }

    /// `pty-req` (RFC 4254 §6.2, ADR-0038 §2): every field is bounded, and
    /// a malformed one disconnects. A request in the wrong state, a second
    /// one, a refused `TERM`, no helper, a failed allocation, or a
    /// certificate without `permit-pty` (the ADR-0038 §3 gate, ADR-0050
    /// §6) is refused and leaves no PTY state behind.
    async fn on_pty_req<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
        want_reply: bool,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let PtyRequest {
            term,
            size,
            modes,
            blob,
        } = match parse_pty_req(r) {
            Ok(request) => request,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        let allowed = self.authenticated.pty_permitted
            && self.state == ChannelState::Idle
            && self.pty.is_none()
            && (self.children.helper().is_some() || self.children.launcher().is_some())
            && pty::valid_term(term);
        // `valid_term` admits ASCII only, so the conversion cannot fail.
        let pending = allowed
            .then(|| {
                let term = std::str::from_utf8(term).ok()?.to_string();
                let alloc = if self.children.launcher().is_some() {
                    PtyAlloc::Remote {
                        size,
                        modes: blob.to_vec(),
                    }
                } else {
                    PtyAlloc::Local(pty::allocate(&modes, size).ok()?)
                };
                Some(PendingPty { alloc, term })
            })
            .flatten();
        // A refusal leaves an already granted PTY in place.
        let granted = pending.is_some();
        if granted {
            self.pty = pending;
        }
        self.reply(session, want_reply, granted).await
    }

    /// `subsystem` (RFC 4254 §6.5, ADR-0041 §1): `sftp` is honoured once,
    /// in `Idle`, with no PTY pending and a helper configured; anything
    /// else is refused. A malformed name disconnects.
    async fn on_subsystem<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
        want_reply: bool,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let name = match parse_subsystem(r) {
            Ok(name) => name,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if name == b"sftp"
            && self.state == ChannelState::Idle
            && self.pty.is_none()
            && self.children.helper().is_some()
        {
            self.start(session, Start::Sftp, want_reply).await
        } else {
            self.reply(session, want_reply, false).await
        }
    }

    /// `window-change` (RFC 4254 §6.7): applied to the master while a PTY
    /// is allocated, with `pty-req`'s dimension rule; refused otherwise.
    async fn on_window_change<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
        want_reply: bool,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let size = match parse_window_change(r) {
            Ok(size) => size,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        let applied = match (&mut self.pty, &self.child) {
            (Some(pending), _) => match &mut pending.alloc {
                PtyAlloc::Local(pair) => pty::resize(&pair.master, size).is_ok(),
                PtyAlloc::Remote { size: kept, .. } => {
                    // Zero dimensions keep their value (ADR-0038 §2).
                    let keep = |new: u32, old: u32| if new == 0 { old } else { new };
                    *kept = Size {
                        cols: keep(size.cols, kept.cols),
                        rows: keep(size.rows, kept.rows),
                        width_px: keep(size.width_px, kept.width_px),
                        height_px: keep(size.height_px, kept.height_px),
                    };
                    true
                }
            },
            (None, Some(child)) if self.on_pty => child.resize(size).is_ok(),
            _ => false,
        };
        self.reply(session, want_reply, applied).await
    }

    /// Starts the channel's one child: on the PTY a `pty-req` allocated,
    /// or on pipes; the SFTP helper always on pipes. Every start emits
    /// `exec.started` (ADR-0038 §9, ADR-0041 §1).
    async fn start<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        start: Start<'_>,
        want_reply: bool,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (command, request_type) = match start {
            Start::Program(Program::Exec(command)) => (command, "exec"),
            Start::Program(Program::Shell) => ("", "shell"),
            Start::Sftp => ("sftp", "subsystem"),
        };
        let mut pending = self.pty.take();
        self.command = Some(command.to_string());
        self.request_type = request_type;
        self.on_pty = pending.is_some();
        // Account mode: the launcher starts the session first, so that
        // `exec.started` carries the UID it actually runs under, from the
        // launcher's own read of the account (ADR-0064 §2). A refusal keeps
        // the UID read at authentication.
        let remote = match self.authenticated.account.as_ref().map(|a| a.name.clone()) {
            Some(name) => {
                let spawned = remote_start(&name, start, pending.take(), self.children).await;
                Some(spawned.map(|(child, uid)| {
                    self.uid = uid;
                    child
                }))
            }
            None => None,
        };
        self.emit_started();
        self.reply(session, want_reply, true).await?;
        let spawned = match (remote, start, pending) {
            // Account mode: the launcher started it (ADR-0064).
            (Some(spawned), _, _) => spawned,
            // `on_subsystem` refuses SFTP while a PTY is pending.
            (None, Start::Sftp, _) => exec::spawn_sftp(self.children),
            (
                None,
                Start::Program(program),
                Some(PendingPty {
                    alloc: PtyAlloc::Local(pair),
                    term,
                }),
            ) => exec::spawn_pty(program, pair, &term, self.children),
            (None, Start::Program(program), _) => exec::spawn(program, self.children),
        };
        if let Ok(child) = spawned {
            self.child = Some(child);
            self.state = ChannelState::Running;
            // Any stdin buffered before the exec stays in `pre_exec_stdin`
            // and is drained by `handoff_stdin` under flow control — never
            // dropped (the pump's queue bound would otherwise discard it
            // and leak the inbound window credit). `client_eof` is likewise
            // applied only once that buffer is fully delivered.
        } else {
            // Spawn failed: still produce a started/finished pair.
            self.exit_status = Some(EXIT_SPAWN_FAILED);
            self.child_out_closed = true;
            self.consumed_closed = true;
            self.state = ChannelState::Draining;
        }
        Ok(())
    }

    async fn on_channel_data<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (recipient, data) = match parse_channel_data(r) {
            Ok(fields) => fields,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        // Frames for the channel during our half-close window are legitimate
        // (the two CLOSEs may cross) but have no sink — discard them.
        if self.state == ChannelState::ServerClosed {
            return Ok(());
        }
        if self.client_eof {
            return Err(session.protocol_disconnect("data-after-eof").await);
        }
        let Some(in_window) = take_inbound(self.in_window, data.len()) else {
            return Err(session.protocol_disconnect("inbound-window-exceeded").await);
        };
        self.in_window = in_window;
        if self.state == ChannelState::Idle {
            self.pre_exec_stdin.push_back(data.to_vec());
        } else if self.child.is_some() {
            // Stash one chunk; handoff happens in phase (B). If one is
            // already stashed, append (both are within the window).
            match self.pending_stdin.as_mut() {
                Some(buf) => buf.extend_from_slice(data),
                None => self.pending_stdin = Some(data.to_vec()),
            }
        }
        Ok(())
    }

    async fn on_window_adjust<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (recipient, add) = match parse_window_adjust(r) {
            Ok(fields) => fields,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        let Some(out_window) = add_out_window(self.out_window, add) else {
            return Err(session.protocol_disconnect("window-overflow").await);
        };
        self.out_window = out_window;
        Ok(())
    }

    async fn on_channel_eof<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let recipient = match parse_recipient(r, "malformed-channel-eof") {
            Ok(recipient) => recipient,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        // Mark EOF; `handoff_stdin` closes the child's stdin only after any
        // buffered (incl. pre-exec) stdin has been delivered, so no input
        // is lost to an early close.
        self.client_eof = true;
        Ok(())
    }

    async fn on_channel_close<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        r: &mut Reader<'_>,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let recipient = match parse_recipient(r, "malformed-channel-close") {
            Ok(recipient) => recipient,
            Err(reason) => return Err(session.protocol_disconnect(reason).await),
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        if self.state == ChannelState::ServerClosed {
            // Normal close handshake completes.
            self.state = ChannelState::Closed;
            return Ok(());
        }
        // Client closed first: relinquish exit-status, drop the output it
        // can no longer receive, kill + reap the child, then reply with our
        // CLOSE once the reap reports the exit — not once the pipes reach
        // EOF, which a process the leader left behind can delay (#190).
        self.early_close = true;
        self.pending_out = None;
        if let Some(child) = self.child.as_mut() {
            child.close_stdin();
            child.discard_output();
            child.kill();
        } else {
            // No child running (Idle or already draining): close now.
            self.child_out_closed = true;
        }
        self.state = ChannelState::Draining;
        Ok(())
    }
}

/// What a channel request starts.
#[derive(Clone, Copy)]
enum Start<'a> {
    /// `exec` or `shell`.
    Program(Program<'a>),
    /// `subsystem "sftp"` (ADR-0041).
    Sftp,
}

/// A pair allocated by `pty-req`, with its validated `TERM` (empty means
/// no `TERM` in the child's environment).
struct PendingPty {
    alloc: PtyAlloc,
    term: String,
}

/// Where a pending PTY lives until the session starts.
enum PtyAlloc {
    /// Service-account mode: the pair `pty-req` allocated.
    Local(PtyPair),
    /// Account mode: the launcher allocates the pair at the start
    /// (ADR-0064 §2); until then the server keeps the fields.
    Remote { size: Size, modes: Vec<u8> },
}

/// Account mode's start: the session's kind and PTY fields go to the
/// launcher, which allocates and starts it (ADR-0063 §2, ADR-0064 §2).
async fn remote_start(
    account: &str,
    start: Start<'_>,
    pending: Option<PendingPty>,
    children: &ChildScope,
) -> std::io::Result<(ChildIo, u32)> {
    let (size, modes, term) = match pending {
        Some(PendingPty {
            alloc: PtyAlloc::Remote { size, modes },
            term,
        }) => (Some(size), modes, term),
        _ => (None, Vec::new(), String::new()),
    };
    let pty = size.map(|size| launcher::PtyRequest {
        term: term.as_bytes(),
        size: launcher::WindowSize {
            cols: size.cols,
            rows: size.rows,
            width_px: size.width_px,
            height_px: size.height_px,
        },
        modes: &modes,
    });
    let session = match start {
        Start::Sftp => launcher::Session::Sftp,
        Start::Program(Program::Shell) => launcher::Session::Shell { pty },
        Start::Program(Program::Exec(command)) => launcher::Session::Exec {
            command: command.as_bytes(),
            pty,
        },
    };
    exec::spawn_remote(account, session, children).await
}

// ---- pure frame builders (unit-tested) ----

fn build_data_frame(peer_chan: u32, kind: Stream, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    match kind {
        Stream::Stdout => {
            w.put_byte(SSH_MSG_CHANNEL_DATA);
            w.put_uint32(peer_chan);
            w.put_string(data);
        }
        Stream::Stderr => {
            w.put_byte(SSH_MSG_CHANNEL_EXTENDED_DATA);
            w.put_uint32(peer_chan);
            w.put_uint32(SSH_EXTENDED_DATA_STDERR);
            w.put_string(data);
        }
    }
    w.into_bytes()
}

fn build_open_confirmation(peer_chan: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    w.put_uint32(peer_chan);
    w.put_uint32(LOCAL_CHANNEL);
    w.put_uint32(INITIAL_WINDOW);
    w.put_uint32(MAX_PACKET);
    w.into_bytes()
}

fn build_open_failure(peer_chan: u32, code: u32, desc: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_CHANNEL_OPEN_FAILURE);
    w.put_uint32(peer_chan);
    w.put_uint32(code);
    w.put_string(desc.as_bytes());
    w.put_string(b"");
    w.into_bytes()
}

fn build_window_adjust(peer_chan: u32, add: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
    w.put_uint32(peer_chan);
    w.put_uint32(add);
    w.into_bytes()
}

fn build_exit_status(peer_chan: u32, status: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_CHANNEL_REQUEST);
    w.put_uint32(peer_chan);
    w.put_string(b"exit-status");
    w.put_boolean(false);
    w.put_uint32(status);
    w.into_bytes()
}

/// RFC 4254 §6.10 `exit-signal`: the name without `SIG`, the core-dumped
/// flag, and an empty message and language tag, as sshd sends.
fn build_exit_signal(peer_chan: u32, name: &str, core_dumped: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(SSH_MSG_CHANNEL_REQUEST);
    w.put_uint32(peer_chan);
    w.put_string(b"exit-signal");
    w.put_boolean(false);
    w.put_string(name.as_bytes());
    w.put_boolean(core_dumped);
    w.put_string(b"");
    w.put_string(b"");
    w.into_bytes()
}

fn build_eof(peer_chan: u32) -> Vec<u8> {
    build_channel_msg(SSH_MSG_CHANNEL_EOF, peer_chan)
}

fn build_close(peer_chan: u32) -> Vec<u8> {
    build_channel_msg(SSH_MSG_CHANNEL_CLOSE, peer_chan)
}

/// A one-field channel message: `byte msg; uint32 recipient`.
fn build_channel_msg(msg: u8, peer_chan: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(msg);
    w.put_uint32(peer_chan);
    w.into_bytes()
}

// ---- inbound message parsers (ADR-0060 §3, #271) ----
//
// Each reads one message's fields from a reader positioned where its
// handler reads them, after the message type byte, and returns them, or
// the reason the handler disconnects with. They hold no state and do no
// I/O, so the `channel` fuzz target reaches them. Which of them an inbound
// packet reaches still depends on the driver's state, as before.

/// The fields of `SSH_MSG_CHANNEL_OPEN` (RFC 4254 §5.1) the server reads.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChannelOpen<'a> {
    pub(crate) channel_type: &'a [u8],
    pub(crate) sender: u32,
    pub(crate) window: u32,
    pub(crate) max_packet: u32,
}

/// Parses an `SSH_MSG_CHANNEL_OPEN` body.
pub(crate) fn parse_channel_open<'a>(r: &mut Reader<'a>) -> Result<ChannelOpen<'a>, &'static str> {
    let (Ok(channel_type), Ok(sender), Ok(window), Ok(max_packet)) = (
        r.string(CHANNEL_TYPE_BOUND),
        r.uint32(),
        r.uint32(),
        r.uint32(),
    ) else {
        return Err("malformed-channel-open");
    };
    Ok(ChannelOpen {
        channel_type,
        sender,
        window,
        max_packet,
    })
}

/// The fields every `SSH_MSG_CHANNEL_REQUEST` (RFC 4254 §5.4) starts with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RequestHead<'a> {
    pub(crate) recipient: u32,
    pub(crate) request_type: &'a [u8],
    pub(crate) want_reply: bool,
}

/// Parses the head of an `SSH_MSG_CHANNEL_REQUEST` body. The fields of
/// the request type follow, for the type's own parser.
pub(crate) fn parse_request_head<'a>(r: &mut Reader<'a>) -> Result<RequestHead<'a>, &'static str> {
    let (Ok(recipient), Ok(request_type), Ok(want_reply)) =
        (r.uint32(), r.string(REQUEST_TYPE_BOUND), r.boolean())
    else {
        return Err("malformed-channel-request");
    };
    Ok(RequestHead {
        recipient,
        request_type,
        want_reply,
    })
}

/// Parses the command of an `exec` request (RFC 4254 §6.5).
pub(crate) fn parse_exec<'a>(r: &mut Reader<'a>) -> Result<&'a str, &'static str> {
    let Ok(bytes) = r.string(COMMAND_BOUND) else {
        return Err("malformed-exec-request");
    };
    std::str::from_utf8(bytes).map_err(|_| "non-utf8-command")
}

/// The fields of a `pty-req` request (RFC 4254 §6.2, ADR-0038 §2).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PtyRequest<'a> {
    pub(crate) term: &'a [u8],
    pub(crate) size: Size,
    pub(crate) modes: pty::Modes,
    /// The encoded modes as sent, which account mode passes to the
    /// launcher (ADR-0063 §2).
    pub(crate) blob: &'a [u8],
}

/// Parses a `pty-req` request. Every field is bounded.
pub(crate) fn parse_pty_req<'a>(r: &mut Reader<'a>) -> Result<PtyRequest<'a>, &'static str> {
    let (Ok(term), Ok(cols), Ok(rows), Ok(width_px), Ok(height_px), Ok(blob)) = (
        r.string(pty::TERM_BOUND),
        r.uint32(),
        r.uint32(),
        r.uint32(),
        r.uint32(),
        r.string(pty::MODES_BOUND),
    ) else {
        return Err("malformed-pty-req");
    };
    let Ok(modes) = pty::Modes::parse(blob) else {
        return Err("truncated-terminal-mode");
    };
    Ok(PtyRequest {
        term,
        size: Size {
            cols,
            rows,
            width_px,
            height_px,
        },
        modes,
        blob,
    })
}

/// Parses the name of a `subsystem` request (RFC 4254 §6.5, ADR-0041 §1).
pub(crate) fn parse_subsystem<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], &'static str> {
    r.string(SUBSYSTEM_BOUND).map_err(|_| "malformed-subsystem")
}

/// Parses a `window-change` request (RFC 4254 §6.7).
pub(crate) fn parse_window_change(r: &mut Reader<'_>) -> Result<Size, &'static str> {
    let (Ok(cols), Ok(rows), Ok(width_px), Ok(height_px)) =
        (r.uint32(), r.uint32(), r.uint32(), r.uint32())
    else {
        return Err("malformed-window-change");
    };
    Ok(Size {
        cols,
        rows,
        width_px,
        height_px,
    })
}

/// Parses an `SSH_MSG_CHANNEL_DATA` body: the recipient and the data,
/// bounded to [`MAX_PACKET`].
pub(crate) fn parse_channel_data<'a>(r: &mut Reader<'a>) -> Result<(u32, &'a [u8]), &'static str> {
    let (Ok(recipient), Ok(data)) = (r.uint32(), r.string(MAX_PACKET as usize)) else {
        return Err("malformed-channel-data");
    };
    Ok((recipient, data))
}

/// Parses an `SSH_MSG_CHANNEL_WINDOW_ADJUST` body: the recipient and the
/// bytes to add.
pub(crate) fn parse_window_adjust(r: &mut Reader<'_>) -> Result<(u32, u32), &'static str> {
    let (Ok(recipient), Ok(add)) = (r.uint32(), r.uint32()) else {
        return Err("malformed-window-adjust");
    };
    Ok((recipient, add))
}

/// Parses the recipient of a one-field message, `SSH_MSG_CHANNEL_EOF` or
/// `SSH_MSG_CHANNEL_CLOSE`, which fails with that message's `reason`.
pub(crate) fn parse_recipient(
    r: &mut Reader<'_>,
    reason: &'static str,
) -> Result<u32, &'static str> {
    r.uint32().map_err(|_| reason)
}

/// Parses an `SSH_MSG_GLOBAL_REQUEST` body (RFC 4254 §4) as far as the
/// server reads it: the request name, then `want_reply`.
pub(crate) fn parse_global_request(r: &mut Reader<'_>) -> Result<bool, &'static str> {
    let (Ok(_name), Ok(want_reply)) = (r.string(REQUEST_TYPE_BOUND), r.boolean()) else {
        return Err("malformed-global-request");
    };
    Ok(want_reply)
}

// ---- window arithmetic (RFC 4254 §5.2) ----

/// What is left of the inbound window after an `SSH_MSG_CHANNEL_DATA` of
/// `len` bytes, or `None` when the peer sent past it.
pub(crate) fn take_inbound(in_window: u32, len: usize) -> Option<u32> {
    // `len` is bounded to MAX_PACKET by the reader, so this fits a u32.
    let len = u32::try_from(len).unwrap_or(u32::MAX);
    in_window.checked_sub(len)
}

/// The outbound window after an `SSH_MSG_CHANNEL_WINDOW_ADJUST` of `add`
/// bytes, or `None` past 2³² − 1 bytes, which RFC 4254 §5.2 forbids a
/// window to exceed.
pub(crate) fn add_out_window(out_window: u64, add: u32) -> Option<u64> {
    let window = out_window.checked_add(u64::from(add))?;
    u32::try_from(window).is_ok().then_some(window)
}

/// How many of `remaining` pending output bytes the next
/// `SSH_MSG_CHANNEL_DATA` carries: no more than the peer's window, its
/// maximum packet size, or ours.
pub(crate) fn send_size(out_window: u64, out_max_packet: u32, remaining: usize) -> usize {
    let cap = out_window
        .min(u64::from(out_max_packet))
        .min(u64::from(MAX_PACKET));
    // cap ≤ MAX_PACKET, so it always fits a usize.
    remaining.min(usize::try_from(cap).unwrap_or(usize::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::CertIdentity;

    /// A bare-key authentication, as `auth::resolve` builds it.
    fn bare_key() -> Authenticated {
        Authenticated {
            fingerprint: "SHA256:test".to_string(),
            certificate: None,
            pty_permitted: true,
            account: None,
        }
    }

    fn read_msg(frame: &[u8]) -> (u8, Reader<'_>) {
        let mut r = Reader::new(frame);
        let msg = r.byte().expect("msg byte");
        (msg, r)
    }

    #[test]
    fn data_frame_is_channel_data_with_payload() {
        let frame = build_data_frame(7, Stream::Stdout, b"hello");
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_DATA);
        assert_eq!(r.uint32().unwrap(), 7);
        assert_eq!(r.string(64).unwrap(), b"hello");
    }

    #[test]
    fn stderr_frame_carries_stderr_data_type() {
        let frame = build_data_frame(3, Stream::Stderr, b"err");
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_EXTENDED_DATA);
        assert_eq!(r.uint32().unwrap(), 3);
        assert_eq!(r.uint32().unwrap(), SSH_EXTENDED_DATA_STDERR);
        assert_eq!(r.string(64).unwrap(), b"err");
    }

    #[test]
    fn open_confirmation_advertises_our_window_and_channel() {
        let frame = build_open_confirmation(42);
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        assert_eq!(r.uint32().unwrap(), 42); // recipient
        assert_eq!(r.uint32().unwrap(), LOCAL_CHANNEL); // our sender id
        assert_eq!(r.uint32().unwrap(), INITIAL_WINDOW);
        assert_eq!(r.uint32().unwrap(), MAX_PACKET);
    }

    #[test]
    fn exit_status_request_has_no_want_reply() {
        let frame = build_exit_status(5, 0);
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_REQUEST);
        assert_eq!(r.uint32().unwrap(), 5);
        assert_eq!(r.string(32).unwrap(), b"exit-status");
        assert!(!r.boolean().unwrap());
        assert_eq!(r.uint32().unwrap(), 0);
    }

    #[test]
    fn exit_signal_request_carries_name_core_flag_and_empty_strings() {
        let frame = build_exit_signal(7, "SEGV", true);
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_REQUEST);
        assert_eq!(r.uint32().unwrap(), 7);
        assert_eq!(r.string(32).unwrap(), b"exit-signal");
        assert!(!r.boolean().unwrap());
        assert_eq!(r.string(32).unwrap(), b"SEGV");
        assert!(r.boolean().unwrap());
        assert_eq!(r.string(32).unwrap(), b"");
        assert_eq!(r.string(32).unwrap(), b"");
        r.finish().unwrap();
    }

    #[test]
    fn negative_exit_code_round_trips_as_uint32() {
        // A signal-killed child reports 128 + signo; serialize/parse must
        // preserve the bit pattern.
        let status = u32::from_ne_bytes(137i32.to_ne_bytes());
        let frame = build_exit_status(1, status);
        let (_, mut r) = read_msg(&frame);
        let _ = r.uint32();
        let _ = r.string(32);
        let _ = r.boolean();
        assert_eq!(r.uint32().unwrap(), 137);
    }

    #[test]
    fn pending_out_cursor_splits_across_takes() {
        let mut p = PendingOut::new(Stream::Stdout, b"abcdef".to_vec());
        assert_eq!(p.take(2), b"ab");
        assert_eq!(p.remaining(), 4);
        assert_eq!(p.take(4), b"cdef");
        assert!(p.is_empty());
    }

    #[test]
    fn window_adjust_frame_round_trips() {
        let frame = build_window_adjust(9, CREDIT_BATCH);
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_WINDOW_ADJUST);
        assert_eq!(r.uint32().unwrap(), 9);
        assert_eq!(r.uint32().unwrap(), CREDIT_BATCH);
    }

    #[test]
    fn open_failure_carries_reason_code() {
        let frame = build_open_failure(2, SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "unknown channel type");
        let (msg, mut r) = read_msg(&frame);
        assert_eq!(msg, SSH_MSG_CHANNEL_OPEN_FAILURE);
        assert_eq!(r.uint32().unwrap(), 2);
        assert_eq!(r.uint32().unwrap(), SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
    }

    // ---- the inbound parsers and the window arithmetic (#271) ----

    fn body(build: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        build(&mut w);
        w.into_bytes()
    }

    /// Every prefix shorter than `bytes` fails with `reason`. `parse`
    /// returns the parser's error, if any.
    fn truncations_fail(
        bytes: &[u8],
        reason: &str,
        parse: impl Fn(&mut Reader<'_>) -> Option<&'static str>,
    ) {
        for cut in 0..bytes.len() {
            let got = parse(&mut Reader::new(&bytes[..cut]));
            assert_eq!(got, Some(reason), "prefix of {cut} bytes");
        }
    }

    #[test]
    fn channel_open_parses_its_four_fields() {
        let bytes = body(|w| {
            w.put_string(b"session");
            w.put_uint32(7);
            w.put_uint32(INITIAL_WINDOW);
            w.put_uint32(MAX_PACKET);
        });
        let open = parse_channel_open(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            open,
            ChannelOpen {
                channel_type: b"session",
                sender: 7,
                window: INITIAL_WINDOW,
                max_packet: MAX_PACKET,
            }
        );
        truncations_fail(&bytes, "malformed-channel-open", |r| {
            parse_channel_open(r).err()
        });
    }

    #[test]
    fn channel_open_bounds_the_channel_type() {
        let long = vec![b'x'; CHANNEL_TYPE_BOUND + 1];
        let bytes = body(|w| {
            w.put_string(&long);
            w.put_uint32(0);
            w.put_uint32(0);
            w.put_uint32(1);
        });
        assert_eq!(
            parse_channel_open(&mut Reader::new(&bytes)),
            Err("malformed-channel-open")
        );
    }

    #[test]
    fn request_head_then_exec_command() {
        let bytes = body(|w| {
            w.put_uint32(LOCAL_CHANNEL);
            w.put_string(b"exec");
            w.put_boolean(true);
            w.put_string(b"echo hello");
        });
        let mut r = Reader::new(&bytes);
        let head = parse_request_head(&mut r).unwrap();
        assert_eq!(
            head,
            RequestHead {
                recipient: LOCAL_CHANNEL,
                request_type: b"exec",
                want_reply: true,
            }
        );
        assert_eq!(parse_exec(&mut r), Ok("echo hello"));
        assert_eq!(r.remaining(), 0);
        // The head is the first 13 bytes: recipient, "exec", want_reply.
        truncations_fail(&bytes[..13], "malformed-channel-request", |r| {
            parse_request_head(r).err()
        });
    }

    #[test]
    fn exec_names_a_missing_and_a_non_utf8_command() {
        assert_eq!(
            parse_exec(&mut Reader::new(&[0, 0])),
            Err("malformed-exec-request")
        );
        let bytes = body(|w| w.put_string(&[0xff, 0xfe]));
        assert_eq!(
            parse_exec(&mut Reader::new(&bytes)),
            Err("non-utf8-command")
        );
        let long = body(|w| w.put_string(&vec![b'a'; COMMAND_BOUND + 1]));
        assert_eq!(
            parse_exec(&mut Reader::new(&long)),
            Err("malformed-exec-request")
        );
    }

    #[test]
    fn pty_req_parses_term_size_and_modes() {
        // VINTR 3, ECHO 1, TTY_OP_END (RFC 4254 §8).
        let modes = [0x01, 0, 0, 0, 3, 0x35, 0, 0, 0, 1, 0x00];
        let bytes = body(|w| {
            w.put_string(b"xterm-256color");
            w.put_uint32(80);
            w.put_uint32(24);
            w.put_uint32(640);
            w.put_uint32(480);
            w.put_string(&modes);
        });
        let request = parse_pty_req(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(request.term, b"xterm-256color");
        assert_eq!(
            request.size,
            Size {
                cols: 80,
                rows: 24,
                width_px: 640,
                height_px: 480,
            }
        );
        assert_eq!(request.modes, pty::Modes::parse(&modes).unwrap());
        truncations_fail(&bytes, "malformed-pty-req", |r| parse_pty_req(r).err());
    }

    #[test]
    fn pty_req_names_truncated_modes() {
        let bytes = body(|w| {
            w.put_string(b"xterm");
            for v in [80, 24, 0, 0] {
                w.put_uint32(v);
            }
            w.put_string(&[0x35, 0, 0]);
        });
        assert_eq!(
            parse_pty_req(&mut Reader::new(&bytes)).unwrap_err(),
            "truncated-terminal-mode"
        );
    }

    #[test]
    fn subsystem_window_change_data_and_adjust() {
        let name = body(|w| w.put_string(b"sftp"));
        assert_eq!(parse_subsystem(&mut Reader::new(&name)), Ok(&b"sftp"[..]));
        truncations_fail(&name, "malformed-subsystem", |r| parse_subsystem(r).err());

        let change = body(|w| {
            for v in [132, 43, 0, 0] {
                w.put_uint32(v);
            }
        });
        assert_eq!(
            parse_window_change(&mut Reader::new(&change)),
            Ok(Size {
                cols: 132,
                rows: 43,
                width_px: 0,
                height_px: 0,
            })
        );
        truncations_fail(&change, "malformed-window-change", |r| {
            parse_window_change(r).err()
        });

        let data = body(|w| {
            w.put_uint32(LOCAL_CHANNEL);
            w.put_string(b"stdin");
        });
        assert_eq!(
            parse_channel_data(&mut Reader::new(&data)),
            Ok((LOCAL_CHANNEL, &b"stdin"[..]))
        );
        truncations_fail(&data, "malformed-channel-data", |r| {
            parse_channel_data(r).err()
        });
        let too_long = body(|w| {
            w.put_uint32(LOCAL_CHANNEL);
            w.put_string(&vec![0; MAX_PACKET as usize + 1]);
        });
        assert_eq!(
            parse_channel_data(&mut Reader::new(&too_long)),
            Err("malformed-channel-data")
        );

        let adjust = body(|w| {
            w.put_uint32(LOCAL_CHANNEL);
            w.put_uint32(CREDIT_BATCH);
        });
        assert_eq!(
            parse_window_adjust(&mut Reader::new(&adjust)),
            Ok((LOCAL_CHANNEL, CREDIT_BATCH))
        );
        truncations_fail(&adjust, "malformed-window-adjust", |r| {
            parse_window_adjust(r).err()
        });
    }

    #[test]
    fn recipient_and_global_request() {
        let recipient = body(|w| w.put_uint32(LOCAL_CHANNEL));
        assert_eq!(
            parse_recipient(&mut Reader::new(&recipient), "malformed-channel-eof"),
            Ok(LOCAL_CHANNEL)
        );
        assert_eq!(
            parse_recipient(&mut Reader::new(&recipient[..3]), "malformed-channel-close"),
            Err("malformed-channel-close")
        );

        let global = body(|w| {
            w.put_string(b"keepalive@openssh.com");
            w.put_boolean(true);
        });
        assert_eq!(parse_global_request(&mut Reader::new(&global)), Ok(true));
        truncations_fail(&global, "malformed-global-request", |r| {
            parse_global_request(r).err()
        });
    }

    #[test]
    fn inbound_window_is_spent_and_never_overdrawn() {
        assert_eq!(take_inbound(INITIAL_WINDOW, 5), Some(INITIAL_WINDOW - 5));
        assert_eq!(take_inbound(5, 5), Some(0));
        assert_eq!(take_inbound(4, 5), None);
        assert_eq!(take_inbound(u32::MAX, usize::MAX), Some(0));
    }

    #[test]
    fn outbound_window_never_exceeds_two_to_the_thirty_two_minus_one() {
        let max = u64::from(u32::MAX);
        assert_eq!(add_out_window(0, u32::MAX), Some(max));
        assert_eq!(add_out_window(1, u32::MAX), None);
        assert_eq!(add_out_window(max, 0), Some(max));
        assert_eq!(add_out_window(u64::MAX, 1), None);
    }

    #[test]
    fn send_size_is_capped_by_both_windows_and_both_packet_sizes() {
        let ours = MAX_PACKET as usize;
        assert_eq!(send_size(0, MAX_PACKET, ours), 0);
        assert_eq!(send_size(10, MAX_PACKET, ours), 10);
        assert_eq!(send_size(u64::from(INITIAL_WINDOW), 512, ours), 512);
        assert_eq!(
            send_size(u64::from(INITIAL_WINDOW), u32::MAX, ours * 4),
            ours
        );
        assert_eq!(send_size(u64::from(INITIAL_WINDOW), u32::MAX, 3), 3);
    }

    /// Scoped subscriber that records each event's message text, so the
    /// tests below can count `exec.finished` emissions.
    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Msg(Option<String>);
            impl tracing::field::Visit for Msg {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = Some(format!("{value:?}"));
                    }
                }
            }
            let mut m = Msg(None);
            event.record(&mut m);
            if let Some(msg) = m.0 {
                self.0.lock().unwrap().push(msg);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Scoped subscriber that records every field of each event as
    /// `(name, value)` pairs.
    #[derive(Clone, Default)]
    struct Fields(std::sync::Arc<std::sync::Mutex<Vec<EventFields>>>);
    type EventFields = Vec<(String, String)>;

    impl tracing::Subscriber for Fields {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct All(Vec<(String, String)>);
            impl tracing::field::Visit for All {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push((field.name().to_string(), value.to_string()));
                }
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0
                        .push((field.name().to_string(), format!("{value:?}")));
                }
            }
            let mut all = All(Vec::new());
            event.record(&mut all);
            self.0.lock().unwrap().push(all.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    fn exec_finished_carries_request_type_and_pty() {
        // ADR-0038 §9: a shell is an `exec` event, with the two added fields.
        let scope = ChildScope::default();
        let capture = Fields::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            let mut d = Driver::new(bare_key(), &scope);
            d.command = Some(String::new());
            d.request_type = "shell";
            d.on_pty = true;
            d.exit_status = Some(0);
            d.emit_finished();
        });
        let events = seen.lock().unwrap().clone();
        let finished = events
            .iter()
            .find(|e| {
                e.iter()
                    .any(|(k, v)| k == "message" && v == "exec.finished")
            })
            .expect("exec.finished emitted");
        let field = |name: &str| {
            finished
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(field("request_type"), Some("shell"));
        assert_eq!(field("pty"), Some("true"));
        assert_eq!(field("command"), Some(""));
        assert!(field("authenticated_identity").is_some());
        assert!(field("executing_uid").is_some());
        // ADR-0042: the channel byte counts, on every request type.
        assert_eq!(field("bytes_received"), Some("0"));
        assert_eq!(field("bytes_sent"), Some("0"));
        // ADR-0051: a bare key carries no certificate field.
        for name in [
            "cert_key_id",
            "cert_serial",
            "cert_ca_fingerprint",
            "cert_principal",
        ] {
            assert_eq!(field(name), None, "{name}");
        }
    }

    #[test]
    fn exec_events_carry_the_certificate_fields() {
        // ADR-0051: all four, on `exec.finished`. The binary's
        // `audit_log` test checks them on `exec.started` too, end to end.
        let scope = ChildScope::default();
        let capture = Fields::default();
        let seen = capture.0.clone();
        let authenticated = Authenticated {
            certificate: Some(CertIdentity {
                key_id: "alice@example".to_string(),
                serial: "18364758544493064720".to_string(),
                ca_fingerprint: "SHA256:ca".to_string(),
                principal: "alice".to_string(),
            }),
            ..bare_key()
        };
        tracing::subscriber::with_default(capture, || {
            let mut d = Driver::new(authenticated, &scope);
            d.command = Some("true".to_string());
            d.exit_status = Some(0);
            d.emit_finished();
        });
        let events = seen.lock().unwrap().clone();
        let finished = events
            .iter()
            .find(|e| {
                e.iter()
                    .any(|(k, v)| k == "message" && v == "exec.finished")
            })
            .expect("exec.finished emitted");
        let field = |name: &str| {
            finished
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(field("authenticated_identity"), Some("SHA256:test"));
        assert_eq!(field("cert_key_id"), Some("alice@example"));
        assert_eq!(field("cert_serial"), Some("18364758544493064720"));
        assert_eq!(field("cert_ca_fingerprint"), Some("SHA256:ca"));
        assert_eq!(field("cert_principal"), Some("alice"));
    }

    fn finished_count(seen: &std::sync::Mutex<Vec<String>>) -> usize {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|m| *m == "exec.finished")
            .count()
    }

    #[test]
    fn drop_emits_owed_exec_finished_on_unwind() {
        let scope = ChildScope::default();
        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            // AssertUnwindSafe: the Driver is owned by the closure and fully
            // dropped by the unwind; no state observable after the panic.
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut d = Driver::new(bare_key(), &scope);
                d.command = Some("true".to_string());
                panic!("mid-exec panic");
            }));
            assert!(unwound.is_err());
        });
        assert_eq!(finished_count(&seen), 1);
    }

    #[test]
    fn drop_after_normal_emission_does_not_duplicate() {
        let scope = ChildScope::default();
        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            let mut d = Driver::new(bare_key(), &scope);
            d.command = Some("true".to_string());
            d.exit_status = Some(0);
            d.emit_finished();
            drop(d);
        });
        assert_eq!(finished_count(&seen), 1);
    }

    /// A start cancelled while it waited for the launcher (ADR-0064 §2):
    /// the drop writes the missing `exec.started` before `exec.finished`.
    #[test]
    fn a_cancelled_start_still_writes_the_pair() {
        let scope = ChildScope::default();
        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            let mut d = Driver::new(bare_key(), &scope);
            d.command = Some("true".to_string());
            drop(d);
        });
        assert_eq!(*seen.lock().unwrap(), ["exec.started", "exec.finished"]);
    }

    #[test]
    fn drop_without_exec_emits_nothing() {
        let scope = ChildScope::default();
        let capture = Capture::default();
        let seen = capture.0.clone();
        tracing::subscriber::with_default(capture, || {
            drop(Driver::new(bare_key(), &scope));
        });
        assert_eq!(finished_count(&seen), 0);
    }
}
