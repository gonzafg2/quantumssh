//! The RFC 4254 connection layer, scoped by ADR-0023 to exactly **one
//! `session` channel carrying one `exec` request**, then a clean close.
//!
//! The [`drive`] loop is the single owner of all wire I/O for the
//! post-auth phase. The child process runs on the blocking pool
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
use tracing::info;

use crate::exec::{self, ChildChunk, ChildIo};
use crate::transport::{Expect, Session, TransportError};
use crate::wire::{Reader, Writer};

// ---- transport messages that may still appear post-auth ----
/// `SSH_MSG_DISCONNECT` (RFC 4253 §11.1).
const SSH_MSG_DISCONNECT: u8 = 1;

// ---- connection-protocol messages (RFC 4254 §4, §5) ----
const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
const SSH_MSG_REQUEST_FAILURE: u8 = 82;
const SSH_MSG_CHANNEL_OPEN: u8 = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const SSH_MSG_CHANNEL_DATA: u8 = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const SSH_MSG_CHANNEL_EOF: u8 = 96;
const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
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
const INITIAL_WINDOW: u32 = 2 * 1024 * 1024;
/// Phase 1 max packet payload (ADR-0023).
const MAX_PACKET: u32 = 32 * 1024;
/// Batch inbound credit before sending `WINDOW_ADJUST`, so we do not emit
/// one per data packet.
const CREDIT_BATCH: u32 = 1024 * 1024;
/// Our single channel's id; every inbound frame's recipient must equal it.
const LOCAL_CHANNEL: u32 = 0;
/// Conventional exit status when the child could not be spawned.
const EXIT_SPAWN_FAILED: i32 = 127;

/// Bound on a channel-type name (RFC 4254 §5.1).
const CHANNEL_TYPE_BOUND: usize = 64;
/// Bound on a request-type name (RFC 4254 §5.4).
const REQUEST_TYPE_BOUND: usize = 64;
/// Bound on an `exec` command string — one packet's payload.
const COMMAND_BOUND: usize = MAX_PACKET as usize;

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
struct Driver {
    identity: String,
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
    /// Both child output pumps have hit EOF (and the reap reported exit).
    child_out_closed: bool,
    /// The consumed-acks channel has closed (stdin pump finished).
    consumed_closed: bool,
    /// An `exec` was accepted (so an `exec.finished` audit event is owed).
    command_started: bool,
    /// `exec.finished` has been emitted (emit exactly once).
    finished_emitted: bool,
    /// The spawned child, once `exec` is accepted.
    child: Option<ChildIo>,
}

impl Driver {
    fn new(identity: String) -> Self {
        Self {
            identity,
            uid: exec::executing_uid(),
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
            child_out_closed: false,
            consumed_closed: false,
            command_started: false,
            finished_emitted: false,
            child: None,
        }
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
pub(crate) async fn drive<S>(session: &mut Expect<S, Session>) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut d = Driver::new(session.identity().to_string());

    loop {
        // (A) Flush child output while the client's window allows.
        d.flush_output(session).await?;
        // (B) Hand one inbound chunk toward the child's stdin (non-blocking).
        d.handoff_stdin();
        // (C) Return inbound credit once a batch has been consumed.
        d.replenish_window(session).await?;
        // (D) Close sequence when the child is done and output is drained.
        if d.ready_to_close() {
            d.send_terminal(session).await?;
        }
        if d.state == ChannelState::Closed {
            d.emit_finished();
            return Ok(());
        }

        // (E) Wait for the next event. Guards are read into locals first so
        // they do not borrow `d` while the child receivers are borrowed.
        let can_read = true;
        let want_output = d.pending_out.is_none() && d.state.may_emit_output();
        let consumed_active = !d.consumed_closed;
        let (out, consumed) = match d.child.as_mut() {
            Some(c) => (Some(&mut c.out_rx), Some(&mut c.consumed_rx)),
            None => (None, None),
        };

        tokio::select! {
            biased;
            pkt = session.read_packet(), if can_read => {
                let payload = pkt?;
                d.handle_inbound(session, &payload).await?;
            }
            chunk = recv_opt_out(out), if want_output => {
                match chunk {
                    Some(ChildChunk::Stdout(b)) => d.pending_out = Some(PendingOut::new(Stream::Stdout, b)),
                    Some(ChildChunk::Stderr(b)) => d.pending_out = Some(PendingOut::new(Stream::Stderr, b)),
                    Some(ChildChunk::Exited(code)) => {
                        d.exit_status.get_or_insert(code);
                        if d.state == ChannelState::Running {
                            d.state = ChannelState::Draining;
                        }
                    }
                    None => d.child_out_closed = true,
                }
            }
            credit = recv_opt_consumed(consumed), if consumed_active => {
                match credit {
                    Some(n) => d.credit_pending = d.credit_pending.saturating_add(n),
                    None => d.consumed_closed = true,
                }
            }
        }
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

impl Driver {
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
            let cap = self
                .out_window
                .min(u64::from(self.out_max_pkt))
                .min(u64::from(MAX_PACKET));
            // cap ≤ MAX_PACKET, so it always fits a usize.
            let n = p
                .remaining()
                .min(usize::try_from(cap).unwrap_or(usize::MAX));
            if n == 0 {
                break;
            }
            let kind = p.kind;
            let frame = build_data_frame(self.peer_chan, kind, p.take(n));
            session.write_packet(&frame).await?;
            self.out_window -= n as u64;
            if self.pending_out.as_ref().is_some_and(PendingOut::is_empty) {
                self.pending_out = None;
            }
        }
        Ok(())
    }

    /// (B) Hands the buffered inbound chunk to the child's stdin without
    /// blocking. A full pump queue leaves it stashed, which keeps the
    /// inbound read gated and backpressures the wire.
    fn handoff_stdin(&mut self) {
        let Some(child) = self.child.as_ref() else {
            return;
        };
        if let Some(chunk) = self.pending_stdin.take()
            && let Err(returned) = child.try_send_stdin(chunk)
        {
            self.pending_stdin = Some(returned);
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

    /// (D) Sends the terminal sequence. On a normal exit: `exit-status`,
    /// `CHANNEL_EOF`, `CHANNEL_CLOSE`, then awaits the client's close. On
    /// an early client close: just our `CHANNEL_CLOSE`, and we are done.
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
        if let Some(code) = self.exit_status {
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

    /// Emits `exec.finished` exactly once, if an `exec` was started.
    fn emit_finished(&mut self) {
        if self.command_started && !self.finished_emitted {
            self.finished_emitted = true;
            let exit_status = self.exit_status.unwrap_or(EXIT_SPAWN_FAILED);
            info!(
                target: "audit",
                authenticated_identity = %self.identity,
                executing_uid = self.uid,
                exit_status,
                "exec.finished"
            );
        }
    }

    /// Dispatches one inbound packet. Total and fail-closed: the eleven
    /// channel messages plus the post-auth transport messages it must
    /// tolerate; everything else terminates the connection.
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
            SSH_MSG_CHANNEL_REQUEST => self.on_channel_request(session, &mut r).await,
            SSH_MSG_CHANNEL_DATA => self.on_channel_data(session, &mut r).await,
            SSH_MSG_CHANNEL_WINDOW_ADJUST => self.on_window_adjust(session, &mut r).await,
            SSH_MSG_CHANNEL_EOF => self.on_channel_eof(session, &mut r).await,
            SSH_MSG_CHANNEL_CLOSE => self.on_channel_close(session, &mut r).await,
            SSH_MSG_GLOBAL_REQUEST => {
                session.write_packet(&[SSH_MSG_REQUEST_FAILURE]).await?;
                Ok(())
            }
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
        let (Ok(ctype), Ok(sender), Ok(window), Ok(max_pkt)) = (
            r.string(CHANNEL_TYPE_BOUND),
            r.uint32(),
            r.uint32(),
            r.uint32(),
        ) else {
            return Err(session.protocol_disconnect("malformed-channel-open").await);
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
        let (Ok(recipient), Ok(rtype), Ok(want_reply)) =
            (r.uint32(), r.string(REQUEST_TYPE_BOUND), r.boolean())
        else {
            return Err(session
                .protocol_disconnect("malformed-channel-request")
                .await);
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        if rtype == b"exec" && self.state == ChannelState::Idle {
            let Ok(cmd_bytes) = r.string(COMMAND_BOUND) else {
                return Err(session.protocol_disconnect("malformed-exec-request").await);
            };
            let Ok(command) = std::str::from_utf8(cmd_bytes) else {
                return Err(session.protocol_disconnect("non-utf8-command").await);
            };
            self.accept_exec(session, command, want_reply).await
        } else {
            // Any other request (pty-req, shell, env, subsystem, signal,
            // window-change, or a second exec) is refused.
            if want_reply {
                session
                    .write_packet(&build_channel_msg(SSH_MSG_CHANNEL_FAILURE, self.peer_chan))
                    .await?;
            }
            Ok(())
        }
    }

    async fn accept_exec<S>(
        &mut self,
        session: &mut Expect<S, Session>,
        command: &str,
        want_reply: bool,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.command_started = true;
        info!(
            target: "audit",
            authenticated_identity = %self.identity,
            executing_uid = self.uid,
            command = %command,
            "exec.started"
        );
        if want_reply {
            session
                .write_packet(&build_channel_msg(SSH_MSG_CHANNEL_SUCCESS, self.peer_chan))
                .await?;
        }
        if let Ok(mut child) = exec::spawn(command) {
            // Drain any stdin that arrived before the exec.
            while let Some(chunk) = self.pre_exec_stdin.pop_front() {
                let _ = child.try_send_stdin(chunk);
            }
            if self.client_eof {
                child.close_stdin();
            }
            self.child = Some(child);
            self.state = ChannelState::Running;
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
        let (Ok(recipient), Ok(data)) = (r.uint32(), r.string(MAX_PACKET as usize)) else {
            return Err(session.protocol_disconnect("malformed-channel-data").await);
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
        // `data` is bounded to MAX_PACKET by the reader, so this fits a u32.
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        if len > self.in_window {
            return Err(session.protocol_disconnect("inbound-window-exceeded").await);
        }
        self.in_window -= len;
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
        let (Ok(recipient), Ok(add)) = (r.uint32(), r.uint32()) else {
            return Err(session.protocol_disconnect("malformed-window-adjust").await);
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        self.out_window += u64::from(add);
        if self.out_window > u64::from(u32::MAX) {
            return Err(session.protocol_disconnect("window-overflow").await);
        }
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
        let Ok(recipient) = r.uint32() else {
            return Err(session.protocol_disconnect("malformed-channel-eof").await);
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        self.client_eof = true;
        if let Some(child) = self.child.as_mut() {
            child.close_stdin();
        }
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
        let Ok(recipient) = r.uint32() else {
            return Err(session.protocol_disconnect("malformed-channel-close").await);
        };
        if recipient != LOCAL_CHANNEL {
            return Err(session.protocol_disconnect("unknown-channel").await);
        }
        if self.state == ChannelState::ServerClosed {
            // Normal close handshake completes.
            self.state = ChannelState::Closed;
            return Ok(());
        }
        // Client closed first: relinquish exit-status, kill + reap the
        // child, then reply with our CLOSE once it drains.
        self.early_close = true;
        if let Some(child) = self.child.as_mut() {
            child.close_stdin();
            child.kill();
        } else {
            // No child running (Idle or already draining): close now.
            self.child_out_closed = true;
        }
        self.state = ChannelState::Draining;
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
