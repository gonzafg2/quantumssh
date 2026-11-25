//! The network server's side of the launcher protocol (ADR-0063 §4,
//! ADR-0064, ADR-0066).
//!
//! One task owns the socket. It sends every message, keeps a FIFO of the
//! `start`s that wait for an answer, and hands each `started` or
//! `refused` to the oldest (ADR-0063 §2). Connection tasks never touch
//! the socket. Outgoing records wait in a queue until the socket takes
//! them, so the task never stops reading while it waits to write: the
//! launcher, which answers before it reads again, could otherwise block
//! on a full queue in each direction.

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendFlags,
};
use tokio::io::Interest;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::error;

use super::{Exit, Malformed, Refusal, Reply, Request, Session, encode_request, parse_reply};

/// The most descriptors one record carries: a pipe session's three ends.
const MAX_FDS: usize = 3;

/// Account mode exists on Linux only (RFC-0019 §4). Elsewhere the codec
/// still builds, so the flags it needs fall back to none.
#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::empty();
#[cfg(target_os = "linux")]
const RECV_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECV_FLAGS: RecvFlags = RecvFlags::empty();

/// A session the launcher started.
pub(crate) struct Started {
    /// The launcher's identifier for it.
    pub(crate) session: u64,
    /// The UID it runs under, from the launcher's own read of the account
    /// (ADR-0064 §2): the audit records' `executing_uid`.
    pub(crate) uid: u32,
    /// Its stdin, stdout and stderr ends, or its PTY master.
    pub(crate) fds: Vec<OwnedFd>,
    /// How it ended, once the launcher has reaped it.
    pub(crate) exited: oneshot::Receiver<Exit>,
    /// Ends the session unless the connection takes it.
    pub(crate) guard: EndGuard,
}

/// Sends `end` for a session when dropped armed (ADR-0064 §4). A
/// `started` whose connection was cancelled while it waited, at the drain
/// deadline, is dropped unread, and the session still ends.
pub(crate) struct EndGuard {
    ops: mpsc::WeakUnboundedSender<Op>,
    session: Option<u64>,
}

impl EndGuard {
    /// The connection owns the session now, and ends it itself.
    pub(crate) const fn disarm(&mut self) {
        self.session = None;
    }
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        if let (Some(session), Some(ops)) = (self.session, self.ops.upgrade()) {
            let _ = ops.send(Op::Send(encode_request(&Request::End { session })));
        }
    }
}

/// Why a start did not give a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartError {
    /// The launcher refused it (ADR-0063 §2).
    Refused(Refusal),
    /// It started, but its descriptors did not all arrive; the server
    /// ended it (ADR-0063 §4). Or the launcher is gone.
    Failed,
}

enum Op {
    Start {
        record: Vec<u8>,
        fds: usize,
        reply: oneshot::Sender<Result<Started, StartError>>,
    },
    Send(Vec<u8>),
}

/// The handle every connection uses to reach the launcher.
#[derive(Clone, Debug)]
pub struct Client {
    ops: mpsc::UnboundedSender<Op>,
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Op")
    }
}

/// Why the socket task ended: the server can no longer start or end
/// sessions, and exits with failure (ADR-0066 §5).
#[derive(Debug)]
pub enum Fault {
    /// The launcher closed its end, or sent an empty record.
    Closed,
    /// A record or its descriptors broke the protocol.
    Malformed(&'static str),
    /// The socket failed.
    Io(io::Error),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("the launcher closed its socket"),
            Self::Malformed(rule) => write!(f, "launcher fault: {rule}"),
            Self::Io(e) => write!(f, "launcher socket: {e}"),
        }
    }
}

impl Client {
    /// Starts the task that owns `socket`, the server's end of the
    /// `SOCK_SEQPACKET` pair. Its handle resolves when the launcher can no
    /// longer be reached. Call inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// The descriptor cannot be registered with the runtime.
    pub fn spawn(socket: OwnedFd) -> io::Result<(Self, JoinHandle<Fault>)> {
        rustix::io::ioctl_fionbio(&socket, true)?;
        // ponytail: the deprecated constructor, sound as in `exec.rs`: the
        // socket is moved in and never duplicated or closed underneath it.
        #[allow(deprecated)]
        let socket = AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE)?;
        let (ops, rx) = mpsc::unbounded_channel();
        let weak = ops.downgrade();
        Ok((Self { ops }, tokio::spawn(run(socket, rx, weak))))
    }

    /// Asks for a session as `account` and waits for the answer.
    pub(crate) async fn start(
        &self,
        account: &str,
        session: Session<'_>,
    ) -> Result<Started, StartError> {
        let fds = match session {
            Session::Exec { pty: Some(_), .. } | Session::Shell { pty: Some(_) } => 1,
            _ => MAX_FDS,
        };
        let record = encode_request(&Request::Start { account, session });
        let (reply, rx) = oneshot::channel();
        self.ops
            .send(Op::Start { record, fds, reply })
            .map_err(|_| StartError::Failed)?;
        rx.await.unwrap_or(Err(StartError::Failed))
    }

    /// Asks the launcher to end `session` (ADR-0064 §4). It never blocks,
    /// so the synchronous kill guards can call it.
    pub(crate) fn end(&self, session: u64) {
        let _ = self
            .ops
            .send(Op::Send(encode_request(&Request::End { session })));
    }

    /// Tells the launcher the server is ready (ADR-0066 §3).
    pub fn ready(&self) {
        let _ = self.ops.send(Op::Send(encode_request(&Request::Ready)));
    }
}

async fn run(
    socket: AsyncFd<OwnedFd>,
    mut ops: mpsc::UnboundedReceiver<Op>,
    weak: mpsc::WeakUnboundedSender<Op>,
) -> Fault {
    let mut pending: VecDeque<(usize, oneshot::Sender<Result<Started, StartError>>)> =
        VecDeque::new();
    let mut waiters: HashMap<u64, oneshot::Sender<Exit>> = HashMap::new();
    // ponytail: unbounded, as `ops` is; both are bounded by the
    // connections, which max_connections bounds.
    let mut out: VecDeque<Vec<u8>> = VecDeque::new();
    let fault = loop {
        tokio::select! {
            op = ops.recv() => {
                let Some(op) = op else {
                    // Every handle is gone: the server is exiting.
                    return Fault::Closed;
                };
                match op {
                    Op::Start { record, fds, reply } => {
                        pending.push_back((fds, reply));
                        out.push_back(record);
                    }
                    Op::Send(record) => out.push_back(record),
                }
            }
            ready = socket.writable(), if !out.is_empty() => {
                if let Err(e) = ready.and_then(|mut guard| flush(&mut guard, &mut out)) {
                    break Fault::Io(e);
                }
            }
            received = recv(&socket) => {
                let (record, fds, truncated) = match received {
                    Ok(Some(received)) => received,
                    Ok(None) => break Fault::Closed,
                    Err(e) => break Fault::Io(e),
                };
                match dispatch(&record, fds, truncated, &mut pending, &mut waiters, &weak) {
                    Ok(None) => {}
                    // A session whose descriptors did not arrive ends now.
                    Ok(Some(session)) => out.push_back(encode_request(&Request::End { session })),
                    Err(fault) => break fault,
                }
            }
        }
    };
    error!(%fault, "launcher unreachable; the server stops");
    fault
}

/// Applies one record from the launcher (ADR-0063 §4). `Some(session)`
/// asks the caller to end a session that started short of descriptors.
fn dispatch(
    record: &[u8],
    mut fds: Vec<OwnedFd>,
    truncated: bool,
    pending: &mut VecDeque<(usize, oneshot::Sender<Result<Started, StartError>>)>,
    waiters: &mut HashMap<u64, oneshot::Sender<Exit>>,
    weak: &mpsc::WeakUnboundedSender<Op>,
) -> Result<Option<u64>, Fault> {
    let reply = parse_reply(record).map_err(|Malformed(rule)| Fault::Malformed(rule))?;
    match reply {
        Reply::Started { session, uid } => {
            let (expected, tx) = pending
                .pop_front()
                .ok_or(Fault::Malformed("started with no start pending"))?;
            if fds.len() > expected && !truncated {
                return Err(Fault::Malformed(
                    "more descriptors than the session carries",
                ));
            }
            if truncated || fds.len() < expected {
                // Most likely this process's descriptor limit: the session
                // fails alone, and the launcher ends it.
                drop(fds);
                let _ = tx.send(Err(StartError::Failed));
                return Ok(Some(session));
            }
            fds.truncate(expected);
            let (exit_tx, exited) = oneshot::channel();
            waiters.insert(session, exit_tx);
            // A connection already gone drops this unread, and its guard
            // ends the session.
            let _ = tx.send(Ok(Started {
                session,
                uid,
                fds,
                exited,
                guard: EndGuard {
                    ops: weak.clone(),
                    session: Some(session),
                },
            }));
        }
        Reply::Refused(refusal) => {
            if !fds.is_empty() || truncated {
                return Err(Fault::Malformed("descriptors on refused"));
            }
            let (_, tx) = pending
                .pop_front()
                .ok_or(Fault::Malformed("refused with no start pending"))?;
            let _ = tx.send(Err(StartError::Refused(refusal)));
        }
        Reply::Exited { session, exit } => {
            if !fds.is_empty() || truncated {
                return Err(Fault::Malformed("descriptors on exited"));
            }
            if let Some(tx) = waiters.remove(&session) {
                let _ = tx.send(exit);
            }
        }
        Reply::Listener => return Err(Fault::Malformed("listener after startup")),
    }
    Ok(None)
}

/// Sends the queued records until the socket would block, each one
/// leaving the queue only once it is sent.
fn flush(
    guard: &mut AsyncFdReadyGuard<'_, OwnedFd>,
    out: &mut VecDeque<Vec<u8>>,
) -> io::Result<()> {
    while let Some(record) = out.front() {
        let sent = guard.try_io(|fd| {
            rustix::net::sendmsg(
                fd.get_ref(),
                &[IoSlice::new(record)],
                &mut SendAncillaryBuffer::default(),
                SEND_FLAGS,
            )
            .map_err(io::Error::from)
        });
        match sent {
            Ok(result) => {
                result?;
                out.pop_front();
            }
            Err(_would_block) => return Ok(()),
        }
    }
    Ok(())
}

/// One record with its descriptors; `None` for a zero-length read, an end
/// of file or an empty record (ADR-0063 §1).
async fn recv(socket: &AsyncFd<OwnedFd>) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>, bool)>> {
    loop {
        let mut guard = socket.readable().await?;
        let result = guard.try_io(|fd| {
            let mut buf = [0u8; 64];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let msg = rustix::net::recvmsg(
                fd.get_ref(),
                &mut [IoSliceMut::new(&mut buf)],
                &mut control,
                RECV_FLAGS,
            )
            .map_err(io::Error::from)?;
            let mut fds = Vec::new();
            for message in control.drain() {
                if let RecvAncillaryMessage::ScmRights(received) = message {
                    fds.extend(received);
                }
            }
            if msg.flags.contains(ReturnFlags::TRUNC) {
                return Err(io::Error::other("record over its bound"));
            }
            Ok((
                buf[..msg.bytes].to_vec(),
                fds,
                msg.flags.contains(ReturnFlags::CTRUNC),
            ))
        });
        match result {
            Ok(Ok((record, _, _))) if record.is_empty() => return Ok(None),
            Ok(Ok(received)) => return Ok(Some(received)),
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => {}
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::time::Duration;

    use rustix::net::{AddressFamily, SocketFlags, SocketType};

    use super::super::{Exit, encode_reply};
    use super::*;

    fn dev_null() -> OwnedFd {
        std::fs::File::open("/dev/null").expect("/dev/null").into()
    }

    /// A `started` whose connection was cancelled while it waited still
    /// ends its session (ADR-0064 §4).
    #[test]
    fn a_started_nobody_takes_ends_its_session() {
        let (ops, mut rx) = mpsc::unbounded_channel();
        let weak = ops.downgrade();
        let (reply, gone) = oneshot::channel();
        drop(gone);
        let mut pending = VecDeque::from([(MAX_FDS, reply)]);
        let mut waiters = HashMap::new();
        let record = encode_reply(&Reply::Started {
            session: 7,
            uid: 1001,
        });
        let fds = vec![dev_null(), dev_null(), dev_null()];
        let applied = dispatch(&record, fds, false, &mut pending, &mut waiters, &weak);
        assert!(matches!(applied, Ok(None)));
        match rx.try_recv() {
            Ok(Op::Send(end)) => assert_eq!(end, encode_request(&Request::End { session: 7 })),
            other => panic!("no end for the session: {other:?}"),
        }
        drop(ops);
    }

    #[test]
    fn a_disarmed_guard_sends_nothing() {
        let (ops, mut rx) = mpsc::unbounded_channel::<Op>();
        let mut guard = EndGuard {
            ops: ops.downgrade(),
            session: Some(7),
        };
        guard.disarm();
        drop(guard);
        assert!(rx.try_recv().is_err());
    }

    /// The socket task keeps reading while it waits to write. A peer that
    /// sends many records before it reads, as the launcher's replies and
    /// `exited`s can, while the server has many `end`s to send, would
    /// otherwise leave both blocked on a full queue.
    #[tokio::test]
    async fn the_socket_task_reads_while_it_waits_to_write() {
        const N: u64 = 2000;
        let (ours, theirs) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let (client, _fault) = Client::spawn(ours).expect("spawn");
        for session in 0..N {
            client.end(session);
        }
        let launcher = std::thread::spawn(move || {
            for session in 0..N {
                let exited = encode_reply(&Reply::Exited {
                    session,
                    exit: Exit::Code(0),
                });
                rustix::net::send(&theirs, &exited, SendFlags::empty()).expect("send");
            }
            let mut buf = [0u8; 64];
            let mut ends = 0;
            while ends < N {
                let (n, _) =
                    rustix::net::recv(&theirs, &mut buf, RecvFlags::empty()).expect("recv");
                assert_eq!(
                    buf[..n],
                    encode_request(&Request::End { session: ends })[..]
                );
                ends += 1;
            }
            ends
        });
        let joined = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || launcher.join().expect("launcher thread")),
        )
        .await
        .expect("the two sides blocked each other");
        assert_eq!(joined.expect("join"), N);
    }
}
