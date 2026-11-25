//! The root launcher of account mode (RFC-0020 §1; ADR-0064, ADR-0066).
//!
//! It starts the network server as the service account, passes it the
//! listening socket, and then serves its requests on a current-thread
//! runtime, so the process keeps one thread (ADR-0066 §4). It reads
//! nothing from the network and trusts nothing the server sends
//! (ADR-0063 §3).

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
};
use rustix::process::{Pid, Signal};
use tokio::io::Interest;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;
use tracing::{error, warn};

use super::{
    Exit, MAX_RECORD, Malformed, PtyRequest, Refusal, Reply, Request, SERVER_ARG, Session,
    encode_reply, parse_request,
};
use crate::account;
use crate::exec::wait_exit;
use crate::pty::{self, Modes, Size};
use crate::session_helper::{HELPER_ARG, HelperArgs, Run};

/// This binary, re-executed for the server and for every session.
const SELF_EXE: &str = "/proc/self/exe";

/// ADR-0065 §3's default `PATH`: OpenSSH portable's, built with the
/// default prefix.
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin";

/// ADR-0038 §7's hang-up grace before the group kill.
const HANGUP_GRACE: Duration = Duration::from_secs(1);

/// What the launcher tells the service manager (ADR-0066 §3, §4).
#[derive(Debug, Clone, Copy)]
pub enum Notice {
    /// The server is ready: `READY=1`.
    Ready,
    /// The first stop request: `STOPPING=1` with the drain deadline.
    Stopping(Duration),
}

/// What the binary hands the launcher once its startup checks pass
/// (ADR-0066 §1).
pub struct Options {
    /// `server.listen`, bound as root.
    pub listener: std::net::TcpListener,
    /// The binary's own arguments, passed on to the server.
    pub server_args: Vec<OsString>,
    /// The service account the server runs as.
    pub service_uid: u32,
    /// Its primary GID.
    pub service_gid: u32,
    /// The listed accounts.
    pub accounts: HashSet<String>,
    /// `limits.max_connections`: the most live sessions (ADR-0064 §1).
    pub max_sessions: usize,
    /// The drain deadline, for `EXTEND_TIMEOUT_USEC=` (ADR-0066 §4).
    pub drain: Duration,
    /// Sends a notice to the service manager.
    pub notify: Box<dyn Fn(Notice) + Send>,
}

/// A live session: its leader, unreaped until its `exited` is sent.
struct LiveSession {
    leader: Child,
    pid: Pid,
    pty: bool,
    hanging_up: bool,
}

/// Runs the launcher until the server exits, and returns the process's
/// exit status (ADR-0066 §5).
#[must_use]
pub fn run(options: Options) -> i32 {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(serve(options)),
        Err(e) => {
            error!(error = %e, "launcher runtime failed to start");
            1
        }
    }
}

async fn serve(options: Options) -> i32 {
    // The handlers exist before the server does, so no stop request is
    // lost (ADR-0066 §4).
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        error!("launcher cannot install its signal handlers");
        return 1;
    };
    let (mut server, socket) = match start_server(&options) {
        Ok(started) => started,
        Err(e) => {
            error!(error = %e, "launcher cannot start the network server");
            return 1;
        }
    };
    let Some(server_pid) = pid_of(&server) else {
        return 1;
    };
    let mut launcher = Launcher {
        options,
        sessions: HashMap::new(),
        next_id: 1,
        ready: false,
    };
    let mut exits: JoinSet<u64> = JoinSet::new();
    let mut graces: JoinSet<u64> = JoinSet::new();
    let server_exit = wait_exit(server_pid);
    tokio::pin!(server_exit);
    let mut reading = true;
    let mut stopping = false;
    // Replies wait here until the socket takes them, so the loop keeps
    // reaping and handling signals while it waits to write. ADR-0063 §2:
    // the next request is read only once every reply has gone, so this
    // holds at most one reply, plus one `exited` per session.
    let mut out = Outbox::new();
    loop {
        tokio::select! {
            () = &mut server_exit => break,
            _ = term.recv() => launcher.stop(server_pid, &mut stopping),
            _ = int.recv() => launcher.stop(server_pid, &mut stopping),
            Some(Ok(id)) = exits.join_next(), if !exits.is_empty() => {
                launcher.leader_exited(id, reading.then_some(&mut out));
            }
            Some(Ok(id)) = graces.join_next(), if !graces.is_empty() => {
                launcher.grace_over(id);
            }
            ready = socket.writable(), if reading && !out.is_empty() => {
                if let Err(e) = ready.and_then(|mut guard| flush(&mut guard, &mut out)) {
                    // A reply that cannot be sent would pair the server's
                    // next answer with the wrong start (ADR-0063 §2), so
                    // the service ends, as for a malformed record (§3).
                    error!(error = %e, "launcher cannot answer the network server");
                    let _ = rustix::process::kill_process(server_pid, Signal::KILL);
                    reading = false;
                    out.clear();
                }
            }
            received = recv(&socket), if reading && out.is_empty() => {
                let malformed = match received {
                    Ok(Received::Record(record)) => launcher
                        .request(&record, &mut out, &mut exits, &mut graces)
                        .err(),
                    Ok(Received::Broken(rule)) => Some(Malformed(rule)),
                    // ADR-0063 §1: an end of file or an empty record. Stop
                    // reading and wait for the server's exit.
                    Ok(Received::Closed) => {
                        reading = false;
                        None
                    }
                    Err(e) => {
                        warn!(error = %e, "launcher socket failed");
                        reading = false;
                        None
                    }
                };
                if let Some(Malformed(rule)) = malformed {
                    // ADR-0063 §3: one record naming the rule, then the
                    // service ends; the server is not trusted to drain.
                    error!(rule, "malformed record from the network server");
                    let _ = rustix::process::kill_process(server_pid, Signal::KILL);
                    reading = false;
                }
            }
        }
    }
    let status = server.wait();
    launcher.end_all();
    match status {
        Ok(status) if status.success() && launcher.ready => 0,
        _ => 1,
    }
}

/// Replies to the server, each with its descriptors, waiting for the
/// socket.
type Outbox = VecDeque<(Vec<u8>, Vec<OwnedFd>)>;

struct Launcher {
    options: Options,
    sessions: HashMap<u64, LiveSession>,
    next_id: u64,
    ready: bool,
}

impl Launcher {
    /// ADR-0066 §4: the first signal notifies and forwards `SIGTERM`; every
    /// later one forwards it again, which ADR-0028 reads as "drain now".
    fn stop(&self, server: Pid, stopping: &mut bool) {
        if !*stopping {
            *stopping = true;
            (self.options.notify)(Notice::Stopping(self.options.drain));
        }
        let _ = rustix::process::kill_process(server, Signal::TERM);
    }

    fn request(
        &mut self,
        record: &[u8],
        out: &mut Outbox,
        exits: &mut JoinSet<u64>,
        graces: &mut JoinSet<u64>,
    ) -> Result<(), Malformed> {
        match parse_request(record)? {
            Request::Ready => {
                if self.ready {
                    return Err(Malformed("a second ready"));
                }
                self.ready = true;
                (self.options.notify)(Notice::Ready);
            }
            Request::Start { account, session } => {
                let (reply, fds) = match self.start(account, session) {
                    Ok((id, uid, fds, pid)) => {
                        exits.spawn(async move {
                            wait_exit(pid).await;
                            id
                        });
                        (Reply::Started { session: id, uid }, fds)
                    }
                    Err(refusal) => (Reply::Refused(refusal), Vec::new()),
                };
                out.push_back((encode_reply(&reply), fds));
            }
            Request::End { session } => self.end(session, graces),
        }
        Ok(())
    }

    /// ADR-0064 §2, in one turn: check the account, the bound, create the
    /// descriptors, start the helper, close the launcher's copies.
    fn start(
        &mut self,
        account: &str,
        session: Session<'_>,
    ) -> Result<(u64, u32, Vec<OwnedFd>, Pid), Refusal> {
        if !self.options.accounts.contains(account) {
            return Err(Refusal::NotListed);
        }
        let record = account::resolve(account).map_err(|_| Refusal::Unresolved)?;
        if record.uid == 0 || record.uid == self.options.service_uid {
            return Err(Refusal::Unresolved);
        }
        if self.sessions.len() >= self.options.max_sessions {
            return Err(Refusal::Limit);
        }
        let (run, pty) = match session {
            Session::Exec { command, pty } => (
                Run::Exec(OsString::from(std::ffi::OsStr::from_bytes(command))),
                pty,
            ),
            Session::Shell { pty } => (Run::Shell, pty),
            Session::Sftp => (Run::Sftp, None),
        };
        let args = HelperArgs {
            run,
            pty: pty.is_some(),
            uid: record.uid,
            gid: record.gid,
            groups: record.groups.clone(),
            home: record.home.clone(),
            program: record.shell.clone(),
        };
        let mut command = Command::new(SELF_EXE);
        command.arg(HELPER_ARG).args(args.to_args()).env_clear();
        command
            .env("HOME", &record.home)
            .env("USER", &record.name)
            .env("LOGNAME", &record.name)
            .env("SHELL", &record.shell)
            .env("PATH", DEFAULT_PATH);
        for (key, value) in std::env::vars_os() {
            if key
                .to_str()
                .is_some_and(|k| k == "LANG" || k.starts_with("LC_"))
            {
                command.env(key, value);
            }
        }
        let (leader, server_ends) = match pty {
            Some(request) => spawn_on_pty(&mut command, request, record.uid)?,
            None => spawn_on_pipes(&mut command)?,
        };
        drop(command);
        let Some(pid) = pid_of(&leader) else {
            return Err(Refusal::Helper);
        };
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(
            id,
            LiveSession {
                leader,
                pid,
                pty: args.pty,
                hanging_up: false,
            },
        );
        Ok((id, record.uid, server_ends, pid))
    }

    /// ADR-0064 §4: ADR-0038 §7's kill sequence, for a session still held
    /// unreaped; an identifier not held is ignored.
    fn end(&mut self, id: u64, graces: &mut JoinSet<u64>) {
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        if session.pty {
            if !session.hanging_up {
                session.hanging_up = true;
                let _ = rustix::process::kill_process(session.pid, Signal::HUP);
                graces.spawn(async move {
                    tokio::time::sleep(HANGUP_GRACE).await;
                    id
                });
            }
        } else {
            kill_group(session.pid);
        }
    }

    fn grace_over(&self, id: u64) {
        if let Some(session) = self.sessions.get(&id) {
            kill_group(session.pid);
        }
    }

    /// ADR-0064 §3: the group kill if a hang-up is in progress, then the
    /// reap, then `exited`.
    /// `out` is `None` once the server's socket is no longer read.
    fn leader_exited(&mut self, id: u64, out: Option<&mut Outbox>) {
        let Some(mut session) = self.sessions.remove(&id) else {
            return;
        };
        if session.hanging_up {
            kill_group(session.pid);
        }
        let exit = session.leader.wait().map_or(Exit::Code(127), exit_of);
        if let Some(out) = out {
            out.push_back((
                encode_reply(&Reply::Exited { session: id, exit }),
                Vec::new(),
            ));
        }
    }

    /// ADR-0064 §5: every session ends at once, and is reaped.
    fn end_all(&mut self) {
        for (_, mut session) in self.sessions.drain() {
            kill_group(session.pid);
            let _ = session.leader.wait();
        }
    }
}

/// `SIGKILL` to the leader's process group and to the leader. Called only
/// while the leader is unreaped, so neither ID can have been reused.
fn kill_group(pid: Pid) {
    let _ = rustix::process::kill_process_group(pid, Signal::KILL);
    let _ = rustix::process::kill_process(pid, Signal::KILL);
}

fn exit_of(status: ExitStatus) -> Exit {
    match (status.code(), status.signal()) {
        (Some(code), _) => Exit::Code(u32::try_from(code).unwrap_or(127)),
        (None, Some(signal)) => Exit::Signal {
            signal: u32::try_from(signal).unwrap_or(0),
            core_dumped: status.core_dumped(),
        },
        (None, None) => Exit::Code(127),
    }
}

fn pid_of(child: &Child) -> Option<Pid> {
    i32::try_from(child.id()).ok().and_then(Pid::from_raw)
}

/// Three pipes: the helper gets stdin's read end and the write ends of
/// stdout and stderr, and the server the other three (ADR-0064 §2).
fn spawn_on_pipes(command: &mut Command) -> Result<(Child, Vec<OwnedFd>), Refusal> {
    let pipes = || std::io::pipe().map_err(|_| Refusal::Helper);
    let (stdin_r, stdin_w) = pipes()?;
    let (stdout_r, stdout_w) = pipes()?;
    let (stderr_r, stderr_w) = pipes()?;
    command
        .stdin(Stdio::from(OwnedFd::from(stdin_r)))
        .stdout(Stdio::from(OwnedFd::from(stdout_w)))
        .stderr(Stdio::from(OwnedFd::from(stderr_w)));
    let leader = command.spawn().map_err(|_| Refusal::Helper)?;
    Ok((
        leader,
        vec![stdin_w.into(), stdout_r.into(), stderr_r.into()],
    ))
}

/// The PTY, allocated as root for the account (ADR-0064 §2): the slave is
/// the helper's stdio, and the server gets the master.
fn spawn_on_pty(
    command: &mut Command,
    request: PtyRequest<'_>,
    owner: u32,
) -> Result<(Child, Vec<OwnedFd>), Refusal> {
    let modes = Modes::parse(request.modes).map_err(|_| Refusal::Pty)?;
    let size = Size {
        cols: request.size.cols,
        rows: request.size.rows,
        width_px: request.size.width_px,
        height_px: request.size.height_px,
    };
    let pair = pty::allocate_for(&modes, size, Some(owner)).map_err(|_| Refusal::Pty)?;
    let term = std::str::from_utf8(request.term).map_err(|_| Refusal::Pty)?;
    if !term.is_empty() {
        command.env("TERM", term);
    }
    let dup = |fd: &OwnedFd| fd.try_clone().map_err(|_| Refusal::Pty);
    command
        .stdin(Stdio::from(dup(&pair.slave)?))
        .stdout(Stdio::from(dup(&pair.slave)?))
        .stderr(Stdio::from(pair.slave));
    let leader = command.spawn().map_err(|_| Refusal::Helper)?;
    Ok((leader, vec![pair.master]))
}

/// ADR-0066 §2: the socket pair, then the server as the service account,
/// with its end as stdin, a cleared environment and its own process group;
/// then `listener` with the listening socket.
fn start_server(options: &Options) -> io::Result<(Child, AsyncFd<OwnedFd>)> {
    let (ours, theirs) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let mut command = Command::new(SELF_EXE);
    command
        .arg(SERVER_ARG)
        .args(&options.server_args)
        .uid(options.service_uid)
        .gid(options.service_gid)
        .env_clear()
        .stdin(Stdio::from(theirs))
        .process_group(0);
    let server = command.spawn()?;
    drop(command);
    rustix::net::sendmsg(
        &ours,
        &[IoSlice::new(&encode_reply(&Reply::Listener))],
        &mut ancillary(&[options.listener.as_fd()]).buffer(),
        SendFlags::NOSIGNAL,
    )?;
    rustix::io::ioctl_fionbio(&ours, true)?;
    // ponytail: the deprecated constructor, sound as in `exec.rs`: the
    // socket is moved in and never duplicated or closed underneath it.
    #[allow(deprecated)]
    let socket = AsyncFd::with_interest(ours, Interest::READABLE | Interest::WRITABLE)?;
    Ok((server, socket))
}

/// Space for one `SCM_RIGHTS` message of up to three descriptors.
struct Ancillary<'fd> {
    space: [std::mem::MaybeUninit<u8>; rustix::cmsg_space!(ScmRights(3))],
    fds: &'fd [std::os::fd::BorrowedFd<'fd>],
}

const fn ancillary<'fd>(fds: &'fd [std::os::fd::BorrowedFd<'fd>]) -> Ancillary<'fd> {
    Ancillary {
        space: [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))],
        fds,
    }
}

impl<'fd> Ancillary<'fd> {
    fn buffer(&mut self) -> SendAncillaryBuffer<'_, 'fd, 'fd> {
        let mut buffer = SendAncillaryBuffer::new(&mut self.space);
        if !self.fds.is_empty() {
            buffer.push(SendAncillaryMessage::ScmRights(self.fds));
        }
        buffer
    }
}

/// Sends the queued replies until the socket would block. Each one, with
/// its descriptors, leaves the queue only once it is sent; the launcher's
/// copies close then (ADR-0064 §2).
fn flush(guard: &mut AsyncFdReadyGuard<'_, OwnedFd>, out: &mut Outbox) -> io::Result<()> {
    while let Some((record, fds)) = out.front() {
        let borrowed: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
        let mut control = ancillary(&borrowed);
        let sent = guard.try_io(|fd| {
            rustix::net::sendmsg(
                fd.get_ref(),
                &[IoSlice::new(record)],
                &mut control.buffer(),
                SendFlags::NOSIGNAL,
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

/// What one read from the server's socket brought.
enum Received {
    /// A record, for the parser.
    Record(Vec<u8>),
    /// A zero-length read: an end of file or an empty record (ADR-0063 §1).
    Closed,
    /// A record that broke the framing (ADR-0063 §3).
    Broken(&'static str),
}

/// One record from the server. The launcher receives no descriptor: any
/// the server sends is closed by the kernel and sets `MSG_CTRUNC`, which is
/// malformed (ADR-0063 §3), as is a record over its bound (`MSG_TRUNC`).
async fn recv(socket: &AsyncFd<OwnedFd>) -> io::Result<Received> {
    let mut buf = vec![0u8; MAX_RECORD + 1];
    loop {
        let mut guard = socket.readable().await?;
        match guard.try_io(|fd| {
            let mut control = RecvAncillaryBuffer::default();
            rustix::net::recvmsg(
                fd.get_ref(),
                &mut [IoSliceMut::new(&mut buf)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            )
            .map_err(io::Error::from)
        }) {
            Ok(Ok(msg)) if msg.flags.contains(ReturnFlags::CTRUNC) => {
                return Ok(Received::Broken("descriptors from the server"));
            }
            Ok(Ok(msg)) if msg.flags.contains(ReturnFlags::TRUNC) || msg.bytes > MAX_RECORD => {
                return Ok(Received::Broken("record over its bound"));
            }
            Ok(Ok(msg)) if msg.bytes == 0 => return Ok(Received::Closed),
            Ok(Ok(msg)) => return Ok(Received::Record(buf[..msg.bytes].to_vec())),
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};

    use super::*;

    fn dev_null() -> OwnedFd {
        std::fs::File::open("/dev/null").expect("/dev/null").into()
    }

    /// The replies leave in order, each with its descriptors, and one that
    /// cannot be sent is an error that stays queued: the caller then ends
    /// the service (ADR-0063 §2).
    #[tokio::test]
    async fn flush_sends_in_order_and_fails_on_a_closed_peer() {
        let (ours, theirs) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        rustix::io::ioctl_fionbio(&ours, true).expect("nonblocking");
        #[allow(deprecated)]
        let socket = AsyncFd::with_interest(ours, Interest::READABLE | Interest::WRITABLE)
            .expect("register");
        let mut out = Outbox::from([
            (b"first".to_vec(), vec![dev_null()]),
            (b"second".to_vec(), Vec::new()),
        ]);
        let mut guard = socket.writable().await.expect("writable");
        flush(&mut guard, &mut out).expect("flush");
        assert!(out.is_empty());
        let mut buf = [0u8; 16];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let msg = rustix::net::recvmsg(
            &theirs,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::empty(),
        )
        .expect("recvmsg");
        assert_eq!(&buf[..msg.bytes], b"first");
        assert_eq!(
            control
                .drain()
                .filter(|m| matches!(m, rustix::net::RecvAncillaryMessage::ScmRights(_)))
                .count(),
            1
        );
        let (n, _) = rustix::net::recv(&theirs, &mut buf, RecvFlags::empty()).expect("recv");
        assert_eq!(&buf[..n], b"second");

        drop(theirs);
        out.push_back((b"third".to_vec(), Vec::new()));
        let mut guard = socket.writable().await.expect("writable");
        assert!(flush(&mut guard, &mut out).is_err());
        assert_eq!(out.len(), 1);
    }
}
