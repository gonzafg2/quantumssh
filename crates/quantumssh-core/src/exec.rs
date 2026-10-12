//! Single-command execution for the M5 channel layer (ADR-0023).
//!
//! The command runs through a fixed shell — `/bin/sh -c "<command>"` —
//! because SSH `exec` delivers one opaque string and the service
//! account's login shell is `/usr/sbin/nologin` (ADR-0016). The child
//! runs under the service-account UID with a **sanitised** environment
//! (ADR-0016 Decision: allowlist `PATH HOME USER SHELL LANG LC_*`); no
//! per-user resolution (threat model §8.12).
//!
//! Concurrency (ADR-0038 §6): `tokio::process`. Each child gets three
//! stdio pump tasks and one reap task, all spawned into the connection's
//! [`ChildScope`] — outside the connection future that a shutdown
//! deadline cancels — and talking to the async channel driver only
//! through Tokio channels. The reap task waits for the child's exit
//! **without reaping it**, then reaps it and removes it from the scope's
//! registry in one critical section, so the scope's synchronous kill
//! guard only ever signals a PID that is still reserved.

// Private module: `pub(crate)` items are the surface the channel driver
// uses. `redundant_pub_crate` would prefer `pub`, but `pub(crate)` states
// the intent — nothing here is public API.
#![allow(clippy::redundant_pub_crate)]

use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rustix::process::{Pid, Signal};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};

/// Outbound chunk size — matches the channel `MAX_PACKET` (ADR-0023) so
/// a single chunk never exceeds one SSH packet's payload.
const CHUNK: usize = 32 * 1024;
/// Child-output queue bound: `OUT_QUEUE × CHUNK` caps the OS-side
/// read-ahead held off the wire when the client window is closed.
const OUT_QUEUE: usize = 8;
/// Pending-stdin queue bound.
const STDIN_QUEUE: usize = 8;
/// Exit-wait interval when no `SIGCHLD` stream can be registered — the
/// fallback's upper bound on exit-detection latency.
const REAP_POLL: Duration = Duration::from_millis(20);
/// Conventional exit status when the wait itself fails or the child is
/// signalled (`exit-signal` detail is deferred to Phase 2 — ADR-0023).
const EXIT_WAIT_FAILED: i32 = 127;

/// A message from the child's tasks to the async driver. The reap task
/// sends [`ChildChunk::Exited`] **before** dropping its sender, so it
/// always arrives before `out_rx` closes (`recv` returns `None`) — the
/// driver can drain all output and still observe the exit, in any
/// scheduling order.
pub(crate) enum ChildChunk {
    /// Bytes from the child's stdout (frame as `CHANNEL_DATA`).
    Stdout(Vec<u8>),
    /// Bytes from the child's stderr (frame as `CHANNEL_EXTENDED_DATA`).
    Stderr(Vec<u8>),
    /// The child exited with this status code.
    Exited(i32),
}

/// The async-side handles to a spawned child. The driver `select!`s over
/// `out_rx` / `consumed_rx` and feeds stdin via [`ChildIo::try_send_stdin`].
pub(crate) struct ChildIo {
    /// stdout/stderr chunks (each ≤ [`CHUNK`]) plus the terminal
    /// [`ChildChunk::Exited`]; `None` once all the child's tasks have
    /// finished.
    pub out_rx: mpsc::Receiver<ChildChunk>,
    /// Bytes the child has actually read from stdin — drives inbound
    /// window replenishment (ADR-0023).
    pub consumed_rx: mpsc::UnboundedReceiver<u32>,
    /// Hands stdin chunks to the stdin pump; `None` once stdin is closed
    /// (client `CHANNEL_EOF` or early `CHANNEL_CLOSE`), which sends the
    /// child EOF on its stdin.
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// The kill request to the reap task: sending it or dropping it
    /// requests the kill. The reap task kills through its **owned
    /// `Child` handle**, while the child is unreaped — never by a PID the
    /// OS may have reused.
    kill_tx: Option<oneshot::Sender<()>>,
    /// The three stdio pumps.
    pumps: [AbortHandle; 3],
}

impl Drop for ChildIo {
    /// Guarantees no child outlives its channel: any drop — including an
    /// abrupt transport failure that unwinds `Driver` without a
    /// cooperative `CHANNEL_CLOSE` — drops the kill request's sender,
    /// which the reap task takes as a kill. The pumps are aborted, since
    /// a process outside the child's group could keep a pipe open and a
    /// pump blocked on it.
    fn drop(&mut self) {
        for pump in &self.pumps {
            pump.abort();
        }
    }
}

impl ChildIo {
    /// Requests the child be killed (client-initiated early close). The
    /// reap task performs the kill through its owned `Child` handle.
    pub(crate) fn kill(&mut self) {
        if let Some(tx) = self.kill_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Closes the child's stdin (drops the sender → the stdin pump
    /// finishes → `ChildStdin` is dropped → the child reads EOF).
    pub(crate) fn close_stdin(&mut self) {
        self.stdin_tx = None;
    }

    /// Hands one chunk toward the child's stdin **without blocking**.
    /// Returns `Err(chunk)` if the pump's queue is full (the driver
    /// re-stashes it, which gates the inbound arm → wire backpressure);
    /// `Ok(())` if queued, or if stdin is already closed (chunk dropped).
    pub(crate) fn try_send_stdin(&self, chunk: Vec<u8>) -> Result<(), Vec<u8>> {
        self.stdin_tx.as_ref().map_or(Ok(()), |tx| {
            tx.try_send(chunk).map_err(|e| match e {
                mpsc::error::TrySendError::Full(c) | mpsc::error::TrySendError::Closed(c) => c,
            })
        })
    }
}

/// The children of one connection (ADR-0038 §6), owned by the
/// connection task outside the connection future that a shutdown
/// deadline cancels.
///
/// Every task of a child runs in this scope's [`JoinSet`], which the
/// connection task awaits through [`ChildScope::join`] before it logs
/// `connection.closed`. The scope's `Drop` is the **synchronous kill
/// guard** for the path where the connection task itself is aborted
/// (ADR-0028's last resort): dropping a `JoinSet` only requests that its
/// tasks abort, so the guard signals every registered child by PID and
/// then by process group, with no await.
#[derive(Default)]
pub(crate) struct ChildScope {
    tasks: Mutex<JoinSet<()>>,
    /// PIDs of the connection's unreaped children, running or zombie.
    live: Arc<Mutex<Vec<Pid>>>,
}

impl ChildScope {
    fn spawn<F>(&self, task: F) -> AbortHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        lock(&self.tasks).spawn(task)
    }

    /// Waits until every child of the scope is reaped and its pumps have
    /// finished. Called once the connection future has ended, so nothing
    /// spawns into the scope meanwhile.
    pub(crate) async fn join(&self) {
        let mut tasks = std::mem::take(&mut *lock(&self.tasks));
        while tasks.join_next().await.is_some() {}
    }
}

impl Drop for ChildScope {
    fn drop(&mut self) {
        let live = lock(&self.live);
        for &pid in live.iter() {
            // By PID, then by group: a child not yet leading its own group
            // (ADR-0038 §6, the PTY helper before `setsid`) is reached by
            // the first, the rest of its group by the second. `ESRCH` is
            // expected from either and ignored. Holding the lock keeps the
            // PID unreaped, so it cannot have been reused.
            let _ = rustix::process::kill_process(pid, Signal::KILL);
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
    }
}

/// Locks a mutex, recovering the data if a holder panicked: the kill
/// guards must run on every path, including an unwind.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The unreaped child, owned by its reap task. Registered in its scope
/// from spawn until [`Reaper::try_reap`] reaps it.
struct Reaper {
    /// `Some` while the child is unreaped (running or zombie).
    child: Option<Child>,
    /// The leader's PID, which is also its process-group ID.
    pid: Pid,
    /// The scope's registry.
    live: Arc<Mutex<Vec<Pid>>>,
}

impl Reaper {
    fn register(child: Child, pid: Pid, live: Arc<Mutex<Vec<Pid>>>) -> Self {
        lock(&live).push(pid);
        Self {
            child: Some(child),
            pid,
            live,
        }
    }

    /// Waits for the child's exit, applying a kill request on the way,
    /// then reaps it. Returns the exit code.
    async fn run(mut self, mut kill_rx: oneshot::Receiver<()>) -> i32 {
        let exit = wait_exit(self.pid);
        tokio::pin!(exit);
        let mut kill_pending = true;
        loop {
            tokio::select! {
                () = &mut exit => {
                    if let Some(code) = self.try_reap() {
                        return code;
                    }
                    exit.set(wait_exit(self.pid));
                }
                // A sent request and a dropped sender both mean kill.
                _ = &mut kill_rx, if kill_pending => {
                    kill_pending = false;
                    if let Some(child) = self.child.as_mut() {
                        kill_group(child, self.pid);
                    }
                }
            }
        }
    }

    /// Reaps the child and deregisters it in one critical section, so the
    /// scope's kill guard never signals a reaped PID. `None` if the child
    /// has not exited yet.
    fn try_reap(&mut self) -> Option<i32> {
        let mut live = lock(&self.live);
        let code = match self.child.as_mut()?.try_wait() {
            Ok(None) => return None,
            Ok(Some(status)) => code_of(status),
            Err(_) => EXIT_WAIT_FAILED,
        };
        self.child = None;
        live.retain(|&p| p != self.pid);
        drop(live);
        Some(code)
    }
}

impl Drop for Reaper {
    /// The reap task was dropped with the child unreaped (its connection
    /// task aborted, or the runtime shutting down): kill it while its PID
    /// is still reserved and deregister it, under the lock, before the
    /// `Child` passes to tokio's orphan reaping.
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let mut live = lock(&self.live);
            kill_group(child, self.pid);
            live.retain(|&p| p != self.pid);
        }
    }
}

/// `SIGKILL` to the child's process group and to the leader through the
/// owned handle. Called only while the leader is unreaped, so its PID —
/// also its process-group ID — cannot have been reused (ADR-0016).
fn kill_group(child: &mut Child, pid: Pid) {
    let _ = rustix::process::kill_process_group(pid, Signal::KILL);
    let _ = child.start_kill();
}

/// Resolves once the child has exited, **without reaping it**
/// (ADR-0038 §6): on Linux through a pidfd, which becomes readable at
/// exit; elsewhere, or if that fails, by a `waitid` peek woken by
/// `SIGCHLD`.
async fn wait_exit(pid: Pid) {
    #[cfg(target_os = "linux")]
    if let Ok(fd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::NONBLOCK)
        && let Ok(fd) = tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE)
        && fd.readable().await.is_ok()
    {
        return;
    }
    // Registered before the first peek, so an exit between a peek and the
    // wait still wakes it.
    let mut sigchld = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).ok();
    while !has_exited(pid) {
        let woken = match sigchld.as_mut() {
            Some(stream) => stream.recv().await.is_some(),
            None => false,
        };
        if !woken {
            sigchld = None;
            tokio::time::sleep(REAP_POLL).await;
        }
    }
}

/// `waitid(EXITED | NOHANG | NOWAIT)`: true once the child has exited,
/// which leaves it a zombie. An error also ends the wait; the reap then
/// reports it.
fn has_exited(pid: Pid) -> bool {
    use rustix::process::{WaitId, WaitIdOptions, waitid};
    !matches!(
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT
        ),
        Ok(None)
    )
}

/// The OS UID the child runs under — the `executing_uid` audit field
/// (ADR-0016). A constant per process in Phase 1 (service-account model).
pub(crate) fn executing_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Spawns `/bin/sh -c "<command>"` with a sanitised environment and
/// wires its stdio to the returned channels. The pumps and the reap task
/// run in `scope` (ADR-0038 §6).
///
/// # Errors
///
/// [`std::io::Error`] if the child cannot be spawned.
pub(crate) fn spawn(command: &str, scope: &ChildScope) -> std::io::Result<ChildIo> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(command);
    sanitise_env(&mut cmd);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put the child in its own process group (it becomes the leader, so
    // pgid == pid). On kill we signal the whole group, not just `/bin/sh`:
    // a shell that fork+execs its command (as dash does) would otherwise
    // leave the grandchild (e.g. `sleep`) running and holding the stdio
    // pipes open, so the pumps never see EOF and the channel never closes.
    cmd.process_group(0);
    let mut child = cmd.spawn()?;

    let child_stdin = child.stdin.take().expect("stdin piped");
    let child_stdout = child.stdout.take().expect("stdout piped");
    let child_stderr = child.stderr.take().expect("stderr piped");
    // A child spawned just now is unreaped, so it has a PID.
    let Some(pid) = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
    else {
        let _ = child.start_kill();
        return Err(std::io::Error::other("spawned child has no pid"));
    };
    let reaper = Reaper::register(child, pid, Arc::clone(&scope.live));

    let (out_tx, out_rx) = mpsc::channel::<ChildChunk>(OUT_QUEUE);
    let (consumed_tx, consumed_rx) = mpsc::unbounded_channel::<u32>();
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_QUEUE);
    let (kill_tx, kill_rx) = oneshot::channel();

    let pumps = [
        scope.spawn(pump_output(
            child_stdout,
            out_tx.clone(),
            ChildChunk::Stdout,
        )),
        scope.spawn(pump_output(
            child_stderr,
            out_tx.clone(),
            ChildChunk::Stderr,
        )),
        scope.spawn(pump_stdin(child_stdin, stdin_rx, consumed_tx)),
    ];
    // The status goes out on the output channel before the sender drops,
    // so it precedes the channel's close.
    scope.spawn(async move {
        let code = reaper.run(kill_rx).await;
        let _ = out_tx.send(ChildChunk::Exited(code)).await;
    });

    Ok(ChildIo {
        out_rx,
        consumed_rx,
        stdin_tx: Some(stdin_tx),
        kill_tx: Some(kill_tx),
        pumps,
    })
}

/// Forwards one output pipe in chunks of at most [`CHUNK`]. `send` waits
/// while the queue is full, which backpressures the child's pipe.
async fn pump_output<R>(mut pipe: R, tx: mpsc::Sender<ChildChunk>, frame: fn(Vec<u8>) -> ChildChunk)
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.send(frame(buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Writes stdin chunks to the child. `write_all` waits until the child
/// reads, which backpressures the wire through the gated inbound window;
/// each consumed chunk's length lets the driver replenish that window
/// (ADR-0023). Dropping the pipe at the end closes the child's stdin.
async fn pump_stdin(
    mut pipe: ChildStdin,
    mut rx: mpsc::Receiver<Vec<u8>>,
    consumed: mpsc::UnboundedSender<u32>,
) {
    while let Some(chunk) = rx.recv().await {
        if pipe.write_all(&chunk).await.is_err() || pipe.flush().await.is_err() {
            break;
        }
        match u32::try_from(chunk.len()) {
            Ok(n) if consumed.send(n).is_ok() => {}
            _ => break,
        }
    }
}

/// ADR-0016: clear the inherited environment and re-add only the
/// allowlisted variables. No client-supplied `env` reaches the child —
/// the channel layer refuses the `env` request (ADR-0023).
fn sanitise_env(cmd: &mut Command) {
    cmd.env_clear();
    for (key, val) in std::env::vars_os() {
        let keep = key.to_str().is_some_and(|k| {
            matches!(k, "PATH" | "HOME" | "USER" | "SHELL" | "LANG") || k.starts_with("LC_")
        });
        if keep {
            cmd.env(key, val);
        }
    }
}

/// Maps an exit status to a conventional code: the code if the child
/// exited normally, or `128 + signo` if a signal killed it (`exit-signal`
/// detail is deferred to Phase 2 — ADR-0023).
fn code_of(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(EXIT_WAIT_FAILED, |sig| 128 + sig)
    }
    #[cfg(not(unix))]
    {
        EXIT_WAIT_FAILED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Reads the child's output until its exit status.
    async fn exit_code(io: &mut ChildIo) -> i32 {
        while let Some(chunk) = io.out_rx.recv().await {
            if let ChildChunk::Exited(code) = chunk {
                return code;
            }
        }
        panic!("output closed without an exit status");
    }

    /// Polls, blocking the thread, until `done` holds or 10 s pass.
    fn wait_blocking(mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[tokio::test]
    async fn reaped_child_leaves_the_registry() {
        let scope = ChildScope::default();
        let mut io = spawn("exit 3", &scope).expect("spawn");
        assert_eq!(lock(&scope.live).len(), 1);
        assert_eq!(exit_code(&mut io).await, 3);
        // Deregistered in the reap's critical section, before the status
        // was sent.
        assert!(lock(&scope.live).is_empty());
        drop(io);
        scope.join().await;
    }

    #[tokio::test]
    async fn dropping_the_handle_kills_the_whole_group() {
        let scope = ChildScope::default();
        // The background job is a second member of the child's group.
        let mut io = spawn("sleep 30 & echo $!; wait", &scope).expect("spawn");
        let job = loop {
            match io.out_rx.recv().await {
                Some(ChildChunk::Stdout(b)) => {
                    let text = String::from_utf8(b).expect("utf-8 pid");
                    let raw: i32 = text.trim().parse().expect("numeric pid");
                    break Pid::from_raw(raw).expect("positive pid");
                }
                Some(_) => {}
                None => panic!("child ended before printing its job's pid"),
            }
        };
        drop(io);
        tokio::time::timeout(Duration::from_secs(10), scope.join())
            .await
            .expect("the killed child is reaped and its pumps end");
        assert!(lock(&scope.live).is_empty());
        // The job was reparented on its parent's death; once its new
        // parent reaps it, its PID is gone.
        assert!(
            wait_blocking(|| rustix::process::test_kill_process(job).is_err()),
            "the group kill must reach the background job"
        );
    }

    #[test]
    fn scope_drop_kills_registered_children_without_awaiting() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (scope, io, pid) = runtime.block_on(async {
            let scope = ChildScope::default();
            let io = spawn("sleep 30", &scope).expect("spawn");
            let pid = lock(&scope.live)[0];
            (scope, io, pid)
        });
        // As when the connection task is aborted: no task runs after the
        // drop, so only the synchronous guard can kill the child.
        drop(scope);
        assert!(
            wait_blocking(|| has_exited(pid)),
            "the scope's guard must kill the child without awaiting"
        );
        drop(io);
    }
}
