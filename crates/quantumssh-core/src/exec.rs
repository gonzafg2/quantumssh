//! Channel children (ADR-0023, ADR-0038): `exec` and `shell`, on pipes
//! or on a pseudo-terminal.
//!
//! Every child runs through a fixed shell — `/bin/sh -c "<command>"` for
//! `exec`, `/bin/sh` as a login shell for `shell` — because the service
//! account's login shell is `/usr/sbin/nologin` (ADR-0016). The child
//! runs under the service-account UID with a **sanitised** environment
//! (ADR-0016 Decision: allowlist `PATH HOME USER SHELL LANG LC_*`, plus
//! `TERM` on a PTY); no per-user resolution (threat model §8.12). A PTY
//! child is started through the binary's re-exec helper
//! ([`crate::pty`]), which makes it a session leader with the slave as
//! its controlling terminal.
//!
//! Concurrency (ADR-0038 §6): `tokio::process`. Each child gets its pump
//! tasks — three stdio pumps on pipes, one master pump on a PTY — and one
//! reap task, all spawned into the connection's
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

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rustix::process::{Pid, Signal};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, Interest};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use crate::pty::{self, PtyPair, Size};

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
/// Conventional exit status when the wait itself fails.
const EXIT_WAIT_FAILED: i32 = 127;
/// The fixed shell every channel child runs through.
const SHELL: &str = "/bin/sh";
/// How long a PTY session's leader has to exit after the hang-up before
/// its group is killed (ADR-0038 §7). An initial value, not a measurement.
const PTY_HANGUP_GRACE: Duration = Duration::from_secs(1);
/// RFC 4254 §6.10's signal names, without the `SIG` prefix. A death by
/// any other signal is reported as `exit-status` 128 + n (ADR-0038 §8).
const EXIT_SIGNALS: [(Signal, &str); 13] = [
    (Signal::ABORT, "ABRT"),
    (Signal::ALARM, "ALRM"),
    (Signal::FPE, "FPE"),
    (Signal::HUP, "HUP"),
    (Signal::ILL, "ILL"),
    (Signal::INT, "INT"),
    (Signal::KILL, "KILL"),
    (Signal::PIPE, "PIPE"),
    (Signal::QUIT, "QUIT"),
    (Signal::SEGV, "SEGV"),
    (Signal::TERM, "TERM"),
    (Signal::USR1, "USR1"),
    (Signal::USR2, "USR2"),
];

/// How the child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChildExit {
    /// The exit code, or `128 + signo` for a death by a signal: the
    /// `exit-status` value and the audit `exit_status` (ADR-0024).
    pub code: i32,
    /// For a death by a signal on RFC 4254 §6.10's list: its name and
    /// whether a core was dumped, sent as `exit-signal` (ADR-0038 §8).
    pub signal: Option<(&'static str, bool)>,
}

impl ChildExit {
    const fn code(code: i32) -> Self {
        Self { code, signal: None }
    }
}

/// What a channel starts (ADR-0038 §1).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Program<'a> {
    /// `exec`: `/bin/sh -c <command>`.
    Exec(&'a str),
    /// `shell`: `/bin/sh` as a login shell, `argv[0]` `-sh`, so
    /// `/etc/profile` and `~/.profile` run.
    Shell,
}

impl Program<'_> {
    const fn argv0(self) -> &'static str {
        match self {
            Self::Exec(_) => SHELL,
            Self::Shell => "-sh",
        }
    }

    fn push_args(self, cmd: &mut Command) {
        if let Self::Exec(command) = self {
            cmd.arg("-c").arg(command);
        }
    }
}

/// A message from the child's tasks to the async driver. The reap task
/// sends [`ChildChunk::Exited`] **before** dropping its sender, so it
/// always arrives before `out_rx` closes (`recv` returns `None`) — the
/// driver can drain all output and still observe the exit, in any
/// scheduling order.
pub(crate) enum ChildChunk {
    /// Bytes from the child's stdout, or from a PTY's single merged
    /// stream (frame as `CHANNEL_DATA`).
    Stdout(Vec<u8>),
    /// Bytes from the child's stderr (frame as `CHANNEL_EXTENDED_DATA`).
    Stderr(Vec<u8>),
    /// The child exited.
    Exited(ChildExit),
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
    /// Hands stdin chunks to the stdin pump, or to a PTY's master pump;
    /// `None` once input is closed (client `CHANNEL_EOF` or early
    /// `CHANNEL_CLOSE`). On pipes that sends the child EOF; a terminal has
    /// no half-close, so a PTY's master stays open for output.
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// The kill request to the reap task: sending it or dropping it
    /// requests the kill. The reap task kills through its **owned
    /// `Child` handle**, while the child is unreaped — never by a PID the
    /// OS may have reused.
    kill_tx: Option<oneshot::Sender<()>>,
    /// The tasks that forward the child's output: the stdout and stderr
    /// pumps, or a PTY's master pump, which also writes its input.
    output_pumps: Vec<AbortHandle>,
    /// A pipe session's stdin pump.
    stdin_pump: Option<AbortHandle>,
    /// A PTY session's master, shared with its pump, for `window-change`.
    /// Once both copies are gone the master is closed, which hangs up the
    /// session (ADR-0038 §7).
    master: Option<Arc<AsyncFd<OwnedFd>>>,
}

impl Drop for ChildIo {
    /// Guarantees no child outlives its channel: any drop — including an
    /// abrupt transport failure that unwinds `Driver` without a
    /// cooperative `CHANNEL_CLOSE` — drops the kill request's sender,
    /// which the reap task takes as a kill. The pumps are aborted, since
    /// a process outside the child's group could keep a pipe open and a
    /// pump blocked on it.
    fn drop(&mut self) {
        for pump in self.output_pumps.iter().chain(&self.stdin_pump) {
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

    /// Stops forwarding the child's output after an early client close
    /// (ADR-0023): the client has closed, so the output has no sink, and
    /// a process the leader left behind could hold the pipes open
    /// indefinitely (#190). With the output pumps aborted, the output
    /// channel closes once the reap task has reported the exit. A PTY's
    /// master is released here too, which hangs up the session.
    pub(crate) fn discard_output(&mut self) {
        for pump in &self.output_pumps {
            pump.abort();
        }
        self.master = None;
    }

    /// Applies a `window-change` to a PTY session's master.
    ///
    /// # Errors
    ///
    /// The ioctl's error, or an error if the session has no PTY.
    pub(crate) fn resize(&self, size: Size) -> io::Result<()> {
        let master = self
            .master
            .as_ref()
            .ok_or_else(|| io::Error::other("no pty"))?;
        pty::resize(master.get_ref(), size)
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
    /// The executable whose helper modes start PTY and SFTP children
    /// (ADR-0038 §5, ADR-0041 §2); `None` refuses `pty-req` and
    /// `subsystem`.
    helper: Option<Arc<Path>>,
}

impl ChildScope {
    pub(crate) fn new(helper: Option<Arc<Path>>) -> Self {
        Self {
            tasks: Mutex::default(),
            live: Arc::default(),
            helper,
        }
    }

    pub(crate) fn helper(&self) -> Option<&Path> {
        self.helper.as_deref()
    }

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
    /// `Some` for a PTY session: a kill request first hangs the session
    /// up and gives the leader this long to exit (ADR-0038 §7).
    hangup_grace: Option<Duration>,
    /// Told when the leader has been reaped: a PTY's master pump then
    /// forwards what the master holds and closes it.
    on_exit: Option<oneshot::Sender<()>>,
}

impl Reaper {
    /// Registers a just-spawned child in the scope.
    ///
    /// # Errors
    ///
    /// An error if the child has no PID, which a child spawned just now
    /// and not yet reaped always has; it is then killed.
    fn register(
        mut child: Child,
        scope: &ChildScope,
        hangup_grace: Option<Duration>,
    ) -> io::Result<Self> {
        let Some(pid) = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw)
        else {
            let _ = child.start_kill();
            return Err(io::Error::other("spawned child has no pid"));
        };
        lock(&scope.live).push(pid);
        Ok(Self {
            child: Some(child),
            pid,
            live: Arc::clone(&scope.live),
            hangup_grace,
            on_exit: None,
        })
    }

    /// Waits for the child's exit, applying a kill request on the way,
    /// then reaps it.
    ///
    /// `session_failed` is the PTY master pump's report of a master read
    /// or write failure, which tears the session down like a kill request
    /// (ADR-0038 §2); a pump that ends without sending it reports nothing.
    async fn run(
        mut self,
        mut kill_rx: oneshot::Receiver<()>,
        mut session_failed: oneshot::Receiver<()>,
    ) -> ChildExit {
        let exit = wait_exit(self.pid);
        tokio::pin!(exit);
        let mut kill_pending = true;
        let mut failure_pending = true;
        // The end of a PTY session's hang-up grace, once one has started.
        let mut grace_end: Option<Instant> = None;
        loop {
            // Biased towards the kill: when the request and the exit are
            // both ready, the group is signalled while the leader is still
            // unreaped. Reaping first would free its PID and leave the rest
            // of the group beyond any later kill (ADR-0038 §6).
            tokio::select! {
                biased;
                // A sent request and a dropped sender both mean kill.
                _ = &mut kill_rx, if kill_pending => {
                    kill_pending = false;
                    self.begin_kill(&mut grace_end);
                }
                failed = &mut session_failed, if failure_pending => {
                    failure_pending = false;
                    if failed.is_ok() {
                        self.begin_kill(&mut grace_end);
                    }
                }
                () = tokio::time::sleep_until(grace_end.unwrap_or_else(Instant::now)),
                    if grace_end.is_some() =>
                {
                    grace_end = None;
                    if let Some(child) = self.child.as_mut() {
                        kill_group(child, self.pid);
                    }
                }
                () = &mut exit => {
                    // A hang-up in progress ends with the group kill even
                    // when the leader exits within the grace (ADR-0038 §7);
                    // the leader is still unreaped, so the group ID is safe.
                    if grace_end.take().is_some()
                        && let Some(child) = self.child.as_mut()
                    {
                        kill_group(child, self.pid);
                    }
                    if let Some(code) = self.try_reap() {
                        if let Some(tx) = self.on_exit.take() {
                            let _ = tx.send(());
                        }
                        return code;
                    }
                    exit.set(wait_exit(self.pid));
                }
            }
        }
    }

    /// Starts the kill of an unreaped child: the group's `SIGKILL` on pipes;
    /// on a PTY, a terminal hang-up — shells forward it to their jobs and
    /// editors save recovery files — and the grace before the group kill
    /// (ADR-0038 §7). Only the first request starts anything.
    fn begin_kill(&mut self, grace_end: &mut Option<Instant>) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match self.hangup_grace {
            Some(grace) if grace_end.is_none() => {
                // The PID is still reserved, as the leader is unreaped.
                let _ = rustix::process::kill_process(self.pid, Signal::HUP);
                *grace_end = Some(Instant::now() + grace);
            }
            Some(_) => {}
            None => kill_group(child, self.pid),
        }
    }

    /// Reaps the child and deregisters it in one critical section, so the
    /// scope's kill guard never signals a reaped PID. `None` if the child
    /// has not exited yet.
    fn try_reap(&mut self) -> Option<ChildExit> {
        let mut live = lock(&self.live);
        let code = match self.child.as_mut()?.try_wait() {
            Ok(None) => return None,
            Ok(Some(status)) => exit_of(status),
            Err(_) => ChildExit::code(EXIT_WAIT_FAILED),
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

/// Spawns the program on pipes with a sanitised environment and wires its
/// stdio to the returned channels. The pumps and the reap task run in
/// `scope` (ADR-0038 §6).
///
/// # Errors
///
/// [`std::io::Error`] if the child cannot be spawned.
pub(crate) fn spawn(program: Program<'_>, scope: &ChildScope) -> io::Result<ChildIo> {
    let mut cmd = Command::new(SHELL);
    cmd.arg0(program.argv0());
    program.push_args(&mut cmd);
    spawn_piped(cmd, scope)
}

/// Spawns the binary's SFTP helper on pipes (ADR-0041 §1), the ordinary
/// pipe child of [`spawn`].
///
/// # Errors
///
/// [`std::io::Error`] if no helper is configured or the child cannot be
/// spawned.
pub(crate) fn spawn_sftp(scope: &ChildScope) -> io::Result<ChildIo> {
    let helper = scope
        .helper()
        .ok_or_else(|| io::Error::other("no helper"))?;
    let mut cmd = Command::new(helper);
    cmd.arg(crate::sftp::HELPER_ARG);
    spawn_piped(cmd, scope)
}

/// Spawns `cmd` with the sanitised environment, its stdio on pipes and
/// its own process group, and supervises it in `scope`.
fn spawn_piped(mut cmd: Command, scope: &ChildScope) -> io::Result<ChildIo> {
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
    let reaper = Reaper::register(child, scope, None)?;

    let (out_tx, out_rx) = mpsc::channel::<ChildChunk>(OUT_QUEUE);
    let (consumed_tx, consumed_rx) = mpsc::unbounded_channel::<u32>();
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_QUEUE);
    let (kill_tx, kill_rx) = oneshot::channel();

    let output_pumps = vec![
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
    ];
    let stdin_pump = scope.spawn(pump_stdin(child_stdin, stdin_rx, consumed_tx));
    // Pipes have no master to fail: the sender is dropped unsent.
    let (_, failed_rx) = oneshot::channel();
    spawn_reap(scope, reaper, kill_rx, failed_rx, out_tx);

    Ok(ChildIo {
        out_rx,
        consumed_rx,
        stdin_tx: Some(stdin_tx),
        kill_tx: Some(kill_tx),
        output_pumps,
        stdin_pump: Some(stdin_pump),
        master: None,
    })
}

/// Spawns the program on the PTY through the binary's re-exec helper
/// (ADR-0038 §5), with the sanitised environment plus `TERM` when the
/// client set one. The master pump and the reap task run in `scope`.
///
/// # Errors
///
/// [`std::io::Error`] if the master cannot be registered or the helper
/// cannot be spawned.
pub(crate) fn spawn_pty(
    program: Program<'_>,
    pair: PtyPair,
    term: &str,
    scope: &ChildScope,
) -> io::Result<ChildIo> {
    let helper = scope
        .helper()
        .ok_or_else(|| io::Error::other("no pty helper"))?;
    let PtyPair { master, slave } = pair;
    let master = Arc::new(AsyncFd::with_interest(
        master,
        Interest::READABLE | Interest::WRITABLE,
    )?);
    let mut cmd = Command::new(helper);
    cmd.arg(pty::HELPER_ARG).arg(SHELL).arg(program.argv0());
    program.push_args(&mut cmd);
    sanitise_env(&mut cmd);
    if !term.is_empty() {
        cmd.env("TERM", term);
    }
    // The helper's stdio are copies of the slave. No `process_group`: a
    // process-group leader cannot `setsid`.
    cmd.stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    let spawned = cmd.spawn();
    // Close the server's copies of the slave, the builder's included, or
    // the master never sees end-of-session (ADR-0038 §5).
    drop(cmd);
    let mut reaper = Reaper::register(spawned?, scope, Some(PTY_HANGUP_GRACE))?;
    let (exited_tx, exited_rx) = oneshot::channel();
    reaper.on_exit = Some(exited_tx);

    let (out_tx, out_rx) = mpsc::channel::<ChildChunk>(OUT_QUEUE);
    let (consumed_tx, consumed_rx) = mpsc::unbounded_channel::<u32>();
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_QUEUE);
    let (kill_tx, kill_rx) = oneshot::channel();
    let (failed_tx, failed_rx) = oneshot::channel();
    let output_pumps = vec![scope.spawn(pump_pty(
        Arc::clone(&master),
        out_tx.clone(),
        stdin_rx,
        consumed_tx,
        exited_rx,
        failed_tx,
    ))];
    spawn_reap(scope, reaper, kill_rx, failed_rx, out_tx);

    Ok(ChildIo {
        out_rx,
        consumed_rx,
        stdin_tx: Some(stdin_tx),
        kill_tx: Some(kill_tx),
        output_pumps,
        stdin_pump: None,
        master: Some(master),
    })
}

/// Runs the reap task in `scope`. The status goes out on the output
/// channel before the sender drops, so it precedes the channel's close.
fn spawn_reap(
    scope: &ChildScope,
    reaper: Reaper,
    kill_rx: oneshot::Receiver<()>,
    failed_rx: oneshot::Receiver<()>,
    out_tx: mpsc::Sender<ChildChunk>,
) {
    scope.spawn(async move {
        let exit = reaper.run(kill_rx, failed_rx).await;
        let _ = out_tx.send(ChildChunk::Exited(exit)).await;
    });
}

/// Drives a PTY session's master (ADR-0038 §6, §7). Output is read only
/// while the queue has room, so a closed client window backpressures the
/// session's writers. Input is written as the master accepts it, and each
/// accepted byte is reported for window credit. Once the leader has been
/// reaped, the pump forwards what the master already holds and ends,
/// without waiting for other processes that still hold the slave. A master
/// read or write that fails other than by would-block or end of session is
/// reported on `failed`, which tears the session down (ADR-0038 §2).
async fn pump_pty(
    master: Arc<AsyncFd<OwnedFd>>,
    out_tx: mpsc::Sender<ChildChunk>,
    mut stdin_rx: mpsc::Receiver<Vec<u8>>,
    consumed: mpsc::UnboundedSender<u32>,
    mut leader_exited: oneshot::Receiver<()>,
    failed: oneshot::Sender<()>,
) {
    let mut buf = vec![0u8; CHUNK];
    let mut permit = None;
    // The input chunk being written, and how much of it the master took.
    let mut input: Option<(Vec<u8>, usize)> = None;
    let mut input_open = true;
    let mut exit_pending = true;
    loop {
        tokio::select! {
            exited = &mut leader_exited, if exit_pending => {
                exit_pending = false;
                if exited.is_ok() {
                    drop(permit.take());
                    drain_master(master.get_ref(), &out_tx, &mut buf).await;
                    return;
                }
            }
            reserved = out_tx.reserve(), if permit.is_none() => match reserved {
                Ok(slot) => permit = Some(slot),
                Err(_) => return,
            },
            ready = master.readable(), if permit.is_some() => {
                let Ok(mut guard) = ready else { return };
                match guard.try_io(|fd| rustix::io::read(fd.get_ref(), &mut buf).map_err(io::Error::from)) {
                    Ok(Ok(n)) if n > 0 => {
                        if let Some(slot) = permit.take() {
                            slot.send(ChildChunk::Stdout(buf[..n].to_vec()));
                        }
                    }
                    // End of session: a 0-byte read on macOS.
                    Ok(Ok(_)) => return,
                    Ok(Err(e)) => {
                        if !is_end_of_session(&e) {
                            let _ = failed.send(());
                        }
                        return;
                    }
                    Err(_would_block) => {}
                }
            }
            chunk = stdin_rx.recv(), if input_open && input.is_none() => match chunk {
                Some(chunk) => input = Some((chunk, 0)),
                None => input_open = false,
            },
            ready = master.writable(), if input.is_some() => {
                let Ok(mut guard) = ready else { return };
                if let Some((chunk, written)) = input.as_mut() {
                    match guard.try_io(|fd| {
                        rustix::io::write(fd.get_ref(), &chunk[*written..]).map_err(io::Error::from)
                    }) {
                        Ok(Ok(n)) => {
                            *written += n;
                            if u32::try_from(n).map_or(true, |n| consumed.send(n).is_err()) {
                                return;
                            }
                            if *written == chunk.len() {
                                input = None;
                            }
                        }
                        Ok(Err(e)) => {
                            if !is_end_of_session(&e) {
                                let _ = failed.send(());
                            }
                            return;
                        }
                        Err(_would_block) => {}
                    }
                }
            }
        }
    }
}

/// `EIO` on the master: no process holds the slave any more (Linux's end
/// of session).
fn is_end_of_session(error: &io::Error) -> bool {
    error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error())
}

/// Forwards what the master already holds and no more (ADR-0038 §7): the
/// byte count is read once, with `FIONREAD`, so a process left writing to
/// the terminal cannot extend the drain while a send waits for the client.
/// Ends early at would-block, end of session or failure.
async fn drain_master(master: &OwnedFd, out_tx: &mpsc::Sender<ChildChunk>, buf: &mut [u8]) {
    let Ok(mut remaining) = rustix::io::ioctl_fionread(master) else {
        return;
    };
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let Ok(n) = rustix::io::read(master, &mut buf[..want]) else {
            return;
        };
        if n == 0
            || out_tx
                .send(ChildChunk::Stdout(buf[..n].to_vec()))
                .await
                .is_err()
        {
            return;
        }
        remaining = remaining.saturating_sub(n as u64);
    }
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

/// Maps an exit status: the code if the child exited normally;
/// `128 + signo` if a signal killed it, with the signal's name when it is
/// on RFC 4254 §6.10's list (ADR-0038 §8).
fn exit_of(status: ExitStatus) -> ChildExit {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        return ChildExit::code(code);
    }
    status
        .signal()
        .map_or(ChildExit::code(EXIT_WAIT_FAILED), |signo| ChildExit {
            code: 128 + signo,
            signal: signal_name(signo).map(|name| (name, status.core_dumped())),
        })
}

/// The RFC 4254 §6.10 name of `signo`, if it is on the list.
fn signal_name(signo: i32) -> Option<&'static str> {
    EXIT_SIGNALS
        .iter()
        .find(|(signal, _)| signal.as_raw() == signo)
        .map(|&(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Reads the child's output until its exit.
    async fn exit_of_child(io: &mut ChildIo) -> ChildExit {
        while let Some(chunk) = io.out_rx.recv().await {
            if let ChildChunk::Exited(exit) = chunk {
                return exit;
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
        let mut io = spawn(Program::Exec("exit 3"), &scope).expect("spawn");
        assert_eq!(lock(&scope.live).len(), 1);
        assert_eq!(exit_of_child(&mut io).await, ChildExit::code(3));
        // Deregistered in the reap's critical section, before the status
        // was sent.
        assert!(lock(&scope.live).is_empty());
        drop(io);
        scope.join().await;
    }

    #[tokio::test]
    async fn a_listed_signal_is_named_and_keeps_128_plus_n() {
        let scope = ChildScope::default();
        let mut io = spawn(Program::Exec("kill -TERM $$"), &scope).expect("spawn");
        assert_eq!(
            exit_of_child(&mut io).await,
            ChildExit {
                code: 128 + Signal::TERM.as_raw(),
                signal: Some(("TERM", false)),
            }
        );
        drop(io);
        scope.join().await;
    }

    #[tokio::test]
    async fn an_unlisted_signal_has_no_name() {
        // SIGVTALRM terminates without a core dump and is not on
        // RFC 4254 §6.10's list.
        let scope = ChildScope::default();
        let mut io = spawn(Program::Exec("kill -VTALRM $$"), &scope).expect("spawn");
        assert_eq!(
            exit_of_child(&mut io).await,
            ChildExit::code(128 + Signal::VTALARM.as_raw())
        );
        drop(io);
        scope.join().await;
    }

    #[tokio::test]
    async fn dropping_the_handle_kills_the_whole_group() {
        let scope = ChildScope::default();
        // The background job is a second member of the child's group.
        let mut io = spawn(Program::Exec("sleep 30 & echo $!; wait"), &scope).expect("spawn");
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
            let io = spawn(Program::Exec("sleep 30"), &scope).expect("spawn");
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

    #[test]
    fn a_pending_kill_is_applied_before_a_simultaneous_exit_is_reaped() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        // The background job keeps the group, and the output pipes, alive
        // after the leader exits.
        let (scope, mut io, pid) = runtime.block_on(async {
            let scope = ChildScope::default();
            let io = spawn(Program::Exec("sleep 30 & exit 0"), &scope).expect("spawn");
            let pid = lock(&scope.live)[0];
            (scope, io, pid)
        });
        // No task has run yet: the leader's exit and the kill request are
        // both ready when the reap task first runs.
        assert!(wait_blocking(|| has_exited(pid)), "the leader exits");
        io.kill();
        io.close_stdin();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), scope.join())
                .await
                .expect("the group kill closes the job's pipes");
        });
        assert!(
            wait_blocking(|| rustix::process::test_kill_process_group(pid).is_err()),
            "the kill must reach the background job"
        );
        drop(io);
    }

    #[tokio::test]
    async fn the_post_exit_drain_takes_only_what_the_master_holds() {
        // ADR-0038 §7: a writer that keeps the terminal full while a slow
        // client holds each send cannot extend the drain.
        let pair = pty::allocate(&pty::Modes::parse(&[]).expect("modes"), Size::default())
            .expect("allocate");
        let slave = pair.slave;
        let writer = std::thread::spawn(move || {
            let chunk = [b'y'; 1024];
            // Blocks while the terminal is full; ends once the master is
            // closed and the write fails.
            while rustix::io::write(&slave, &chunk).is_ok() {}
        });
        // Let the terminal fill.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (tx, mut rx) = mpsc::channel(1);
        let consumer = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let mut buf = vec![0u8; CHUNK];
        tokio::time::timeout(
            Duration::from_secs(5),
            drain_master(&pair.master, &tx, &mut buf),
        )
        .await
        .expect("the drain ends at the snapshot taken when it started");
        drop(tx);
        drop(pair.master);
        consumer.await.expect("consumer");
        writer.join().expect("writer");
    }
}
