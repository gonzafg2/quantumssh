//! Single-command execution for the M5 channel layer (ADR-0023).
//!
//! The command runs through a fixed shell — `/bin/sh -c "<command>"` —
//! because SSH `exec` delivers one opaque string and the service
//! account's login shell is `/usr/sbin/nologin` (ADR-0016). The child
//! runs under the service-account UID with a **sanitised** environment
//! (ADR-0016 Decision: allowlist `PATH HOME USER SHELL LANG LC_*`); no
//! per-user resolution (threat model §8.12).
//!
//! Concurrency (ADR-0022): `std::process::Command` on
//! `tokio::task::spawn_blocking`, not `tokio::process`. The child's
//! stdio is pumped by dedicated blocking tasks that talk to the async
//! channel driver only through Tokio channels — the async/blocking
//! boundary is exactly this set of channels. Reading stdout while
//! writing stdin from one thread deadlocks `std` pipes, so each
//! direction gets its own pump.

// Private module: `pub(crate)` items are the surface the channel driver
// uses. `redundant_pub_crate` would prefer `pub`, but `pub(crate)` states
// the intent — nothing here is public API.
#![allow(clippy::redundant_pub_crate)]

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

/// Outbound chunk size — matches the channel `MAX_PACKET` (ADR-0023) so
/// a single chunk never exceeds one SSH packet's payload.
const CHUNK: usize = 32 * 1024;
/// Child-output queue bound: `OUT_QUEUE × CHUNK` caps the OS-side
/// read-ahead held off the wire when the client window is closed.
const OUT_QUEUE: usize = 8;
/// Pending-stdin queue bound.
const STDIN_QUEUE: usize = 8;
/// Reap poll interval — the upper bound on exit-detection latency.
const REAP_POLL: Duration = Duration::from_millis(20);
/// Conventional exit status when the wait itself fails or the child is
/// signalled (`exit-signal` detail is deferred to Phase 2 — ADR-0023).
const EXIT_WAIT_FAILED: i32 = 127;

/// A message from the child's blocking tasks to the async driver. The
/// reap task sends [`ChildChunk::Exited`] **before** dropping its sender,
/// so it always arrives before `out_rx` closes (`recv` returns `None`)
/// — the driver can drain all output and still observe the exit, in any
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
    /// [`ChildChunk::Exited`]; `None` once all blocking tasks have
    /// finished.
    pub out_rx: mpsc::Receiver<ChildChunk>,
    /// Bytes the child has actually read from stdin — drives inbound
    /// window replenishment (ADR-0023).
    pub consumed_rx: mpsc::UnboundedReceiver<u32>,
    /// Hands stdin chunks to the stdin pump; `None` once stdin is closed
    /// (client `CHANNEL_EOF` or early `CHANNEL_CLOSE`), which sends the
    /// child EOF on its stdin.
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Requests the child be killed. The reap task polls this and kills
    /// through its **owned `Child` handle** (`Child::kill()` is safe after
    /// exit) — never by raw pid — so a kill can never target a pid the OS
    /// has reused (the TOCTOU a post-`wait()` kill-by-pid would carry).
    kill_flag: Arc<AtomicBool>,
}

impl Drop for ChildIo {
    /// Guarantees no child outlives its channel: any drop — including an
    /// abrupt transport failure that unwinds `Driver` without a
    /// cooperative `CHANNEL_CLOSE` — signals the reap to kill the child,
    /// which then unblocks and frees its blocking thread.
    fn drop(&mut self) {
        self.kill_flag.store(true, Ordering::SeqCst);
    }
}

impl ChildIo {
    /// Requests the child be killed (client-initiated early close). The
    /// reap task performs the kill through its owned `Child` handle on its
    /// next poll.
    pub(crate) fn kill(&self) {
        self.kill_flag.store(true, Ordering::SeqCst);
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

/// The OS UID the child runs under — the `executing_uid` audit field
/// (ADR-0016). A constant per process in Phase 1 (service-account model).
pub(crate) fn executing_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Spawns `/bin/sh -c "<command>"` with a sanitised environment and
/// wires its stdio to the returned channels. The child and its three
/// stdio pumps plus a reap task run on the blocking pool (ADR-0022).
///
/// # Errors
///
/// [`std::io::Error`] if the child cannot be spawned.
pub(crate) fn spawn(command: &str) -> std::io::Result<ChildIo> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(command);
    sanitise_env(&mut cmd);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;

    let mut child_stdin = child.stdin.take().expect("stdin piped");
    let mut child_stdout = child.stdout.take().expect("stdout piped");
    let mut child_stderr = child.stderr.take().expect("stderr piped");

    let (out_tx, out_rx) = mpsc::channel::<ChildChunk>(OUT_QUEUE);
    let (consumed_tx, consumed_rx) = mpsc::unbounded_channel::<u32>();
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_QUEUE);

    // stdout pump: read ≤ CHUNK at a time; `blocking_send` parks (and so
    // backpressures the child's stdout pipe) when the queue is full.
    let out_tx_stdout = out_tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx_stdout
                        .blocking_send(ChildChunk::Stdout(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // stderr pump.
    let out_tx_stderr = out_tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match child_stderr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx_stderr
                        .blocking_send(ChildChunk::Stderr(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // stdin pump: `write_all` blocks (backpressuring the wire via the
    // gated inbound window) until the child reads; reports consumed bytes
    // so the driver can replenish the inbound window (ADR-0023).
    tokio::task::spawn_blocking(move || {
        while let Some(chunk) = stdin_rx.blocking_recv() {
            if child_stdin.write_all(&chunk).is_err() || child_stdin.flush().is_err() {
                break;
            }
            match u32::try_from(chunk.len()) {
                Ok(n) if consumed_tx.send(n).is_ok() => {}
                _ => break,
            }
        }
        // Dropping `child_stdin` here closes the child's stdin (EOF).
    });

    // reap: poll for exit, honouring a kill request through the owned
    // `Child` handle, then report the status on the same channel (before
    // dropping the sender, so it precedes the channel's close).
    let kill_flag = Arc::new(AtomicBool::new(false));
    let kf = Arc::clone(&kill_flag);
    tokio::task::spawn_blocking(move || {
        let code = reap_child(&mut child, &kf);
        let _ = out_tx.blocking_send(ChildChunk::Exited(code));
    });

    Ok(ChildIo {
        out_rx,
        consumed_rx,
        stdin_tx: Some(stdin_tx),
        kill_flag,
    })
}

/// Polls the child to exit, applying a kill request through the owned
/// handle (no kill-by-pid, so no pid-reuse race). Polling adds at most
/// [`REAP_POLL`] latency to exit detection — imperceptible for a command
/// whose output already streamed over the wire.
fn reap_child(child: &mut std::process::Child, kill_flag: &AtomicBool) -> i32 {
    loop {
        if kill_flag.load(Ordering::SeqCst) {
            let _ = child.kill(); // idempotent; safe to call after exit
        }
        match child.try_wait() {
            Ok(Some(status)) => return code_of(status),
            Ok(None) => std::thread::sleep(REAP_POLL),
            Err(_) => return EXIT_WAIT_FAILED,
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
