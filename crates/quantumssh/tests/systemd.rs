//! The systemd readiness protocol end to end (ADR-0043 §7): the real
//! binary, started with `$NOTIFY_SOCKET` naming a socket this test
//! binds, sends `READY=1` once its port accepts, and `STOPPING=1` with
//! the stop-timeout extension when SIGTERM starts the drain.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Kills the server if the test fails before it exits.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A tree under the workspace `target/`, whose ancestor chain passes the
/// `StrictModes` walk (the assumption the config tests and the interop
/// harness make).
fn tree() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/systemd-tests")
        .join(format!("notify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create test tree");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    root
}

fn received(socket: &UnixDatagram) -> String {
    let mut buf = [0u8; 256];
    let n = socket.recv(&mut buf).expect("notification datagram");
    String::from_utf8(buf[..n].to_vec()).expect("utf-8")
}

#[test]
fn ready_once_listening_and_stopping_at_sigterm() {
    let root = tree();
    let host_key = root.join("hostkey");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
    let authorized_keys = root.join("authorized_keys");
    std::fs::copy(root.join("hostkey.pub"), &authorized_keys).expect("authorized_keys");

    // `sun_path` is short (104 bytes on macOS): the socket lives under
    // the system temp directory, not the deep workspace path.
    let socket_path =
        std::env::temp_dir().join(format!("qssh-systemd-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);
    let socket = UnixDatagram::bind(&socket_path).expect("bind notify socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");

    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_quantumssh"))
            .args(["--listen", "127.0.0.1:0", "--log-format", "json"])
            .arg("--host-key")
            .arg(&host_key)
            .arg("--authorized-keys")
            .arg(&authorized_keys)
            .env("NOTIFY_SOCKET", &socket_path)
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the server"),
    );

    assert_eq!(received(&socket), "READY=1");

    // `server.started` precedes READY=1 and names the bound port.
    let stderr = server.0.stderr.take().expect("stderr");
    let mut lines = BufReader::new(stderr).lines();
    let started = lines
        .by_ref()
        .map(|line| line.expect("log line"))
        .find(|line| line.contains("server.started"))
        .expect("server.started");
    let addr = started
        .split("\"listen_addr\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("listen_addr field");

    // At READY=1 the port accepts: the server's banner arrives.
    let mut stream = TcpStream::connect(addr).expect("connect after READY=1");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut banner = [0u8; 8];
    stream.read_exact(&mut banner).expect("banner");
    assert_eq!(&banner, b"SSH-2.0-");
    drop(stream);

    let pid = rustix::process::Pid::from_child(&server.0);
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("SIGTERM");
    // The default drain deadline is 30 s; the extension adds 5 s.
    assert_eq!(
        received(&socket),
        "STOPPING=1\nEXTEND_TIMEOUT_USEC=35000000"
    );

    let status = server.0.wait().expect("wait for the server");
    assert!(status.success(), "drained shutdown exits 0: {status}");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir_all(&root);
}
