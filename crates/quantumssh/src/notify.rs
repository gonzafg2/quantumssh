//! systemd readiness notification (ADR-0043): the `sd_notify(3)` datagram
//! protocol on the standard library — no `libsystemd`, no crate, no
//! `unsafe`, as OpenSSH has done since 9.8p1.
//!
//! systemd names its socket in `$NOTIFY_SOCKET`. When the variable is
//! unset or empty the server is not supervised, and nothing is sent.
//! Channel children never see the variable: the ADR-0016 environment
//! allowlist drops it.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;

use tracing::warn;

/// Sent once the listener is bound and the shutdown handlers are
/// installed: the port accepts, and a stop request will drain.
pub const READY: &str = "READY=1";

/// ADR-0028's 2 s abort grace past the drain deadline, plus the exit.
const STOP_MARGIN: Duration = Duration::from_secs(5);

/// The message sent when the drain starts: `STOPPING=1`, and a stop
/// timeout extended to cover a `drain` longer than systemd's
/// `TimeoutStopSec=`. systemd only ever lengthens the timer with it.
pub fn stopping(drain: Duration) -> String {
    let extend = drain.saturating_add(STOP_MARGIN).as_micros();
    format!("STOPPING=1\nEXTEND_TIMEOUT_USEC={extend}")
}

/// Sends `state` to the service manager named by `$NOTIFY_SOCKET`, if
/// any. A failure is logged and never fatal: under `Type=notify` a
/// missing `READY=1` still fails the start at `TimeoutStartSec=`.
pub fn notify(state: &str) {
    let Some(target) = std::env::var_os("NOTIFY_SOCKET").filter(|t| !t.is_empty()) else {
        return;
    };
    if let Err(e) = send(&target, state) {
        warn!(
            socket = %target.to_string_lossy(),
            error = %e,
            "cannot notify the service manager"
        );
    }
}

/// One datagram carrying `state` to `target`: a path (`/…`) or, on
/// Linux, an abstract name (`@…`). Anything else (`vsock:`) is
/// unsupported.
fn send(target: &OsStr, state: &str) -> io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    let sent = match target.as_bytes() {
        [b'/', ..] => socket.send_to(state.as_bytes(), Path::new(target))?,
        #[cfg(target_os = "linux")]
        [b'@', name @ ..] => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            socket.send_to_addr(state.as_bytes(), &addr)?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not a path or an abstract socket name",
            ));
        }
    };
    if sent == state.len() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::WriteZero, "short datagram"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A receiving socket under the system temp directory: short enough
    /// for `sun_path` on every platform, unique per test and process.
    fn receiver(name: &str) -> (UnixDatagram, PathBuf) {
        let path = std::env::temp_dir().join(format!("qssh-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path).expect("bind receiver");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        (socket, path)
    }

    fn received(socket: &UnixDatagram) -> String {
        let mut buf = [0u8; 256];
        let n = socket.recv(&mut buf).expect("datagram");
        String::from_utf8(buf[..n].to_vec()).expect("utf-8")
    }

    #[test]
    fn stopping_extends_the_timeout_past_the_drain() {
        assert_eq!(
            stopping(Duration::from_secs(30)),
            "STOPPING=1\nEXTEND_TIMEOUT_USEC=35000000"
        );
        assert_eq!(
            stopping(Duration::from_secs(600)),
            "STOPPING=1\nEXTEND_TIMEOUT_USEC=605000000"
        );
    }

    #[test]
    fn a_path_address_receives_one_datagram() {
        let (socket, path) = receiver("path");
        send(path.as_os_str(), READY).expect("send");
        assert_eq!(received(&socket), "READY=1");
        send(path.as_os_str(), &stopping(Duration::from_secs(1))).expect("send");
        assert_eq!(received(&socket), "STOPPING=1\nEXTEND_TIMEOUT_USEC=6000000");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_socket_is_an_error() {
        let path = std::env::temp_dir().join(format!("qssh-absent-{}.sock", std::process::id()));
        assert!(send(path.as_os_str(), READY).is_err());
    }

    #[test]
    fn other_address_forms_are_unsupported() {
        for target in ["vsock:2:1234", "relative.sock"] {
            let err = send(OsStr::new(target), READY).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{target}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_abstract_address_receives_one_datagram() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("qssh-notify-test-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .expect("abstract name");
        let socket = UnixDatagram::bind_addr(&addr).expect("bind abstract");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        send(OsStr::new(&format!("@{name}")), READY).expect("send");
        assert_eq!(received(&socket), "READY=1");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn abstract_names_are_unsupported_off_linux() {
        let err = send(OsStr::new("@qssh"), READY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
