//! Integration tests for the M1 contract: version exchange
//! (RFC 4253 §4.2) over a real TCP connection, plus the §5.1.3
//! slow-handshake budget.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use quantumssh_core::server::{Config, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

const TEST_BUDGET: Duration = Duration::from_secs(5);

async fn start_server(handshake_timeout: Duration) -> SocketAddr {
    let config = Config {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        handshake_timeout,
    };
    let server = Server::bind(&config).await.expect("bind ephemeral port");
    let addr = server.local_addr().expect("local addr");
    drop(tokio::spawn(server.serve()));
    addr
}

/// Reads until the server ends the connection. A clean EOF and a
/// `ConnectionReset` are both accepted: when the server fail-closes
/// with client bytes still in flight (e.g. the oversized-line cut),
/// the kernel answers the unread data with RST.
async fn read_until_server_closes(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match timeout(TEST_BUDGET, stream.read(&mut buf))
            .await
            .expect("server closes within budget")
        {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }
    data
}

#[tokio::test]
async fn exchanges_versions_and_cleanly_closes() {
    let addr = start_server(Duration::from_secs(30)).await;

    let mut stream = timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect");

    stream
        .write_all(b"SSH-2.0-testclient_0.1\r\n")
        .await
        .expect("send client id");

    let data = read_until_server_closes(&mut stream).await;
    let line = String::from_utf8(data).expect("server id is utf-8");
    assert!(
        line.starts_with("SSH-2.0-quantumssh_"),
        "unexpected banner: {line:?}"
    );
    assert!(line.ends_with("\r\n"), "banner must end with CRLF");

    // The accept loop survives: a second client succeeds.
    let mut second = timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("second connect")
        .expect("second tcp connect");
    second
        .write_all(b"SSH-2.0-testclient_0.1\r\n")
        .await
        .expect("send second id");
    let data = read_until_server_closes(&mut second).await;
    assert!(!data.is_empty());
}

#[tokio::test]
async fn slow_handshake_is_closed_at_the_budget() {
    // Threat model §5.1.3: a client that connects and never completes
    // the handshake is cut at the configured deadline.
    let addr = start_server(Duration::from_millis(200)).await;

    let mut stream = timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect");

    // Send nothing. The server must send its banner, wait for ours,
    // give up at the 200 ms budget, and close — well within the test
    // budget rather than hanging forever.
    let data = read_until_server_closes(&mut stream).await;
    let line = String::from_utf8(data).expect("server id is utf-8");
    assert!(line.starts_with("SSH-2.0-quantumssh_"));
}

#[tokio::test]
async fn malformed_identification_is_rejected() {
    let addr = start_server(Duration::from_secs(30)).await;

    let mut stream = timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect");

    stream
        .write_all(b"HTTP/1.1 GET /\r\n")
        .await
        .expect("send junk");

    // The server still sends its banner first, then rejects ours and
    // closes; the connection must reach EOF without hanging.
    let data = read_until_server_closes(&mut stream).await;
    assert!(!data.is_empty());
}

#[tokio::test]
async fn oversized_identification_line_is_rejected() {
    let addr = start_server(Duration::from_secs(30)).await;

    let mut stream = timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect");

    // 300 bytes with no newline: must be cut at the 255-byte bound,
    // not buffered indefinitely.
    let long = vec![b'A'; 300];
    stream.write_all(&long).await.expect("send oversized line");

    let data = read_until_server_closes(&mut stream).await;
    assert!(!data.is_empty());
}
