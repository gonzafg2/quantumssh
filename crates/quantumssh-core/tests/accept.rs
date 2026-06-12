//! Integration test for the M0 contract: the server binds, accepts a
//! TCP connection, and closes it cleanly.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use quantumssh_core::server::{Config, Server};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn accepts_and_cleanly_closes_a_tcp_connection() {
    let config = Config {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        handshake_timeout: Duration::from_secs(30),
    };
    let server = Server::bind(&config).await.expect("bind ephemeral port");
    let addr = server.local_addr().expect("local addr");
    let serve = tokio::spawn(server.serve());

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect");

    // M0 contract: the server closes immediately — the client reads EOF
    // without receiving any bytes.
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read within budget")
        .expect("read");
    assert_eq!(n, 0, "server must close without sending bytes in M0");

    // The accept loop must survive the served connection: a second
    // client connects successfully (sequential loop, not one-shot).
    let mut second = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .expect("second connect within budget")
        .expect("second tcp connect");
    let n = timeout(Duration::from_secs(5), second.read(&mut buf))
        .await
        .expect("second read within budget")
        .expect("second read");
    assert_eq!(n, 0);

    serve.abort();
}
