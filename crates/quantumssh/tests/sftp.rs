//! SFTP integration tests (ADR-0041 §7). The in-process server re-executes
//! this package's real binary as its SFTP helper
//! (`CARGO_BIN_EXE_quantumssh`), and a real SSH client speaks SFTP version 3
//! over the session channel.

#[path = "../../quantumssh-core/tests/support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use quantumssh_core::host_key::HostKey;
use quantumssh_core::wire::{Reader, Writer};
use support::*;
use tokio::net::TcpStream;

/// `SSH_MSG_CHANNEL_SUCCESS` (RFC 4254 §5.4).
const CH_SUCCESS: u8 = 99;

const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_REALPATH: u8 = 16;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_NAME: u8 = 104;

async fn start() -> (SocketAddr, Arc<HostKey>) {
    start_server_with_helper(PathBuf::from(env!("CARGO_BIN_EXE_quantumssh"))).await
}

/// Reads until a `CHANNEL_SUCCESS` or `CHANNEL_FAILURE`, and returns it.
async fn expect_reply(client: &mut SealedClient, stream: &mut TcpStream) -> u8 {
    loop {
        let pkt = client.read_sealed(stream).await;
        if let Some(&msg @ (CH_SUCCESS | CH_FAILURE)) = pkt.first() {
            return msg;
        }
    }
}

/// One SFTP session over the channel: frames requests into
/// `CHANNEL_DATA` and reassembles replies from the channel stream.
struct Sftp {
    stream: TcpStream,
    client: SealedClient,
    chan: u32,
    inbox: Vec<u8>,
}

impl Sftp {
    async fn open(addr: SocketAddr, host_key: &HostKey) -> Self {
        let (mut stream, mut client) = authenticate(addr, host_key).await;
        client.write_sealed(&mut stream, &channel_open(0)).await;
        let chan = expect_open_confirmation(&mut client, &mut stream).await;
        client
            .write_sealed(&mut stream, &channel_subsystem(chan, b"sftp"))
            .await;
        assert_eq!(
            expect_reply(&mut client, &mut stream).await,
            CH_SUCCESS,
            "subsystem sftp is honoured"
        );
        Self {
            stream,
            client,
            chan,
            inbox: Vec::new(),
        }
    }

    async fn send(&mut self, payload: &[u8]) {
        let mut framed = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(payload);
        // The SFTP stream is split into channel packets of at most the
        // server's 32 KiB maximum, as a real client does.
        for chunk in framed.chunks(32 * 1024) {
            self.client
                .write_sealed(&mut self.stream, &channel_data(self.chan, chunk))
                .await;
        }
    }

    /// The next SFTP reply payload.
    async fn recv(&mut self) -> Vec<u8> {
        loop {
            if self.inbox.len() >= 4 {
                let len = u32::from_be_bytes(self.inbox[..4].try_into().unwrap()) as usize;
                if self.inbox.len() >= 4 + len {
                    let reply = self.inbox[4..4 + len].to_vec();
                    self.inbox.drain(..4 + len);
                    return reply;
                }
            }
            let pkt = self.client.read_sealed(&mut self.stream).await;
            let mut r = Reader::new(&pkt);
            if r.byte().unwrap() == CH_DATA {
                let _ = r.uint32().unwrap();
                let data = r.string(32 * 1024).unwrap();
                self.inbox.extend_from_slice(data);
                let credit = u32::try_from(data.len()).unwrap();
                self.client
                    .write_sealed(&mut self.stream, &window_adjust(self.chan, credit))
                    .await;
            }
        }
    }

    async fn request(&mut self, kind: u8, id: u32, build: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_byte(kind);
        w.put_uint32(id);
        build(&mut w);
        self.send(&w.into_bytes()).await;
        self.recv().await
    }
}

fn status_code(reply: &[u8]) -> u32 {
    let mut r = Reader::new(reply);
    assert_eq!(r.byte().unwrap(), FXP_STATUS, "a STATUS reply: {reply:?}");
    let _ = r.uint32().unwrap();
    r.uint32().unwrap()
}

fn handle_of(reply: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(reply);
    assert_eq!(r.byte().unwrap(), FXP_HANDLE, "a HANDLE reply: {reply:?}");
    let _ = r.uint32().unwrap();
    r.string(64).unwrap().to_vec()
}

/// A fresh, canonical directory under the system temp dir.
fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("quantumssh-sftp-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::canonicalize(dir).expect("canonical temp dir")
}

#[tokio::test]
async fn a_file_round_trips_through_the_real_helper() {
    let (addr, host_key) = start().await;
    let mut sftp = Sftp::open(addr, &host_key).await;

    sftp.send(&[FXP_INIT, 0, 0, 0, 3]).await;
    let version = sftp.recv().await;
    assert_eq!(&version[..5], &[FXP_VERSION, 0, 0, 0, 3]);

    let file = temp_dir("roundtrip").join("upload.bin");
    let path = file.to_str().unwrap().as_bytes().to_vec();
    let content: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

    let reply = sftp
        .request(FXP_OPEN, 1, |w| {
            w.put_string(&path);
            w.put_uint32(0x2 | 0x8 | 0x10); // WRITE | CREAT | TRUNC
            w.put_uint32(0);
        })
        .await;
    let handle = handle_of(&reply);
    for (i, chunk) in content.chunks(32 * 1024).enumerate() {
        let offset = (i * 32 * 1024) as u64;
        let reply = sftp
            .request(FXP_WRITE, 2, |w| {
                w.put_string(&handle);
                w.put_uint64(offset);
                w.put_string(chunk);
            })
            .await;
        assert_eq!(status_code(&reply), 0, "WRITE ok");
    }
    let reply = sftp.request(FXP_CLOSE, 3, |w| w.put_string(&handle)).await;
    assert_eq!(status_code(&reply), 0, "CLOSE ok");
    assert_eq!(std::fs::read(&file).unwrap(), content);

    let reply = sftp
        .request(FXP_OPEN, 4, |w| {
            w.put_string(&path);
            w.put_uint32(0x1); // READ
            w.put_uint32(0);
        })
        .await;
    let handle = handle_of(&reply);
    let mut read_back = Vec::new();
    loop {
        let offset = read_back.len() as u64;
        let reply = sftp
            .request(FXP_READ, 5, |w| {
                w.put_string(&handle);
                w.put_uint64(offset);
                w.put_uint32(64 * 1024);
            })
            .await;
        if reply[0] == FXP_STATUS {
            assert_eq!(status_code(&reply), 1, "EOF ends the read");
            break;
        }
        let mut r = Reader::new(&reply);
        assert_eq!(r.byte().unwrap(), FXP_DATA);
        let _ = r.uint32().unwrap();
        read_back.extend_from_slice(r.string(256 * 1024).unwrap());
    }
    assert_eq!(read_back, content);

    let reply = sftp.request(FXP_REALPATH, 6, |w| w.put_string(b".")).await;
    assert_eq!(reply[0], FXP_NAME, "REALPATH answers a NAME");

    // EOF on the helper's stdin ends the session cleanly.
    sftp.client
        .write_sealed(&mut sftp.stream, &channel_one_field(CH_EOF, sftp.chan))
        .await;
    let (_out, _err, exit) = collect_session(&mut sftp.client, &mut sftp.stream, sftp.chan).await;
    assert_eq!(exit, Some(0), "the helper exits 0 at EOF");
}

#[tokio::test]
async fn subsystem_is_refused_for_other_names_and_after_a_pty_req() {
    let (addr, host_key) = start().await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;
    client.write_sealed(&mut stream, &channel_open(0)).await;
    let chan = expect_open_confirmation(&mut client, &mut stream).await;

    client
        .write_sealed(&mut stream, &channel_subsystem(chan, b"netconf"))
        .await;
    assert_eq!(expect_reply(&mut client, &mut stream).await, CH_FAILURE);

    client
        .write_sealed(&mut stream, &channel_pty_req(chan, b"xterm", 80, 24, &[]))
        .await;
    assert_eq!(expect_reply(&mut client, &mut stream).await, CH_SUCCESS);
    client
        .write_sealed(&mut stream, &channel_subsystem(chan, b"sftp"))
        .await;
    assert_eq!(
        expect_reply(&mut client, &mut stream).await,
        CH_FAILURE,
        "SFTP never runs on a PTY"
    );
}
