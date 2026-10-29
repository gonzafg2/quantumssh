//! PTY integration tests (ADR-0038 §11). The in-process server re-executes
//! this package's real binary as its PTY helper (`CARGO_BIN_EXE_quantumssh`),
//! as a deployed server does, and a real SSH client drives it.

#[path = "../../quantumssh-core/tests/support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use quantumssh_core::host_key::HostKey;
use quantumssh_core::wire::Reader;
use support::*;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// `SSH_MSG_CHANNEL_SUCCESS` (RFC 4254 §5.4).
const CH_SUCCESS: u8 = 99;

async fn start() -> (SocketAddr, Arc<HostKey>) {
    start_server_with_helper(PathBuf::from(env!("CARGO_BIN_EXE_quantumssh"))).await
}

/// Opens the session channel and allocates a PTY.
async fn open_with_pty(
    addr: SocketAddr,
    host_key: &HostKey,
    cols: u32,
    rows: u32,
    modes: &[u8],
) -> (TcpStream, SealedClient, u32) {
    let (mut stream, mut client) = authenticate(addr, host_key).await;
    client.write_sealed(&mut stream, &channel_open(0)).await;
    let chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(
            &mut stream,
            &channel_pty_req(chan, b"xterm-256color", cols, rows, modes),
        )
        .await;
    assert_eq!(
        expect_reply(&mut client, &mut stream).await,
        CH_SUCCESS,
        "pty-req granted"
    );
    (stream, client, chan)
}

/// Reads until a `CHANNEL_SUCCESS` or `CHANNEL_FAILURE`, discarding
/// anything else, and returns which one arrived.
async fn expect_reply(client: &mut SealedClient, stream: &mut TcpStream) -> u8 {
    loop {
        let pkt = client.read_sealed(stream).await;
        if let Some(&msg @ (CH_SUCCESS | CH_FAILURE)) = pkt.first() {
            return msg;
        }
    }
}

/// Reads session output until it contains `needle`, returning window
/// credit as it goes.
async fn read_until(
    client: &mut SealedClient,
    stream: &mut TcpStream,
    chan: u32,
    needle: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    while !out.windows(needle.len()).any(|w| w == needle) {
        let pkt = client.read_sealed(stream).await;
        let mut r = Reader::new(&pkt);
        if r.byte().unwrap() == CH_DATA {
            let _ = r.uint32().unwrap();
            let data = r.string(32 * 1024).unwrap();
            out.extend_from_slice(data);
            let credit = u32::try_from(data.len()).unwrap();
            client
                .write_sealed(stream, &window_adjust(chan, credit))
                .await;
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn exec_on_a_pty_gets_a_controlling_terminal_term_size_and_modes() {
    let (addr, host_key) = start().await;
    // RFC 4254 §8: opcode 53 (ECHO) = 0, then TTY_OP_END.
    let modes = [53, 0, 0, 0, 0, 0];
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 100, 40, &modes).await;
    // `[ -t 0 ]`, not `tty`: macOS's `ttyname` finds the name by reading
    // `/dev`, which misses the entry while other PTYs come and go (#221).
    let command: &[u8] = b"[ -t 0 ] && echo stdin-tty; stty size; echo term=$TERM; \
        : < /dev/tty && echo ctty-ok; \
        stty -a | grep -q -- '-echo ' && echo echo-off";
    client
        .write_sealed(&mut stream, &channel_exec(chan, command))
        .await;
    let (out, _err, exit) = collect_session(&mut client, &mut stream, chan).await;
    for expected in [
        "stdin-tty",
        "40 100",
        "term=xterm-256color",
        "ctty-ok",
        "echo-off",
    ] {
        assert!(
            contains(&out, expected),
            "missing {expected:?} in {:?}",
            String::from_utf8_lossy(&out)
        );
    }
    assert_eq!(exit, Some(0));
}

/// RFC-0002: a PTY child, too, starts in `$HOME`, not in the directory
/// the server was started from.
#[tokio::test]
async fn exec_on_a_pty_runs_in_the_home_directory() {
    let home = std::env::var_os("HOME").expect("HOME is set for the test");
    let expected = std::fs::canonicalize(&home).expect("HOME exists");
    let (addr, host_key) = start().await;
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 80, 24, &[]).await;
    client
        .write_sealed(&mut stream, &channel_exec(chan, b"pwd -P"))
        .await;
    let (out, _err, exit) = collect_session(&mut client, &mut stream, chan).await;
    let pwd = String::from_utf8(out).expect("utf-8");
    assert_eq!(std::path::Path::new(pwd.trim_end()), expected);
    assert_eq!(exit, Some(0));
}

#[tokio::test]
async fn shell_on_a_pty_reads_input_and_reports_its_exit() {
    let (addr, host_key) = start().await;
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 80, 24, &[]).await;
    client
        .write_sealed(&mut stream, &channel_request(chan, b"shell"))
        .await;
    client
        .write_sealed(&mut stream, &channel_data(chan, b"echo login-$0; exit 7\n"))
        .await;
    let (out, _err, exit) = collect_session(&mut client, &mut stream, chan).await;
    assert!(
        contains(&out, "login--sh"),
        "a login shell, argv[0] -sh: {:?}",
        String::from_utf8_lossy(&out)
    );
    assert_eq!(exit, Some(7));
}

#[tokio::test]
async fn window_change_resizes_a_running_session() {
    let (addr, host_key) = start().await;
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 80, 24, &[]).await;
    client
        .write_sealed(
            &mut stream,
            &channel_exec(chan, b"echo ready; read _; stty size"),
        )
        .await;
    read_until(&mut client, &mut stream, chan, b"ready").await;
    client
        .write_sealed(&mut stream, &channel_window_change(chan, 120, 50))
        .await;
    assert_eq!(
        expect_reply(&mut client, &mut stream).await,
        CH_SUCCESS,
        "window-change applied"
    );
    client
        .write_sealed(&mut stream, &channel_data(chan, b"\n"))
        .await;
    read_until(&mut client, &mut stream, chan, b"50 120").await;
}

#[tokio::test]
async fn early_close_hangs_up_a_running_session() {
    // ADR-0038 §7: SIGHUP and the master closed, at most 1 s of grace,
    // then the group is killed; the server's CLOSE follows the reap.
    let (addr, host_key) = start().await;
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 80, 24, &[]).await;
    client
        .write_sealed(&mut stream, &channel_exec(chan, b"echo ready; sleep 30"))
        .await;
    read_until(&mut client, &mut stream, chan, b"ready").await;
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, chan))
        .await;
    let closed = timeout(Duration::from_secs(4), async {
        while client.read_sealed(&mut stream).await.first() != Some(&CH_CLOSE) {}
    })
    .await;
    assert!(closed.is_ok(), "the session ends within the hang-up grace");
}

#[tokio::test]
async fn hang_up_kills_the_group_even_when_the_leader_exits_in_the_grace() {
    // ADR-0038 §7: the leader honours SIGHUP and exits at once, but a job
    // in its group that ignores SIGHUP (`nohup`) still gets the group kill.
    // On Linux nothing else would end the job; macOS also ends it when the
    // session's terminal is hung up.
    let (addr, host_key) = start().await;
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 80, 24, &[]).await;
    client
        .write_sealed(
            &mut stream,
            &channel_exec(
                chan,
                b"nohup sleep 30 >/dev/null 2>&1 & echo job=$! end; sleep 30",
            ),
        )
        .await;
    let out = read_until(&mut client, &mut stream, chan, b" end").await;
    let text = String::from_utf8_lossy(&out);
    let job: i32 = text
        .split("job=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
        .expect("the job's pid");
    let job = rustix::process::Pid::from_raw(job).expect("positive pid");
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, chan))
        .await;
    timeout(Duration::from_secs(4), async {
        while client.read_sealed(&mut stream).await.first() != Some(&CH_CLOSE) {}
    })
    .await
    .expect("the session ends within the hang-up grace");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while rustix::process::test_kill_process(job).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "the nohup'd job in the leader's group must be killed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn a_refused_second_pty_req_keeps_the_first_pty() {
    // ADR-0038 §2: a second `pty-req` is refused and leaves the granted
    // PTY in place for the child. The child reports the size, not `tty`,
    // whose name lookup is unreliable on macOS (#221).
    let (addr, host_key) = start().await;
    let (mut stream, mut client, chan) = open_with_pty(addr, &host_key, 80, 24, &[]).await;
    client
        .write_sealed(&mut stream, &channel_pty_req(chan, b"xterm", 100, 40, &[]))
        .await;
    assert_eq!(expect_reply(&mut client, &mut stream).await, CH_FAILURE);
    client
        .write_sealed(&mut stream, &channel_exec(chan, b"stty size"))
        .await;
    let (out, _err, exit) = collect_session(&mut client, &mut stream, chan).await;
    assert!(
        contains(&out, "24 80"),
        "the child runs on the first PTY: {:?}",
        String::from_utf8_lossy(&out)
    );
    assert_eq!(exit, Some(0));
}
