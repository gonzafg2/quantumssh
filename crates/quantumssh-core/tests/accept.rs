//! Integration tests for the Phase 1 contract: the full post-quantum
//! handshake (M2–M3), publickey authentication (M4), and the channel
//! layer with single-command `exec` (M5).
//! — version exchange, ADR-0021 KEXINIT negotiation, the hybrid
//! `mlkem768x25519-sha256` exchange with a verified host-key
//! signature, NEWKEYS, AEAD transport, service request, the
//! `ssh-userauth` publickey loop, and the one `session` channel /
//! `exec` flow (open → exec → data → exit-status → close, ADR-0023).
//! Also retains M3-level denial and rejection paths.

mod support;

use support::*;

use ed25519_dalek::SigningKey;
use quantumssh_core::admission::Limits;
use quantumssh_core::auth;
use quantumssh_core::kex;
use quantumssh_core::transport::RekeyThresholds;
use quantumssh_core::wire::{Reader, Writer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn full_handshake_then_encrypted_ext_info_and_service_denial_chacha20() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_EXT_INFO,
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    // ext-info-c was offered: the server's first encrypted packet
    // must be EXT_INFO with server-sig-algs = ssh-ed25519 (RFC 8308;
    // ADR-0021).
    let ext_info = client.read_sealed(&mut stream).await;
    let mut r = Reader::new(&ext_info);
    assert_eq!(r.byte().unwrap(), kex::SSH_MSG_EXT_INFO);
    assert_eq!(r.uint32().unwrap(), 1, "exactly one extension");
    assert_eq!(r.string(64).unwrap(), b"server-sig-algs");
    assert_eq!(r.string(64).unwrap(), b"ssh-ed25519");
    r.finish().unwrap();

    // Service denied for an unsupported service.
    client
        .write_sealed(&mut stream, &unsupported_service_request())
        .await;
    let denial = client.read_sealed(&mut stream).await;
    assert_service_denied(&denial);
}

#[tokio::test]
async fn full_handshake_with_aes256_gcm_and_no_ext_info() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    // Client prefers AES-GCM and does not offer ext-info-c: no
    // EXT_INFO may arrive, and the GCM path must carry the exchange.
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
    )
    .await;

    client
        .write_sealed(&mut stream, &unsupported_service_request())
        .await;
    let denial = client.read_sealed(&mut stream).await;
    assert_service_denied(&denial);
}

#[tokio::test]
async fn tampered_encrypted_packet_drops_the_connection() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    // Seal a legitimate service request, then flip one ciphertext bit.
    let mut packet = client
        .tx
        .seal(client.seq_tx, &service_request_payload())
        .expect("seal");
    let mid = packet.len() / 2;
    packet[mid] ^= 0x01;
    stream.write_all(&packet).await.expect("write tampered");

    // Fail closed: the server terminates without yielding anything an
    // unauthenticated peer could use (a DISCONNECT may or may not
    // make it out before the reset; the connection must die).
    let mut data = Vec::new();
    let outcome = timeout(TEST_BUDGET, stream.read_to_end(&mut data))
        .await
        .expect("server must drop the connection within the budget");
    match outcome {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected read error: {e}"),
    }
}

#[tokio::test]
async fn non_hybrid_client_is_disconnected_with_code_3() {
    let (addr, _) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    read_server_id(&mut stream).await;
    stream.write_all(CLIENT_ID).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    let _i_s = read_packet(&mut stream).await;

    // Classical-only KEXINIT (the ADR-0020 negative interop case).
    let mut w = Writer::new();
    w.put_byte(kex::SSH_MSG_KEXINIT);
    w.put_bytes(&[7u8; 16]);
    w.put_name_list("curve25519-sha256,kex-strict-c-v00@openssh.com");
    w.put_name_list("ssh-ed25519");
    w.put_name_list("chacha20-poly1305@openssh.com");
    w.put_name_list("chacha20-poly1305@openssh.com");
    w.put_name_list("hmac-sha2-256");
    w.put_name_list("hmac-sha2-256");
    w.put_name_list("none");
    w.put_name_list("none");
    w.put_name_list("");
    w.put_name_list("");
    w.put_boolean(false);
    w.put_uint32(0);
    write_packet(&mut stream, &w.into_bytes()).await;

    expect_disconnect(&mut stream, kex::DISCONNECT_KEY_EXCHANGE_FAILED).await;
}

#[tokio::test]
async fn missing_strict_kex_is_disconnected_with_code_3() {
    let (addr, _) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    read_server_id(&mut stream).await;
    stream.write_all(CLIENT_ID).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    let _i_s = read_packet(&mut stream).await;

    let mut w = Writer::new();
    w.put_byte(kex::SSH_MSG_KEXINIT);
    w.put_bytes(&[7u8; 16]);
    w.put_name_list("mlkem768x25519-sha256"); // no kex-strict-c
    w.put_name_list("ssh-ed25519");
    w.put_name_list("chacha20-poly1305@openssh.com");
    w.put_name_list("chacha20-poly1305@openssh.com");
    w.put_name_list("hmac-sha2-256");
    w.put_name_list("hmac-sha2-256");
    w.put_name_list("none");
    w.put_name_list("none");
    w.put_name_list("");
    w.put_name_list("");
    w.put_boolean(false);
    w.put_uint32(0);
    write_packet(&mut stream, &w.into_bytes()).await;

    expect_disconnect(&mut stream, kex::DISCONNECT_KEY_EXCHANGE_FAILED).await;
}

#[tokio::test]
async fn ignore_message_before_kexinit_is_terminated() {
    // Strict-kex: the first packet must be KEXINIT; SSH_MSG_IGNORE
    // (2) — the Terrapin injection primitive — terminates.
    let (addr, _) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    read_server_id(&mut stream).await;
    stream.write_all(CLIENT_ID).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    let _i_s = read_packet(&mut stream).await;

    write_packet(&mut stream, &[2u8, 0, 0, 0, 0]).await; // SSH_MSG_IGNORE
    expect_disconnect(&mut stream, kex::DISCONNECT_PROTOCOL_ERROR).await;
}

#[tokio::test]
async fn slow_handshake_is_closed_at_the_budget() {
    // Threat model §5.1.3: a silent client is cut at the deadline.
    let (addr, _) = start_server(Duration::from_millis(200)).await;
    let mut stream = connect(addr).await;
    let _ = read_server_id(&mut stream).await;
    // Send nothing further; the server must close within its budget.
    let mut buf = [0u8; 256];
    loop {
        match timeout(TEST_BUDGET, stream.read(&mut buf))
            .await
            .expect("server closes within budget")
        {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }
}

#[tokio::test]
async fn malformed_identification_is_rejected() {
    let (addr, _) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    stream.write_all(b"HTTP/1.1 GET /\r\n").await.unwrap();
    // Server sends its banner then closes without a KEXINIT exchange.
    let _ = read_server_id(&mut stream).await;
    let mut data = Vec::new();
    let n = timeout(TEST_BUDGET, stream.read_to_end(&mut data))
        .await
        .expect("close within budget")
        .unwrap_or(0);
    assert_eq!(n, 0, "no packets after a rejected identification");
}

#[tokio::test]
async fn channel_open_session_then_exec_echo() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"echo hello"))
        .await;

    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout, b"hello\n");
    assert_eq!(exit, Some(0));
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, server_chan))
        .await;
}

#[tokio::test]
async fn exec_cat_echoes_stdin() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"cat"))
        .await;
    client
        .write_sealed(&mut stream, &channel_data(server_chan, b"ping"))
        .await;
    client
        .write_sealed(&mut stream, &channel_one_field(CH_EOF, server_chan))
        .await;

    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout, b"ping");
    assert_eq!(exit, Some(0));
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, server_chan))
        .await;
}

#[tokio::test]
async fn signal_death_sends_exit_signal_instead_of_exit_status() {
    // ADR-0038 §8: a death by a listed signal is reported by name.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"kill -TERM $$"))
        .await;

    let mut requests = Vec::new();
    loop {
        let pkt = client.read_sealed(&mut stream).await;
        let mut r = Reader::new(&pkt);
        match r.byte().unwrap() {
            CH_REQUEST => {
                let _ = r.uint32().unwrap();
                let req = r.string(64).unwrap().to_vec();
                assert!(!r.boolean().unwrap(), "want_reply must be false");
                if req == b"exit-signal" {
                    let name = r.string(64).unwrap().to_vec();
                    let core_dumped = r.boolean().unwrap();
                    assert_eq!(r.string(64).unwrap(), b"", "empty message");
                    assert_eq!(r.string(64).unwrap(), b"", "empty language tag");
                    requests.push((req, Some((name, core_dumped))));
                } else {
                    requests.push((req, None));
                }
            }
            CH_CLOSE => break,
            _ => {}
        }
    }
    assert_eq!(
        requests,
        vec![(b"exit-signal".to_vec(), Some((b"TERM".to_vec(), false)))],
        "exactly one exit-signal, and no exit-status"
    );
}

#[tokio::test]
async fn exec_stderr_is_extended_data() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"echo oops 1>&2"))
        .await;

    let (stdout, stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout, b"");
    assert_eq!(stderr, b"oops\n");
    assert_eq!(exit, Some(0));
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, server_chan))
        .await;
}

#[tokio::test]
async fn second_channel_open_is_refused() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let _server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    // A second open is refused; the first channel survives.
    client.write_sealed(&mut stream, &channel_open(1)).await;
    let reply = client.read_sealed(&mut stream).await;
    let mut r = Reader::new(&reply);
    assert_eq!(r.byte().unwrap(), CH_OPEN_FAILURE);
    assert_eq!(r.uint32().unwrap(), 1); // recipient echoes our second sender
    assert_eq!(r.uint32().unwrap(), 1); // ADMINISTRATIVELY_PROHIBITED
}

#[tokio::test]
async fn non_session_channel_type_is_refused() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client
        .write_sealed(&mut stream, &channel_open_type(0, b"direct-tcpip"))
        .await;
    let reply = client.read_sealed(&mut stream).await;
    let mut r = Reader::new(&reply);
    assert_eq!(r.byte().unwrap(), CH_OPEN_FAILURE);
    assert_eq!(r.uint32().unwrap(), 0); // recipient echoes our sender
    assert_eq!(r.uint32().unwrap(), 3); // UNKNOWN_CHANNEL_TYPE
}

#[tokio::test]
async fn zero_max_packet_is_rejected() {
    // A zero maximum_packet_size would stall flush_output forever (DoS);
    // the server must fail closed at channel open.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    let mut w = Writer::new();
    w.put_byte(CH_OPEN);
    w.put_string(b"session");
    w.put_uint32(0);
    w.put_uint32(2 * 1024 * 1024);
    w.put_uint32(0); // maximum_packet_size = 0
    client.write_sealed(&mut stream, &w.into_bytes()).await;

    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&kex::SSH_MSG_DISCONNECT));
}

#[tokio::test]
async fn pty_req_without_a_helper_is_refused() {
    // ADR-0038 §5: with no helper executable configured, the library never
    // spawns one, so every `pty-req` is refused.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(
            &mut stream,
            &channel_pty_req(server_chan, b"xterm", 80, 24, &[]),
        )
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&CH_FAILURE));
}

#[tokio::test]
async fn subsystem_without_a_helper_is_refused() {
    // ADR-0041 §1: with no helper executable, `subsystem` is refused.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_subsystem(server_chan, b"sftp"))
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&CH_FAILURE));
}

#[tokio::test]
async fn malformed_pty_req_disconnects() {
    // ADR-0038 §2: a field that fails to parse is a protocol error.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_request(server_chan, b"pty-req"))
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&kex::SSH_MSG_DISCONNECT));
}

#[tokio::test]
async fn window_change_without_a_pty_is_refused() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_window_change(server_chan, 100, 40))
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&CH_FAILURE));
}

#[tokio::test]
async fn shell_without_a_pty_runs_on_pipes() {
    // ADR-0038 §1: `shell` without a PTY starts `/bin/sh` on pipes, like
    // `exec`, and reads its commands from stdin.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_request(server_chan, b"shell"))
        .await;
    client
        .write_sealed(
            &mut stream,
            &channel_data(server_chan, b"echo hi; exit 3\n"),
        )
        .await;
    client
        .write_sealed(&mut stream, &channel_one_field(CH_EOF, server_chan))
        .await;
    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert!(
        stdout.windows(2).any(|w| w == b"hi"),
        "the shell ran the command: {stdout:?}"
    );
    assert_eq!(exit, Some(3));
}

#[tokio::test]
async fn client_early_close_kills_child() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    // A long-running command, then an immediate client close.
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"sleep 30"))
        .await;
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, server_chan))
        .await;

    // The server kills the child and replies with its own CLOSE promptly
    // (it must not wait out the sleep).
    let mut saw_close = false;
    for _ in 0..20 {
        let pkt = client.read_sealed(&mut stream).await;
        if pkt.first() == Some(&CH_CLOSE) {
            saw_close = true;
            break;
        }
    }
    assert!(saw_close, "server must close after early client close");
}

#[tokio::test]
async fn early_close_after_exit_does_not_wait_on_a_left_behind_pipe_holder() {
    // #190: the leader exits normally, but its background job keeps the
    // output pipes open. A client close must still be answered promptly
    // (ADR-0023), not after the job ends.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(
            &mut stream,
            &channel_exec(server_chan, b"sleep 30 & echo ready"),
        )
        .await;
    // `ready` is the leader's last act; give it a moment to exit.
    loop {
        let pkt = client.read_sealed(&mut stream).await;
        if pkt.first() == Some(&CH_DATA) {
            break;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, server_chan))
        .await;

    // Shorter than the read budget, so a hang fails this assertion.
    let closed = timeout(Duration::from_secs(3), async {
        loop {
            if client.read_sealed(&mut stream).await.first() == Some(&CH_CLOSE) {
                break;
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "server must answer the client's close without waiting for the job"
    );
}

#[tokio::test]
async fn cancel_safety_under_load() {
    // 3 MiB of output exceeds the 2 MiB window, forcing many
    // WINDOW_ADJUST round-trips and repeated select! cancellation of the
    // resumable read — the real test of the cancel-safe framing.
    const N: usize = 3 * 1024 * 1024;
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(
            &mut stream,
            &channel_exec(server_chan, b"head -c 3145728 /dev/zero"),
        )
        .await;

    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout.len(), N, "exact byte count must survive the stream");
    assert!(stdout.iter().all(|&b| b == 0), "stream integrity");
    assert_eq!(exit, Some(0));
    client
        .write_sealed(&mut stream, &channel_one_field(CH_CLOSE, server_chan))
        .await;
}

#[tokio::test]
async fn auth_failure_on_wrong_signature() {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let auth_vk = auth_signing.verifying_key();
    let key_blob = auth_test_blob(&auth_vk);

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&6));

    // Build a request with a tampered signature.
    let mut w = Writer::new();
    w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    w.put_string(b"testuser");
    w.put_string(b"ssh-connection");
    w.put_string(b"publickey");
    w.put_boolean(true);
    w.put_string(b"ssh-ed25519");
    w.put_string(&key_blob);
    // RFC 8709 §6 nested encoding with wrong raw signature bytes.
    let mut sig_blob = Writer::new();
    sig_blob.put_string(b"ssh-ed25519");
    sig_blob.put_string(&[0u8; 64]);
    w.put_string(&sig_blob.into_bytes());
    client.write_sealed(&mut stream, &w.into_bytes()).await;

    let auth_reply = client.read_sealed(&mut stream).await;
    assert_eq!(auth_reply.first(), Some(&auth::SSH_MSG_USERAUTH_FAILURE));
}

#[tokio::test]
async fn auth_rejects_non_publickey_method() {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let _auth_vk = auth_signing.verifying_key();

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&6));

    // Send "password" method.
    let mut w = Writer::new();
    w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    w.put_string(b"testuser");
    w.put_string(b"ssh-connection");
    w.put_string(b"password");
    w.put_boolean(false);
    w.put_string(b"hunter2");
    client.write_sealed(&mut stream, &w.into_bytes()).await;

    let auth_reply = client.read_sealed(&mut stream).await;
    let mut r = Reader::new(&auth_reply);
    assert_eq!(r.byte().unwrap(), auth::SSH_MSG_USERAUTH_FAILURE);
    let methods = r.name_list(64).unwrap();
    assert!(methods.contains("publickey"));
    assert!(!r.boolean().unwrap());
}

#[tokio::test]
async fn auth_pk_ok_then_signed_succeeds() {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let auth_vk = auth_signing.verifying_key();
    let key_blob = auth_test_blob(&auth_vk);

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&6));

    // Probe without signature → PK_OK.
    client
        .write_sealed(&mut stream, &probe_auth_request(&key_blob))
        .await;
    let pk_ok = client.read_sealed(&mut stream).await;
    assert_eq!(pk_ok.first(), Some(&auth::SSH_MSG_USERAUTH_PK_OK));

    // Signed request → SUCCESS.
    client
        .write_sealed(
            &mut stream,
            &signed_auth_request(&auth_signing, &session_id, &key_blob),
        )
        .await;
    let success = client.read_sealed(&mut stream).await;
    assert_eq!(success, vec![auth::SSH_MSG_USERAUTH_SUCCESS]);
}

#[tokio::test]
async fn max_auth_attempts_disconnects() {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let auth_vk = auth_signing.verifying_key();
    let _key_blob = auth_test_blob(&auth_vk);

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&6));

    for i in 0..12 {
        let mut w = Writer::new();
        w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
        w.put_string(b"testuser");
        w.put_string(b"ssh-connection");
        w.put_string(b"publickey");
        w.put_boolean(true);
        w.put_string(b"ssh-ed25519");
        w.put_string(&[0xe0u8; 12]); // unknown blob
        // RFC 8709 §6 nested encoding with wrong raw signature bytes.
        let mut sig_blob = Writer::new();
        sig_blob.put_string(b"ssh-ed25519");
        sig_blob.put_string(&[0u8; 64]);
        w.put_string(&sig_blob.into_bytes());
        client.write_sealed(&mut stream, &w.into_bytes()).await;

        let reply = client.read_sealed(&mut stream).await;
        if i < 11 {
            assert_eq!(
                reply.first(),
                Some(&auth::SSH_MSG_USERAUTH_FAILURE),
                "attempt {i}"
            );
        } else {
            let mut r = Reader::new(&reply);
            assert_eq!(r.byte().unwrap(), kex::SSH_MSG_DISCONNECT, "attempt {i}");
            assert_eq!(r.uint32().unwrap(), 11, "DISCONNECT_BY_APPLICATION");
            return;
        }
    }
}

#[tokio::test]
async fn channel_messages_before_open_are_rejected() {
    // RFC 4254 §5.1: recipient ids exist only after CHANNEL_OPEN. Every
    // channel message for a never-opened channel is a protocol
    // violation, not something to answer (the type-state discipline).
    // Each frame is WELL-FORMED — the guard rejects on the message type
    // before parsing, so a malformed frame would not prove it is the
    // guard (not a parse error) doing the work. All five guarded types
    // are covered.
    let cases: [(&str, Vec<u8>); 5] = [
        ("CHANNEL_REQUEST", channel_request(0, b"exec")),
        ("CHANNEL_DATA", channel_data(0, b"x")),
        ("CHANNEL_WINDOW_ADJUST", window_adjust(0, 1)),
        ("CHANNEL_EOF", channel_one_field(CH_EOF, 0)),
        ("CHANNEL_CLOSE", channel_one_field(CH_CLOSE, 0)),
    ];
    for (label, frame) in cases {
        let (addr, host_key) = start_server(Duration::from_secs(30)).await;
        let (mut stream, mut client) = authenticate(addr, &host_key).await;
        client.write_sealed(&mut stream, &frame).await;
        let reply = client.read_sealed(&mut stream).await;
        assert_eq!(
            reply.first(),
            Some(&kex::SSH_MSG_DISCONNECT),
            "{label} must disconnect before open"
        );
    }
}

#[tokio::test]
async fn pk_ok_probes_spend_the_attempt_budget() {
    // A known-key probe (PK_OK) must count against MAX_AUTH_ATTEMPTS:
    // it is otherwise the only pre-auth message repeatable without
    // budget (threat model §5.3.1).
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let auth_vk = auth_signing.verifying_key();
    let key_blob = auth_test_blob(&auth_vk);

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id, _server_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&6));

    for i in 0..12 {
        client
            .write_sealed(&mut stream, &probe_auth_request(&key_blob))
            .await;
        let reply = client.read_sealed(&mut stream).await;
        if i < 11 {
            assert_eq!(
                reply.first(),
                Some(&auth::SSH_MSG_USERAUTH_PK_OK),
                "probe {i}"
            );
        } else {
            let mut r = Reader::new(&reply);
            assert_eq!(r.byte().unwrap(), kex::SSH_MSG_DISCONNECT, "probe {i}");
            assert_eq!(r.uint32().unwrap(), 11, "DISCONNECT_BY_APPLICATION");
        }
    }
}

#[tokio::test]
async fn client_initiated_rekey_chacha() {
    rekey_roundtrip("chacha20-poly1305@openssh.com").await;
}

#[tokio::test]
async fn client_initiated_rekey_gcm() {
    // Guards the AES-GCM invocation-counter reset across a re-key.
    rekey_roundtrip("aes256-gcm@openssh.com").await;
}

#[tokio::test]
async fn byte_threshold_triggers_server_rekey() {
    // A low byte threshold makes the server initiate a re-key mid-stream.
    let cipher = "chacha20-poly1305@openssh.com";
    let (addr, host_key) = start_server_rekey(Duration::from_secs(30), test_rekey(4096)).await;
    let (mut stream, mut client, session_id, server_id) =
        authenticate_full(addr, &host_key, cipher).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    // > 4 KiB of output crosses the server's outbound byte threshold.
    client
        .write_sealed(
            &mut stream,
            &channel_exec(server_chan, b"head -c 20000 /dev/zero"),
        )
        .await;

    // Read until the server initiates a re-key (inbound KEXINIT), complete
    // it, then keep reading under the new keys to the clean close.
    let mut stdout = Vec::new();
    let mut exit = None;
    let mut rekeyed = false;
    loop {
        let pkt = client.read_sealed(&mut stream).await;
        match pkt.first().copied() {
            Some(20) => {
                // Server-initiated re-key: we already hold its KEXINIT.
                client
                    .rekey_as_client(&mut stream, &session_id, &server_id, cipher, Some(pkt))
                    .await;
                rekeyed = true;
            }
            Some(94) => {
                let mut r = Reader::new(&pkt);
                let _ = r.byte();
                let _ = r.uint32();
                let d = r.string(32 * 1024).unwrap();
                stdout.extend_from_slice(d);
                let credit = u32::try_from(d.len()).unwrap();
                client
                    .write_sealed(&mut stream, &window_adjust(server_chan, credit))
                    .await;
            }
            Some(98) => {
                let mut r = Reader::new(&pkt);
                let _ = r.byte();
                let _ = r.uint32();
                if r.string(64).unwrap() == b"exit-status" {
                    let _ = r.boolean();
                    exit = Some(i32::from_ne_bytes(r.uint32().unwrap().to_ne_bytes()));
                }
            }
            Some(97) => break, // CHANNEL_CLOSE
            _ => {}            // SUCCESS, EOF
        }
    }
    assert!(rekeyed, "server must have initiated a re-key");
    assert_eq!(stdout.len(), 20000, "all output survives the key switch");
    assert!(stdout.iter().all(|&b| b == 0));
    assert_eq!(exit, Some(0));
}

#[tokio::test]
async fn ignore_debug_unimplemented_are_tolerated_post_auth() {
    // RFC 4253 §11.2–§11.4: IGNORE and DEBUG MUST be accepted at any
    // time outside the KEX handshake; none of the three may kill the
    // session.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    let mut ignore = Writer::new();
    ignore.put_byte(2); // SSH_MSG_IGNORE
    ignore.put_string(b"chaff");
    client.write_sealed(&mut stream, &ignore.into_bytes()).await;

    let mut debug = Writer::new();
    debug.put_byte(4); // SSH_MSG_DEBUG
    debug.put_boolean(false);
    debug.put_string(b"client-side debug message");
    debug.put_string(b"");
    client.write_sealed(&mut stream, &debug.into_bytes()).await;

    let mut unimpl = Writer::new();
    unimpl.put_byte(3); // SSH_MSG_UNIMPLEMENTED
    unimpl.put_uint32(7);
    client.write_sealed(&mut stream, &unimpl.into_bytes()).await;

    // The session survived: a normal exec round-trip still works.
    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"echo alive"))
        .await;
    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout, b"alive\n");
    assert_eq!(exit, Some(0));
}

#[tokio::test]
async fn global_request_replies_only_when_want_reply() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    // want_reply = TRUE → exactly one REQUEST_FAILURE (RFC 4254 §4).
    client
        .write_sealed(&mut stream, &global_request(b"keepalive@openssh.com", true))
        .await;
    assert_eq!(client.read_sealed(&mut stream).await, vec![82]);

    // want_reply = FALSE → no reply at all: the server's next packet
    // belongs to the channel open that follows (a spurious
    // REQUEST_FAILURE here would fail expect_open_confirmation).
    client
        .write_sealed(
            &mut stream,
            &global_request(b"no-more-sessions@openssh.com", false),
        )
        .await;
    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"echo paired"))
        .await;
    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout, b"paired\n");
    assert_eq!(exit, Some(0));
}

#[tokio::test]
async fn truncated_global_request_is_rejected() {
    // Fail closed: a GLOBAL_REQUEST without name/want_reply is a
    // protocol violation, not something to guess a reply for.
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &[80]).await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&kex::SSH_MSG_DISCONNECT));
}

#[tokio::test]
async fn packet_threshold_triggers_server_rekey() {
    // Byte and time triggers disabled; only the RFC 4253 §9 packet
    // backstop can fire. Enough output crosses it on the tx side.
    let cipher = "chacha20-poly1305@openssh.com";
    let thresholds = RekeyThresholds {
        max_bytes: u64::MAX,
        max_interval: Duration::from_hours(1),
        max_packets: 40,
        completion_deadline: Duration::from_secs(5),
    };
    let (addr, host_key) = start_server_rekey(Duration::from_secs(30), thresholds).await;
    let (mut stream, mut client, session_id, server_id) =
        authenticate_full(addr, &host_key, cipher).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(
            &mut stream,
            &channel_exec(server_chan, b"head -c 2000000 /dev/zero"),
        )
        .await;

    let mut stdout = Vec::new();
    let mut exit = None;
    let mut rekeyed = false;
    loop {
        let pkt = client.read_sealed(&mut stream).await;
        match pkt.first().copied() {
            Some(20) => {
                client
                    .rekey_as_client(&mut stream, &session_id, &server_id, cipher, Some(pkt))
                    .await;
                rekeyed = true;
            }
            Some(94) => {
                let mut r = Reader::new(&pkt);
                let _ = r.byte();
                let _ = r.uint32();
                let d = r.string(32 * 1024).unwrap();
                stdout.extend_from_slice(d);
                let credit = u32::try_from(d.len()).unwrap();
                client
                    .write_sealed(&mut stream, &window_adjust(server_chan, credit))
                    .await;
            }
            Some(98) => {
                let mut r = Reader::new(&pkt);
                let _ = r.byte();
                let _ = r.uint32();
                if r.string(64).unwrap() == b"exit-status" {
                    let _ = r.boolean();
                    exit = Some(i32::from_ne_bytes(r.uint32().unwrap().to_ne_bytes()));
                }
            }
            Some(97) => break, // CHANNEL_CLOSE
            _ => {}            // SUCCESS, EOF
        }
    }
    assert!(rekeyed, "the packet backstop must have initiated a re-key");
    assert_eq!(
        stdout.len(),
        2_000_000,
        "all output survives the key switch"
    );
    assert_eq!(exit, Some(0));
}

#[tokio::test]
async fn two_connections_are_served_concurrently() {
    let (addr, host_key) = start_server(TEST_BUDGET).await;
    // A holds its slot mid-handshake (server ID read, nothing sent).
    let mut held = connect(addr).await;
    let _ = read_server_id(&mut held).await;
    // B completes a full handshake and authenticates while A is still
    // open — impossible under the Phase-1 sequential spawn-and-join.
    let (stream, sealed) = authenticate(addr, &host_key).await;
    drop((stream, sealed, held));
}

#[tokio::test]
async fn per_source_half_open_cap_refuses_with_no_banner() {
    let limits = Limits {
        max_per_source: 2,
        ..Limits::default()
    };
    let (addr, _hk, _tx, _serve) = start_server_full(
        TEST_BUDGET,
        RekeyThresholds::bsi_defaults(TEST_BUDGET),
        limits,
    )
    .await;
    let mut a = connect(addr).await;
    let _ = read_server_id(&mut a).await;
    let mut b = connect(addr).await;
    let _ = read_server_id(&mut b).await;
    // The third half-open from the same source is refused pre-banner:
    // the socket closes without a single byte (ADR-0028).
    let mut c = connect(addr).await;
    let mut buf = [0u8; 1];
    let n = timeout(TEST_BUDGET, c.read(&mut buf))
        .await
        .expect("refusal within budget")
        .expect("read");
    assert_eq!(n, 0, "refused connection must close without a banner");
    drop((a, b));
}

#[tokio::test]
async fn accept_rate_limit_refuses_after_the_burst() {
    let limits = Limits {
        accept_burst: 2,
        accept_rate: 1,
        ..Limits::default()
    };
    let (addr, _hk, _tx, _serve) = start_server_full(
        TEST_BUDGET,
        RekeyThresholds::bsi_defaults(TEST_BUDGET),
        limits,
    )
    .await;
    let mut a = connect(addr).await;
    let _ = read_server_id(&mut a).await;
    let mut b = connect(addr).await;
    let _ = read_server_id(&mut b).await;
    // Burst exhausted: the third accept inside the same second is
    // refused pre-banner even though half-open slots remain.
    let mut c = connect(addr).await;
    let mut buf = [0u8; 1];
    let n = timeout(TEST_BUDGET, c.read(&mut buf))
        .await
        .expect("refusal within budget")
        .expect("read");
    assert_eq!(n, 0, "rate-limited connection must close without a banner");
    drop((a, b));
}

#[tokio::test]
async fn shutdown_disconnects_pre_auth_immediately_and_serve_returns() {
    let (addr, _hk, tx, serve) = start_server_full(
        TEST_BUDGET,
        RekeyThresholds::bsi_defaults(TEST_BUDGET),
        Limits::default(),
    )
    .await;
    let mut held = connect(addr).await;
    let _ = read_server_id(&mut held).await;
    // Drain deadline far away: a pre-auth connection must not get it.
    tx.send(tokio::time::Instant::now() + Duration::from_secs(61))
        .expect("send shutdown");
    read_to_eof(&mut held).await;
    // The loop drains and returns Ok well before the 60 s deadline.
    let result = timeout(TEST_BUDGET, serve)
        .await
        .expect("serve returns before the deadline")
        .expect("join serve");
    result.expect("clean shutdown");
}

#[tokio::test]
async fn shutdown_drains_an_authenticated_session_at_the_deadline() {
    let (addr, host_key, tx, serve) = start_server_full(
        TEST_BUDGET,
        RekeyThresholds::bsi_defaults(TEST_BUDGET),
        Limits::default(),
    )
    .await;
    let (mut stream, _sealed) = authenticate(addr, &host_key).await;
    let started = std::time::Instant::now();
    let drain = Duration::from_secs(1);
    tx.send(tokio::time::Instant::now() + drain)
        .expect("send shutdown");
    // The authenticated session gets the drain window (not an
    // immediate cut), then closes at the deadline.
    read_to_eof(&mut stream).await;
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "authenticated session was cut before the drain deadline"
    );
    let result = timeout(TEST_BUDGET, serve)
        .await
        .expect("serve returns after the drain")
        .expect("join serve");
    result.expect("clean shutdown");
}
