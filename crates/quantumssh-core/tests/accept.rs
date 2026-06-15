//! Integration tests for the M4 contract: the full post-quantum
//! handshake (M2–M3) plus publickey authentication (M4).
//! — version exchange, ADR-0021 KEXINIT negotiation, the hybrid
//! `mlkem768x25519-sha256` exchange with a verified host-key
//! signature, NEWKEYS, AEAD transport, service request, and the
//! `ssh-userauth` publickey loop. Also retains M3-level denial and
//! rejection paths.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate as _, FromSeed as _, KeyExport as _};
use quantumssh_core::auth;
use quantumssh_core::auth::AuthorizedKeys;
use quantumssh_core::cipher;
use quantumssh_core::host_key::HostKey;
use quantumssh_core::kex;
use quantumssh_core::server::{Config, Server};
use quantumssh_core::wire::{self, Reader, Writer};
use sha2::{Digest, Sha256};
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

const TEST_BUDGET: Duration = Duration::from_secs(5);
const CLIENT_ID: &[u8] = b"SSH-2.0-testclient_0.1";

async fn start_server(handshake_timeout: Duration) -> (SocketAddr, Arc<HostKey>) {
    let host_key = Arc::new(HostKey::from_seed([11u8; 32]));
    // Create a temp authorized_keys with the test key so the server
    // can start (authorized_keys is mandatory). Use a well-known seed.
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let ak_path = temp_authorized_keys(&auth_signing);
    let authorized_keys = Arc::new(AuthorizedKeys::load(&ak_path).expect("load test ak"));
    let config = Config {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        handshake_timeout,
        host_key: Arc::clone(&host_key),
        authorized_keys,
    };
    let server = Server::bind(&config).await.expect("bind ephemeral port");
    let addr = server.local_addr().expect("local addr");
    drop(tokio::spawn(server.serve()));
    (addr, host_key)
}

async fn connect(addr: SocketAddr) -> TcpStream {
    timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect")
}

/// Reads the server identification line.
async fn read_server_id(stream: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let b = timeout(TEST_BUDGET, stream.read_u8())
            .await
            .expect("id byte within budget")
            .expect("read id byte");
        if b == b'\n' {
            break;
        }
        line.push(b);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    line
}

/// Reads one unencrypted packet's payload.
async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    timeout(TEST_BUDGET, stream.read_exact(&mut len))
        .await
        .expect("packet length within budget")
        .expect("read length");
    let body_len = wire::validate_packet_length(u32::from_be_bytes(len)).expect("valid length");
    let mut body = vec![0u8; body_len];
    timeout(TEST_BUDGET, stream.read_exact(&mut body))
        .await
        .expect("packet body within budget")
        .expect("read body");
    wire::decode_packet_body(&body)
        .expect("valid body")
        .to_vec()
}

async fn write_packet(stream: &mut TcpStream, payload: &[u8]) {
    let packet = wire::encode_packet(payload).expect("encode");
    stream.write_all(&packet).await.expect("write packet");
}

/// A stock-OpenSSH-like client KEXINIT with the given KEX and cipher
/// lists. Returns the exact payload (kept as `I_C`).
fn client_kexinit(kex_list: &str, ciphers: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(kex::SSH_MSG_KEXINIT);
    w.put_bytes(&[7u8; 16]);
    w.put_name_list(kex_list);
    w.put_name_list("ssh-ed25519,rsa-sha2-512");
    w.put_name_list(ciphers);
    w.put_name_list(ciphers);
    w.put_name_list("umac-64-etm@openssh.com,hmac-sha2-256");
    w.put_name_list("umac-64-etm@openssh.com,hmac-sha2-256");
    w.put_name_list("none,zlib@openssh.com");
    w.put_name_list("none,zlib@openssh.com");
    w.put_name_list("");
    w.put_name_list("");
    w.put_boolean(false);
    w.put_uint32(0);
    w.into_bytes()
}

/// The KEX list of a stock OpenSSH client that offers `ext-info-c`.
const OPENSSH_KEX_EXT_INFO: &str =
    "mlkem768x25519-sha256,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com";
/// The same client without the `ext-info-c` marker.
const OPENSSH_KEX_PLAIN: &str =
    "mlkem768x25519-sha256,curve25519-sha256,kex-strict-c-v00@openssh.com";

/// Client-side outcome of a completed handshake: the agreed secret,
/// the exchange hash (= session id on the first exchange), and the
/// AEAD ciphers installed for both directions, sequence counters
/// freshly reset per strict-kex.
struct SealedClient {
    /// Seals client→server packets.
    tx: cipher::PacketCipher,
    /// Opens server→client packets.
    rx: cipher::PacketCipher,
    seq_tx: u32,
    seq_rx: u32,
}

impl SealedClient {
    async fn read_sealed(&mut self, stream: &mut TcpStream) -> Vec<u8> {
        let mut length_bytes = [0u8; 4];
        timeout(TEST_BUDGET, stream.read_exact(&mut length_bytes))
            .await
            .expect("sealed length within budget")
            .expect("read sealed length");
        let body_len = self
            .rx
            .body_len(self.seq_rx, length_bytes)
            .expect("valid sealed length");
        let mut body = vec![0u8; body_len];
        timeout(TEST_BUDGET, stream.read_exact(&mut body))
            .await
            .expect("sealed body within budget")
            .expect("read sealed body");
        let payload = self
            .rx
            .open(self.seq_rx, length_bytes, &mut body)
            .expect("authentic packet");
        self.seq_rx += 1;
        payload
    }

    async fn write_sealed(&mut self, stream: &mut TcpStream, payload: &[u8]) {
        let packet = self.tx.seal(self.seq_tx, payload).expect("seal");
        stream.write_all(&packet).await.expect("write sealed");
        self.seq_tx += 1;
    }
}

/// Drives the complete handshake from the client side — verifying the
/// server's Ed25519 signature over the recomputed exchange hash — and
/// returns the installed client-side AEAD transport and the `session_id`.
async fn establish(
    stream: &mut TcpStream,
    host_key: &HostKey,
    kex_list: &str,
    ciphers: &str,
    negotiated_cipher: &str,
) -> (SealedClient, [u8; 32]) {
    // Version exchange.
    let server_id = read_server_id(stream).await;
    assert!(server_id.starts_with(b"SSH-2.0-quantumssh_"));
    stream.write_all(CLIENT_ID).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();

    // KEXINIT exchange.
    let i_s = read_packet(stream).await;
    assert_eq!(i_s.first(), Some(&kex::SSH_MSG_KEXINIT));
    let i_c = client_kexinit(kex_list, ciphers);
    write_packet(stream, &i_c).await;

    // Hybrid init: fresh client keypair.
    let seed = ml_kem::Seed::try_from(&[5u8; 64][..]).unwrap();
    let (dk, ek) = MlKem768::from_seed(&seed);
    let x_secret = XSecret::from([21u8; 32]);
    let mut c_init = Vec::with_capacity(kex::CLIENT_INIT_LEN);
    c_init.extend_from_slice(ek.to_bytes().as_slice());
    c_init.extend_from_slice(XPublic::from(&x_secret).as_bytes());

    let mut init = Writer::new();
    init.put_byte(kex::SSH_MSG_KEX_HYBRID_INIT);
    init.put_string(&c_init);
    write_packet(stream, &init.into_bytes()).await;

    // Hybrid reply: K_S ‖ S_REPLY ‖ signature.
    let reply = read_packet(stream).await;
    let mut r = Reader::new(&reply);
    assert_eq!(r.byte().unwrap(), kex::SSH_MSG_KEX_HYBRID_REPLY);
    let k_s = r.string(256).unwrap();
    let s_reply = r.string(kex::SERVER_REPLY_LEN).unwrap();
    let sig_blob = r.string(256).unwrap();
    r.finish().unwrap();

    // The host key blob must be the server's.
    assert_eq!(k_s, host_key.public_key_blob());

    // Client side of the secret.
    let (ct_bytes, server_x) = s_reply.split_at(kex::MLKEM_CT_LEN);
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes).unwrap();
    let k_pq = dk.decapsulate(&ct);
    let server_pk: [u8; 32] = server_x.try_into().unwrap();
    let k_cl = x_secret.diffie_hellman(&XPublic::from(server_pk));
    let mut h = Sha256::new();
    h.update(k_pq.as_slice());
    h.update(k_cl.as_bytes());
    let shared: [u8; 32] = h.finalize().into();

    // Recompute H exactly as the server must have, and verify the
    // signature over it with the server's public key — the proof the
    // whole exchange (identities, KEXINITs, K) matches end to end.
    let hash = kex::exchange_hash(&kex::ExchangeHashInputs {
        client_id: CLIENT_ID,
        server_id: &server_id,
        client_kexinit: &i_c,
        server_kexinit: &i_s,
        host_key_blob: k_s,
        client_init: &c_init,
        server_reply: s_reply,
        shared_secret: &shared,
    });
    let mut sig_reader = Reader::new(sig_blob);
    assert_eq!(sig_reader.string(64).unwrap(), b"ssh-ed25519");
    let sig_bytes: [u8; 64] = sig_reader.string(128).unwrap().try_into().unwrap();
    let mut ks_reader = Reader::new(k_s);
    ks_reader.string(64).unwrap();
    let vk_bytes: [u8; 32] = ks_reader.string(64).unwrap().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
    vk.verify(&hash, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
        .expect("server signature over H must verify");

    // NEWKEYS both ways.
    let newkeys = read_packet(stream).await;
    assert_eq!(newkeys, vec![kex::SSH_MSG_NEWKEYS]);
    write_packet(stream, &[kex::SSH_MSG_NEWKEYS]).await;

    // RFC 4253 §7.2 key schedule, client side: tx = client→server
    // ('C' key, 'A' IV), rx = server→client ('D', 'B'). The session
    // id is the first exchange hash; strict-kex resets both counters.
    let session_id: [u8; 32] = hash.as_slice().try_into().unwrap();
    let derive = |letter: u8, len: usize| {
        let mut out = kex::derive_key(&shared, &hash, letter, &session_id, len);
        out.truncate(len);
        out
    };
    let name = negotiated_cipher;
    let tx = cipher::PacketCipher::new(
        name,
        &derive(b'C', cipher::PacketCipher::key_len(name)),
        &derive(b'A', cipher::PacketCipher::iv_len(name)),
    )
    .expect("client tx cipher");
    let rx = cipher::PacketCipher::new(
        name,
        &derive(b'D', cipher::PacketCipher::key_len(name)),
        &derive(b'B', cipher::PacketCipher::iv_len(name)),
    )
    .expect("client rx cipher");
    (
        SealedClient {
            tx,
            rx,
            seq_tx: 0,
            seq_rx: 0,
        },
        session_id,
    )
}

/// The encrypted `SSH_MSG_SERVICE_REQUEST` for `ssh-userauth`.
fn service_request_payload() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(5); // SSH_MSG_SERVICE_REQUEST
    w.put_string(b"ssh-userauth");
    w.into_bytes()
}

/// Service request for an unsupported service — triggers the deny path.
fn unsupported_service_request() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(5);
    w.put_string(b"ssh-connection");
    w.into_bytes()
}

/// Writes a temporary `authorized_keys` file with the given Ed25519 key.
fn temp_authorized_keys(signing: &SigningKey) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let vk = signing.verifying_key();
    let blob = auth_test_blob(&vk);
    let b64 = quantumssh_core::host_key::base64_encode_nopad(&blob);
    let dir = std::env::temp_dir();
    let path = dir.join(format!("quantumssh-test-ak-{n}.txt"));
    let mut f = std::fs::File::create(&path).expect("create temp ak file");
    writeln!(f, "ssh-ed25519 {b64} test-key").expect("write ak");
    path
}

/// Builds the wire-format key blob for an Ed25519 verifying key.
fn auth_test_blob(vk: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(b"ssh-ed25519");
    w.put_string(vk.as_bytes());
    w.into_bytes()
}

/// Asserts a sealed DISCONNECT with `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`.
fn assert_service_denied(payload: &[u8]) {
    let mut r = Reader::new(payload);
    assert_eq!(r.byte().unwrap(), kex::SSH_MSG_DISCONNECT);
    assert_eq!(
        r.uint32().unwrap(),
        7,
        "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE"
    );
}

#[tokio::test]
async fn full_handshake_then_encrypted_ext_info_and_service_denial_chacha20() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id) = establish(
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
    let (mut client, _session_id) = establish(
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
    let (mut client, _session_id) = establish(
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

/// Expects a DISCONNECT packet with the given code.
async fn expect_disconnect(stream: &mut TcpStream, code: u32) {
    let payload = read_packet(stream).await;
    let mut r = Reader::new(&payload);
    assert_eq!(r.byte().unwrap(), kex::SSH_MSG_DISCONNECT);
    assert_eq!(r.uint32().unwrap(), code, "disconnect code");
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

// --------------------------------------------------------------------
// M4 — authentication tests
// --------------------------------------------------------------------

/// Builds a `SSH_MSG_USERAUTH_REQUEST` with a valid publickey
/// signature, ready to be sealed and sent.
fn signed_auth_request(signing: &SigningKey, session_id: &[u8; 32], key_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    w.put_string(b"testuser");
    w.put_string(b"ssh-connection");
    w.put_string(b"publickey");
    w.put_boolean(true);
    w.put_string(b"ssh-ed25519");
    w.put_string(key_blob);
    let payload_without_sig = w.into_bytes();

    let signed = auth::auth_signed_data(session_id, &payload_without_sig);
    let sig = signing.sign(&signed);

    let mut full = Writer::new();
    full.put_bytes(&payload_without_sig);
    full.put_string(sig.to_bytes().as_ref());
    full.into_bytes()
}

/// Builds a `SSH_MSG_USERAUTH_REQUEST` with `signature_present = false`.
fn probe_auth_request(key_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    w.put_string(b"testuser");
    w.put_string(b"ssh-connection");
    w.put_string(b"publickey");
    w.put_boolean(false);
    w.put_string(b"ssh-ed25519");
    w.put_string(key_blob);
    w.into_bytes()
}

#[tokio::test]
async fn auth_success_then_channel_rejection() {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let auth_vk = auth_signing.verifying_key();
    let key_blob = auth_test_blob(&auth_vk);

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, session_id) = establish(
        &mut stream,
        &host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;

    // Request ssh-userauth → expect SERVICE_ACCEPT.
    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    let service_reply = client.read_sealed(&mut stream).await;
    let mut r = Reader::new(&service_reply);
    assert_eq!(r.byte().unwrap(), 6, "SSH_MSG_SERVICE_ACCEPT");

    // Send a valid signed auth request → expect SUCCESS.
    client
        .write_sealed(
            &mut stream,
            &signed_auth_request(&auth_signing, &session_id, &key_blob),
        )
        .await;
    let auth_reply = client.read_sealed(&mut stream).await;
    assert_eq!(auth_reply, vec![auth::SSH_MSG_USERAUTH_SUCCESS]);

    // Send channel-open → expect CHANNEL_OPEN_FAILURE.
    let mut ch = Writer::new();
    ch.put_byte(90); // SSH_MSG_CHANNEL_OPEN
    ch.put_string(b"session");
    ch.put_uint32(0);
    ch.put_uint32(2 * 1024 * 1024);
    ch.put_uint32(32 * 1024);
    client.write_sealed(&mut stream, &ch.into_bytes()).await;
    let ch_reply = client.read_sealed(&mut stream).await;
    let mut cr = Reader::new(&ch_reply);
    assert_eq!(cr.byte().unwrap(), 92, "SSH_MSG_CHANNEL_OPEN_FAILURE");
}

#[tokio::test]
async fn auth_failure_on_wrong_signature() {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let auth_vk = auth_signing.verifying_key();
    let key_blob = auth_test_blob(&auth_vk);

    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let mut stream = connect(addr).await;
    let (mut client, _session_id) = establish(
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
    w.put_string(&[0u8; 64]); // wrong "signature"
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
    let (mut client, _session_id) = establish(
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
    let (mut client, session_id) = establish(
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
    let (mut client, _session_id) = establish(
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
        w.put_string(&[0u8; 64]);
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
