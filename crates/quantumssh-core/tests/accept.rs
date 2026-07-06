//! Integration tests for the Phase 1 contract: the full post-quantum
//! handshake (M2–M3), publickey authentication (M4), and the channel
//! layer with single-command `exec` (M5).
//! — version exchange, ADR-0021 KEXINIT negotiation, the hybrid
//! `mlkem768x25519-sha256` exchange with a verified host-key
//! signature, NEWKEYS, AEAD transport, service request, the
//! `ssh-userauth` publickey loop, and the one `session` channel /
//! `exec` flow (open → exec → data → exit-status → close, ADR-0023).
//! Also retains M3-level denial and rejection paths.

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
use quantumssh_core::transport::RekeyThresholds;
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
    start_server_rekey(
        handshake_timeout,
        RekeyThresholds::bsi_defaults(handshake_timeout),
    )
    .await
}

async fn start_server_rekey(
    handshake_timeout: Duration,
    rekey: RekeyThresholds,
) -> (SocketAddr, Arc<HostKey>) {
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
        rekey,
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
/// returns the installed client-side AEAD transport, the `session_id`,
/// and the server identification line (for recomputing a re-key `H_r`).
async fn establish(
    stream: &mut TcpStream,
    host_key: &HostKey,
    kex_list: &str,
    ciphers: &str,
    negotiated_cipher: &str,
) -> (SealedClient, [u8; 32], Vec<u8>) {
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
        server_id,
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

    // RFC 8709 §6: signature blob is string("ssh-ed25519") + string(raw_sig)
    let mut sig_blob = Writer::new();
    sig_blob.put_string(b"ssh-ed25519");
    sig_blob.put_string(sig.to_bytes().as_ref());

    let mut full = Writer::new();
    full.put_bytes(&payload_without_sig);
    full.put_string(&sig_blob.into_bytes());
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

// ---- M5: channel layer + exec (ADR-0023) ----

/// Authenticates with the test key and returns the encrypted client ready
/// to drive the channel layer.
async fn authenticate(addr: SocketAddr, host_key: &HostKey) -> (TcpStream, SealedClient) {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let key_blob = auth_test_blob(&auth_signing.verifying_key());
    let mut stream = connect(addr).await;
    let (mut client, session_id, _server_id) = establish(
        &mut stream,
        host_key,
        OPENSSH_KEX_PLAIN,
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
    )
    .await;
    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    assert_eq!(client.read_sealed(&mut stream).await.first(), Some(&6));
    client
        .write_sealed(
            &mut stream,
            &signed_auth_request(&auth_signing, &session_id, &key_blob),
        )
        .await;
    assert_eq!(
        client.read_sealed(&mut stream).await,
        vec![auth::SSH_MSG_USERAUTH_SUCCESS]
    );
    (stream, client)
}

const CH_OPEN: u8 = 90;
const CH_OPEN_CONFIRMATION: u8 = 91;
const CH_OPEN_FAILURE: u8 = 92;
const CH_WINDOW_ADJUST: u8 = 93;
const CH_DATA: u8 = 94;
const CH_EXTENDED_DATA: u8 = 95;
const CH_EOF: u8 = 96;
const CH_CLOSE: u8 = 97;
const CH_REQUEST: u8 = 98;
const CH_FAILURE: u8 = 100;

fn channel_open(sender: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_OPEN);
    w.put_string(b"session");
    w.put_uint32(sender);
    w.put_uint32(2 * 1024 * 1024);
    w.put_uint32(32 * 1024);
    w.into_bytes()
}

fn channel_open_type(sender: u32, ctype: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_OPEN);
    w.put_string(ctype);
    w.put_uint32(sender);
    w.put_uint32(2 * 1024 * 1024);
    w.put_uint32(32 * 1024);
    w.into_bytes()
}

fn channel_exec(recipient: u32, command: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(b"exec");
    w.put_boolean(true);
    w.put_string(command);
    w.into_bytes()
}

fn channel_request(recipient: u32, rtype: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(rtype);
    w.put_boolean(true);
    w.into_bytes()
}

fn channel_data(recipient: u32, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_DATA);
    w.put_uint32(recipient);
    w.put_string(data);
    w.into_bytes()
}

fn channel_one_field(msg: u8, recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(msg);
    w.put_uint32(recipient);
    w.into_bytes()
}

fn window_adjust(recipient: u32, add: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_WINDOW_ADJUST);
    w.put_uint32(recipient);
    w.put_uint32(add);
    w.into_bytes()
}

/// `SSH_MSG_GLOBAL_REQUEST` (RFC 4254 §4).
fn global_request(name: &[u8], want_reply: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(80);
    w.put_string(name);
    w.put_boolean(want_reply);
    w.into_bytes()
}

/// Reads the `OPEN_CONFIRMATION`, returning the server's channel id.
async fn expect_open_confirmation(client: &mut SealedClient, stream: &mut TcpStream) -> u32 {
    let conf = client.read_sealed(stream).await;
    let mut r = Reader::new(&conf);
    assert_eq!(r.byte().unwrap(), CH_OPEN_CONFIRMATION);
    let _recipient = r.uint32().unwrap();
    r.uint32().unwrap() // server's sender channel id
}

/// Drains the session: accumulates stdout/stderr (returning window credit
/// as it goes, so a >2 MiB stream does not stall), captures the
/// `exit-status`, and stops at `CHANNEL_CLOSE`.
async fn collect_session(
    client: &mut SealedClient,
    stream: &mut TcpStream,
    server_chan: u32,
) -> (Vec<u8>, Vec<u8>, Option<i32>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    loop {
        let pkt = client.read_sealed(stream).await;
        let mut r = Reader::new(&pkt);
        match r.byte().unwrap() {
            CH_DATA => {
                let _ = r.uint32().unwrap();
                let d = r.string(32 * 1024).unwrap();
                stdout.extend_from_slice(d);
                let credit = u32::try_from(d.len()).unwrap();
                client
                    .write_sealed(stream, &window_adjust(server_chan, credit))
                    .await;
            }
            CH_EXTENDED_DATA => {
                let _ = r.uint32().unwrap();
                let _code = r.uint32().unwrap();
                let d = r.string(32 * 1024).unwrap();
                stderr.extend_from_slice(d);
                let credit = u32::try_from(d.len()).unwrap();
                client
                    .write_sealed(stream, &window_adjust(server_chan, credit))
                    .await;
            }
            CH_REQUEST => {
                let _ = r.uint32().unwrap();
                let req = r.string(64).unwrap().to_vec();
                let _ = r.boolean().unwrap();
                if req == b"exit-status" {
                    exit = Some(i32::from_ne_bytes(r.uint32().unwrap().to_ne_bytes()));
                }
            }
            CH_CLOSE => return (stdout, stderr, exit),
            _ => {} // CHANNEL_SUCCESS, CHANNEL_EOF: ignore
        }
    }
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
async fn exec_stderr_is_extended_data() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"echo oops 1>&2"))
        .await;

    let (stdout, stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert!(stdout.is_empty());
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
async fn pty_req_is_refused() {
    let (addr, host_key) = start_server(Duration::from_secs(30)).await;
    let (mut stream, mut client) = authenticate(addr, &host_key).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_request(server_chan, b"pty-req"))
        .await;
    let reply = client.read_sealed(&mut stream).await;
    assert_eq!(reply.first(), Some(&CH_FAILURE));
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

// ---- M6: re-keying (ADR-0026) ----

/// Like `authenticate`, but returns the `session_id` and server id line a
/// re-key needs, and the cipher is selectable.
async fn authenticate_full(
    addr: SocketAddr,
    host_key: &HostKey,
    cipher: &str,
) -> (TcpStream, SealedClient, [u8; 32], Vec<u8>) {
    let auth_signing = SigningKey::from_bytes(&[77u8; 32]);
    let key_blob = auth_test_blob(&auth_signing.verifying_key());
    let mut stream = connect(addr).await;
    let (mut client, session_id, server_id) =
        establish(&mut stream, host_key, OPENSSH_KEX_PLAIN, cipher, cipher).await;
    client
        .write_sealed(&mut stream, &service_request_payload())
        .await;
    assert_eq!(client.read_sealed(&mut stream).await.first(), Some(&6));
    client
        .write_sealed(
            &mut stream,
            &signed_auth_request(&auth_signing, &session_id, &key_blob),
        )
        .await;
    assert_eq!(
        client.read_sealed(&mut stream).await,
        vec![auth::SSH_MSG_USERAUTH_SUCCESS]
    );
    (stream, client, session_id, server_id)
}

/// Re-key thresholds for tests: generous deadline; bytes and interval set
/// by the caller (`u64::MAX` / 1 h disables a trigger).
const fn test_rekey(max_bytes: u64) -> RekeyThresholds {
    RekeyThresholds {
        max_bytes,
        max_interval: Duration::from_hours(1),
        max_packets: u32::MAX,
        completion_deadline: Duration::from_secs(5),
    }
}

impl SealedClient {
    /// Drives a client-initiated encrypted re-key (RFC 4253 §9): send our
    /// KEXINIT, exchange the hybrid, verify the signature over the
    /// recomputed `H_r`, swap NEWKEYS, and install the new ciphers derived
    /// with the ORIGINAL `session_id` and the new `H_r`.
    async fn rekey_as_client(
        &mut self,
        stream: &mut TcpStream,
        session_id: &[u8; 32],
        server_id: &[u8],
        cipher: &str,
        server_kexinit: Option<Vec<u8>>,
    ) {
        // 1. Our KEXINIT (encrypted); the strict marker is ignored on re-key.
        let i_c = client_kexinit(OPENSSH_KEX_PLAIN, cipher);
        self.write_sealed(stream, &i_c).await;
        // 2. Server's KEXINIT — already received if the server initiated.
        let i_s = if let Some(is) = server_kexinit {
            is
        } else {
            let is = self.read_sealed(stream).await;
            assert_eq!(is.first(), Some(&kex::SSH_MSG_KEXINIT));
            is
        };
        // 3. HYBRID_INIT with a fresh keypair.
        let seed = ml_kem::Seed::try_from(&[9u8; 64][..]).unwrap();
        let (dk, ek) = MlKem768::from_seed(&seed);
        let x_secret = XSecret::from([42u8; 32]);
        let mut c_init = Vec::with_capacity(kex::CLIENT_INIT_LEN);
        c_init.extend_from_slice(ek.to_bytes().as_slice());
        c_init.extend_from_slice(XPublic::from(&x_secret).as_bytes());
        let mut init = Writer::new();
        init.put_byte(kex::SSH_MSG_KEX_HYBRID_INIT);
        init.put_string(&c_init);
        self.write_sealed(stream, &init.into_bytes()).await;
        // 4. HYBRID_REPLY: recompute H_r, verify the signature.
        let reply = self.read_sealed(stream).await;
        let mut r = Reader::new(&reply);
        assert_eq!(r.byte().unwrap(), kex::SSH_MSG_KEX_HYBRID_REPLY);
        let k_s = r.string(256).unwrap();
        let s_reply = r.string(kex::SERVER_REPLY_LEN).unwrap();
        let sig_blob = r.string(256).unwrap();
        r.finish().unwrap();
        let (ct_bytes, server_x) = s_reply.split_at(kex::MLKEM_CT_LEN);
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes).unwrap();
        let k_pq = dk.decapsulate(&ct);
        let server_pk: [u8; 32] = server_x.try_into().unwrap();
        let k_cl = x_secret.diffie_hellman(&XPublic::from(server_pk));
        let mut h = Sha256::new();
        h.update(k_pq.as_slice());
        h.update(k_cl.as_bytes());
        let shared: [u8; 32] = h.finalize().into();
        let h_r = kex::exchange_hash(&kex::ExchangeHashInputs {
            client_id: CLIENT_ID,
            server_id,
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
        vk.verify(&h_r, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("re-key signature over H_r must verify");

        // The new key schedule uses the ORIGINAL session id and the new H_r.
        let derive = |letter: u8, len: usize| {
            let mut out = kex::derive_key(&shared, &h_r, letter, session_id, len);
            out.truncate(len);
            out
        };
        // 5. Server NEWKEYS → install our new rx (server→client, D/B); reset.
        assert_eq!(self.read_sealed(stream).await, vec![kex::SSH_MSG_NEWKEYS]);
        self.rx = cipher::PacketCipher::new(
            cipher,
            &derive(b'D', cipher::PacketCipher::key_len(cipher)),
            &derive(b'B', cipher::PacketCipher::iv_len(cipher)),
        )
        .expect("client re-key rx");
        self.seq_rx = 0;
        // 6. Our NEWKEYS under the OLD tx → install our new tx (C/A); reset.
        self.write_sealed(stream, &[kex::SSH_MSG_NEWKEYS]).await;
        self.tx = cipher::PacketCipher::new(
            cipher,
            &derive(b'C', cipher::PacketCipher::key_len(cipher)),
            &derive(b'A', cipher::PacketCipher::iv_len(cipher)),
        )
        .expect("client re-key tx");
        self.seq_tx = 0;
    }
}

/// Runs a client-initiated re-key mid-session and confirms data flows under
/// the new keys, for the given cipher.
async fn rekey_roundtrip(cipher: &str) {
    let (addr, host_key) = start_server_rekey(Duration::from_secs(30), test_rekey(u64::MAX)).await;
    let (mut stream, mut client, session_id, server_id) =
        authenticate_full(addr, &host_key, cipher).await;

    client.write_sealed(&mut stream, &channel_open(0)).await;
    let server_chan = expect_open_confirmation(&mut client, &mut stream).await;
    client
        .write_sealed(&mut stream, &channel_exec(server_chan, b"cat"))
        .await;
    // CHANNEL_SUCCESS arrives before we re-key.
    assert_eq!(client.read_sealed(&mut stream).await.first(), Some(&99));

    client
        .rekey_as_client(&mut stream, &session_id, &server_id, cipher, None)
        .await;

    // Data flows under the new keys: stdin echoed back by `cat`.
    client
        .write_sealed(&mut stream, &channel_data(server_chan, b"after-rekey"))
        .await;
    client
        .write_sealed(&mut stream, &channel_one_field(CH_EOF, server_chan))
        .await;
    let (stdout, _stderr, exit) = collect_session(&mut client, &mut stream, server_chan).await;
    assert_eq!(stdout, b"after-rekey");
    assert_eq!(exit, Some(0));
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
