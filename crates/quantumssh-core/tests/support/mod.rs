//! The SSH test client shared by the integration tests: a real
//! client over `quantumssh_core`'s public primitives — hybrid KEX,
//! sealed transport, publickey auth and channel frames — and helpers
//! that start an in-process server. Included by `accept.rs` and, through
//! `#[path]`, by the binary crate's PTY tests (ADR-0038 §11).

// Each including test crate uses a different subset.
#![allow(dead_code)]

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate as _, FromSeed as _, KeyExport as _};
use quantumssh_core::admission::Limits;
use quantumssh_core::auth;
use quantumssh_core::auth::AuthorizedKeys;
use quantumssh_core::cert::{self, TrustedUserCaKeys};
use quantumssh_core::cipher;
use quantumssh_core::host_key::HostKey;
use quantumssh_core::kex;
use quantumssh_core::server::{Config, Server};
use quantumssh_core::transport::RekeyThresholds;
use quantumssh_core::wire::{self, Reader, Writer};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::{Duration, timeout};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

pub const TEST_BUDGET: Duration = Duration::from_secs(5);

pub const CLIENT_ID: &[u8] = b"SSH-2.0-testclient_0.1";

pub async fn start_server(handshake_timeout: Duration) -> (SocketAddr, Arc<HostKey>) {
    start_server_rekey(
        handshake_timeout,
        RekeyThresholds::bsi_defaults(handshake_timeout),
    )
    .await
}

pub async fn start_server_rekey(
    handshake_timeout: Duration,
    rekey: RekeyThresholds,
) -> (SocketAddr, Arc<HostKey>) {
    let (addr, host_key, _tx, _serve) =
        start_server_full(handshake_timeout, rekey, Limits::default()).await;
    (addr, host_key)
}

/// Full-control variant: custom limits, plus the shutdown sender and
/// the serve task handle for the ADR-0028 tests.
pub async fn start_server_full(
    handshake_timeout: Duration,
    rekey: RekeyThresholds,
    limits: Limits,
) -> (
    SocketAddr,
    Arc<HostKey>,
    broadcast::Sender<tokio::time::Instant>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    start_server_configured(handshake_timeout, rekey, limits, None, None).await
}

/// A server whose PTY children re-execute `helper` (ADR-0038 §5).
pub async fn start_server_with_helper(helper: std::path::PathBuf) -> (SocketAddr, Arc<HostKey>) {
    let budget = Duration::from_secs(30);
    let (addr, host_key, _tx, _serve) = start_server_configured(
        budget,
        RekeyThresholds::bsi_defaults(budget),
        Limits::default(),
        Some(helper),
        None,
    )
    .await;
    (addr, host_key)
}

/// A server that trusts [`test_ca`] for user certificates (ADR-0050),
/// whose PTY and SFTP children re-execute `helper` when one is given.
pub async fn start_server_with_ca(
    helper: Option<std::path::PathBuf>,
) -> (SocketAddr, Arc<HostKey>) {
    let cas = TrustedUserCaKeys::load(&temp_authorized_keys(&test_ca())).expect("load test CA");
    let budget = Duration::from_secs(30);
    let (addr, host_key, _tx, _serve) = start_server_configured(
        budget,
        RekeyThresholds::bsi_defaults(budget),
        Limits::default(),
        helper,
        Some(Arc::new(cas)),
    )
    .await;
    (addr, host_key)
}

pub async fn start_server_configured(
    handshake_timeout: Duration,
    rekey: RekeyThresholds,
    limits: Limits,
    helper: Option<std::path::PathBuf>,
    trusted_user_ca_keys: Option<Arc<TrustedUserCaKeys>>,
) -> (
    SocketAddr,
    Arc<HostKey>,
    broadcast::Sender<tokio::time::Instant>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
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
        trusted_user_ca_keys,
        rekey,
        limits,
        helper,
    };
    let server = Server::bind(&config).await.expect("bind ephemeral port");
    let addr = server.local_addr().expect("local addr");
    let (tx, loop_rx) = broadcast::channel(4);
    let serve = tokio::spawn(server.serve(tx.clone(), loop_rx));
    (addr, host_key, tx, serve)
}

pub async fn connect(addr: SocketAddr) -> TcpStream {
    timeout(TEST_BUDGET, TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("tcp connect")
}

/// Reads the server identification line.
pub async fn read_server_id(stream: &mut TcpStream) -> Vec<u8> {
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
pub async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
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

pub async fn write_packet(stream: &mut TcpStream, payload: &[u8]) {
    let packet = wire::encode_packet(payload).expect("encode");
    stream.write_all(&packet).await.expect("write packet");
}

/// A stock-OpenSSH-like client KEXINIT with the given KEX and cipher
/// lists. Returns the exact payload (kept as `I_C`).
pub fn client_kexinit(kex_list: &str, ciphers: &str) -> Vec<u8> {
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
pub const OPENSSH_KEX_EXT_INFO: &str =
    "mlkem768x25519-sha256,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com";

/// The same client without the `ext-info-c` marker.
pub const OPENSSH_KEX_PLAIN: &str =
    "mlkem768x25519-sha256,curve25519-sha256,kex-strict-c-v00@openssh.com";

/// Client-side outcome of a completed handshake: the agreed secret,
/// the exchange hash (= session id on the first exchange), and the
/// AEAD ciphers installed for both directions, sequence counters
/// freshly reset per strict-kex.
pub struct SealedClient {
    /// Seals client→server packets.
    pub tx: cipher::PacketCipher,
    /// Opens server→client packets.
    pub rx: cipher::PacketCipher,
    pub seq_tx: u32,
    pub seq_rx: u32,
}

impl SealedClient {
    pub async fn read_sealed(&mut self, stream: &mut TcpStream) -> Vec<u8> {
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

    pub async fn write_sealed(&mut self, stream: &mut TcpStream, payload: &[u8]) {
        let packet = self.tx.seal(self.seq_tx, payload).expect("seal");
        stream.write_all(&packet).await.expect("write sealed");
        self.seq_tx += 1;
    }
}

/// Drives the complete handshake from the client side — verifying the
/// server's Ed25519 signature over the recomputed exchange hash — and
/// returns the installed client-side AEAD transport, the `session_id`,
/// and the server identification line (for recomputing a re-key `H_r`).
pub async fn establish(
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
pub fn service_request_payload() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(5); // SSH_MSG_SERVICE_REQUEST
    w.put_string(b"ssh-userauth");
    w.into_bytes()
}

/// Service request for an unsupported service — triggers the deny path.
pub fn unsupported_service_request() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(5);
    w.put_string(b"ssh-connection");
    w.into_bytes()
}

/// Writes a temporary `authorized_keys` file with the given Ed25519 key.
pub fn temp_authorized_keys(signing: &SigningKey) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let vk = signing.verifying_key();
    let blob = auth_test_blob(&vk);
    let b64 = quantumssh_core::host_key::base64_encode_nopad(&blob);
    let dir = std::env::temp_dir();
    // The process ID keeps test binaries that run at once apart.
    let path = dir.join(format!("quantumssh-test-ak-{}-{n}.txt", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create temp ak file");
    writeln!(f, "ssh-ed25519 {b64} test-key").expect("write ak");
    path
}

/// Builds the wire-format key blob for an Ed25519 verifying key.
pub fn auth_test_blob(vk: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(b"ssh-ed25519");
    w.put_string(vk.as_bytes());
    w.into_bytes()
}

/// Asserts a sealed DISCONNECT with `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`.
pub fn assert_service_denied(payload: &[u8]) {
    let mut r = Reader::new(payload);
    assert_eq!(r.byte().unwrap(), kex::SSH_MSG_DISCONNECT);
    assert_eq!(
        r.uint32().unwrap(),
        7,
        "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE"
    );
}

/// Expects a DISCONNECT packet with the given code.
pub async fn expect_disconnect(stream: &mut TcpStream, code: u32) {
    let payload = read_packet(stream).await;
    let mut r = Reader::new(&payload);
    assert_eq!(r.byte().unwrap(), kex::SSH_MSG_DISCONNECT);
    assert_eq!(r.uint32().unwrap(), code, "disconnect code");
}

// --------------------------------------------------------------------
// M4 — authentication tests
// --------------------------------------------------------------------

/// Builds a `SSH_MSG_USERAUTH_REQUEST` with a valid publickey
/// signature, ready to be sealed and sent.
pub fn signed_auth_request(
    signing: &SigningKey,
    session_id: &[u8; 32],
    key_blob: &[u8],
) -> Vec<u8> {
    signed_auth_request_for(signing, session_id, b"ssh-ed25519", key_blob)
}

/// [`signed_auth_request`] for a key `algorithm`: `ssh-ed25519`, or
/// [`cert::CERT_ALGORITHM`] with a certificate blob.
pub fn signed_auth_request_for(
    signing: &SigningKey,
    session_id: &[u8; 32],
    algorithm: &[u8],
    key_blob: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    w.put_string(b"testuser");
    w.put_string(b"ssh-connection");
    w.put_string(b"publickey");
    w.put_boolean(true);
    w.put_string(algorithm);
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
pub fn probe_auth_request(key_blob: &[u8]) -> Vec<u8> {
    probe_auth_request_for(b"ssh-ed25519", key_blob)
}

/// [`probe_auth_request`] for a key `algorithm`.
pub fn probe_auth_request_for(algorithm: &[u8], key_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(auth::SSH_MSG_USERAUTH_REQUEST);
    w.put_string(b"testuser");
    w.put_string(b"ssh-connection");
    w.put_string(b"publickey");
    w.put_boolean(false);
    w.put_string(algorithm);
    w.put_string(key_blob);
    w.into_bytes()
}

// ---- ADR-0050: user certificates ----

/// The CA [`start_server_with_ca`] trusts.
pub fn test_ca() -> SigningKey {
    SigningKey::from_bytes(&[91u8; 32])
}

/// The user key the test certificates certify.
pub fn cert_user_key() -> SigningKey {
    SigningKey::from_bytes(&[92u8; 32])
}

/// A user certificate for [`cert_user_key`], signed by `ca`, valid from
/// the epoch until `valid_before`, for `principals`, with `permit-pty`
/// when `permit_pty` (`draft-ietf-sshm-cert` §2.1, the shape
/// `ssh-keygen -s` produces).
pub fn user_cert(
    ca: &SigningKey,
    principals: &[&[u8]],
    valid_before: u64,
    permit_pty: bool,
) -> Vec<u8> {
    let mut names = Writer::new();
    for p in principals {
        names.put_string(p);
    }
    let mut extensions = Writer::new();
    if permit_pty {
        extensions.put_string(b"permit-pty");
        extensions.put_string(b"");
    }
    let mut w = Writer::new();
    w.put_string(cert::CERT_ALGORITHM.as_bytes());
    w.put_string(&[0x42; 32]);
    w.put_string(cert_user_key().verifying_key().as_bytes());
    w.put_uint64(7);
    w.put_uint32(1);
    w.put_string(b"testuser@ci");
    w.put_string(&names.into_bytes());
    w.put_uint64(0);
    w.put_uint64(valid_before);
    w.put_string(b"");
    w.put_string(&extensions.into_bytes());
    w.put_string(b"");
    w.put_string(&auth_test_blob(&ca.verifying_key()));
    let signed = w.into_bytes();
    let mut sig = Writer::new();
    sig.put_string(b"ssh-ed25519");
    sig.put_string(&ca.sign(&signed).to_bytes());
    let mut w = Writer::new();
    w.put_bytes(&signed);
    w.put_string(&sig.into_bytes());
    w.into_bytes()
}

/// Authenticates as `testuser` with the certificate `cert_blob` for
/// [`cert_user_key`].
pub async fn authenticate_with_cert(
    addr: SocketAddr,
    host_key: &HostKey,
    cert_blob: &[u8],
) -> (TcpStream, SealedClient) {
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
            &signed_auth_request_for(
                &cert_user_key(),
                &session_id,
                cert::CERT_ALGORITHM.as_bytes(),
                cert_blob,
            ),
        )
        .await;
    assert_eq!(
        client.read_sealed(&mut stream).await,
        vec![auth::SSH_MSG_USERAUTH_SUCCESS]
    );
    (stream, client)
}

// ---- M5: channel layer + exec (ADR-0023) ----

/// Authenticates with the test key and returns the encrypted client ready
/// to drive the channel layer.
pub async fn authenticate(addr: SocketAddr, host_key: &HostKey) -> (TcpStream, SealedClient) {
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

pub const CH_OPEN: u8 = 90;

pub const CH_OPEN_CONFIRMATION: u8 = 91;

pub const CH_OPEN_FAILURE: u8 = 92;

pub const CH_WINDOW_ADJUST: u8 = 93;

pub const CH_DATA: u8 = 94;

pub const CH_EXTENDED_DATA: u8 = 95;

pub const CH_EOF: u8 = 96;

pub const CH_CLOSE: u8 = 97;

pub const CH_REQUEST: u8 = 98;

pub const CH_FAILURE: u8 = 100;

pub fn channel_open(sender: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_OPEN);
    w.put_string(b"session");
    w.put_uint32(sender);
    w.put_uint32(2 * 1024 * 1024);
    w.put_uint32(32 * 1024);
    w.into_bytes()
}

pub fn channel_open_type(sender: u32, ctype: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_OPEN);
    w.put_string(ctype);
    w.put_uint32(sender);
    w.put_uint32(2 * 1024 * 1024);
    w.put_uint32(32 * 1024);
    w.into_bytes()
}

pub fn channel_exec(recipient: u32, command: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(b"exec");
    w.put_boolean(true);
    w.put_string(command);
    w.into_bytes()
}

pub fn channel_request(recipient: u32, rtype: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(rtype);
    w.put_boolean(true);
    w.into_bytes()
}

/// `pty-req` (RFC 4254 §6.2) with a reply requested and zero pixel
/// dimensions.
pub fn channel_pty_req(recipient: u32, term: &[u8], cols: u32, rows: u32, modes: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(b"pty-req");
    w.put_boolean(true);
    w.put_string(term);
    w.put_uint32(cols);
    w.put_uint32(rows);
    w.put_uint32(0);
    w.put_uint32(0);
    w.put_string(modes);
    w.into_bytes()
}

/// `subsystem` (RFC 4254 §6.5) with a reply requested.
pub fn channel_subsystem(recipient: u32, name: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(b"subsystem");
    w.put_boolean(true);
    w.put_string(name);
    w.into_bytes()
}

/// `window-change` (RFC 4254 §6.7), with a reply requested so a test can
/// see whether it was applied.
pub fn channel_window_change(recipient: u32, cols: u32, rows: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_REQUEST);
    w.put_uint32(recipient);
    w.put_string(b"window-change");
    w.put_boolean(true);
    w.put_uint32(cols);
    w.put_uint32(rows);
    w.put_uint32(0);
    w.put_uint32(0);
    w.into_bytes()
}

pub fn channel_data(recipient: u32, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_DATA);
    w.put_uint32(recipient);
    w.put_string(data);
    w.into_bytes()
}

pub fn channel_one_field(msg: u8, recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(msg);
    w.put_uint32(recipient);
    w.into_bytes()
}

pub fn window_adjust(recipient: u32, add: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(CH_WINDOW_ADJUST);
    w.put_uint32(recipient);
    w.put_uint32(add);
    w.into_bytes()
}

/// `SSH_MSG_GLOBAL_REQUEST` (RFC 4254 §4).
pub fn global_request(name: &[u8], want_reply: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_byte(80);
    w.put_string(name);
    w.put_boolean(want_reply);
    w.into_bytes()
}

/// Reads the `OPEN_CONFIRMATION`, returning the server's channel id.
pub async fn expect_open_confirmation(client: &mut SealedClient, stream: &mut TcpStream) -> u32 {
    let conf = client.read_sealed(stream).await;
    let mut r = Reader::new(&conf);
    assert_eq!(r.byte().unwrap(), CH_OPEN_CONFIRMATION);
    let _recipient = r.uint32().unwrap();
    r.uint32().unwrap() // server's sender channel id
}

/// Drains the session: accumulates stdout/stderr (returning window credit
/// as it goes, so a >2 MiB stream does not stall), captures the
/// `exit-status`, and stops at `CHANNEL_CLOSE`.
pub async fn collect_session(
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

// ---- M6: re-keying (ADR-0026) ----

/// Like `authenticate`, but returns the `session_id` and server id line a
/// re-key needs, and the cipher is selectable.
pub async fn authenticate_full(
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
pub const fn test_rekey(max_bytes: u64) -> RekeyThresholds {
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
    pub async fn rekey_as_client(
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
pub async fn rekey_roundtrip(cipher: &str) {
    rekey_roundtrip_with(cipher, test_rekey(u64::MAX)).await;
}

/// [`rekey_roundtrip`] under the given re-key thresholds.
pub async fn rekey_roundtrip_with(cipher: &str, rekey: RekeyThresholds) {
    let (addr, host_key) = start_server_rekey(Duration::from_secs(30), rekey).await;
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

// ---- ADR-0028: concurrency, admission control, graceful shutdown ----

/// Reads until EOF, bounded by the test budget.
pub async fn read_to_eof(stream: &mut TcpStream) {
    let mut buf = [0u8; 256];
    loop {
        let n = timeout(TEST_BUDGET, stream.read(&mut buf))
            .await
            .expect("EOF within budget")
            .expect("read");
        if n == 0 {
            return;
        }
    }
}
