//! Key-exchange negotiation: the ADR-0021 `SSH_MSG_KEXINIT` profile,
//! byte for byte.
//!
//! ADR-0021 is the single authoritative reference this module
//! hard-codes. The binding rules implemented here:
//!
//! - **Selection is client-list-wins** (RFC 4253 §7.1): the
//!   negotiated algorithm in each slot is the first entry on the
//!   *client's* list that the server also offers.
//! - **Marker pseudo-algorithms are never selectable**: `kex-strict-*`
//!   and `ext-info-*` are filtered out before selection and before
//!   any emptiness check (RFC 8308 §2.2).
//! - **The negotiated KEX must be `mlkem768x25519-sha256`** — there is
//!   no fallback. Every rejection path uses
//!   `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3).
//! - **strict-kex is required on the initial KEXINIT** and the marker
//!   is ignored on re-key KEXINITs.
//! - **The MAC list never fails** under the AEAD-only profile, and
//!   languages never participate in failure.

use crate::wire::{self, Reader, Writer};

/// `SSH_MSG_DISCONNECT` (RFC 4253 §11.1).
pub const SSH_MSG_DISCONNECT: u8 = 1;
/// `SSH_MSG_EXT_INFO` (RFC 8308 §2.3).
pub const SSH_MSG_EXT_INFO: u8 = 7;
/// `SSH_MSG_KEXINIT` (RFC 4253 §7.1).
pub const SSH_MSG_KEXINIT: u8 = 20;
/// `SSH_MSG_NEWKEYS` (RFC 4253 §7.3).
pub const SSH_MSG_NEWKEYS: u8 = 21;
/// Hybrid KEX initiation, client → server
/// (`draft-ietf-sshm-mlkem-hybrid-kex`; shares number 30).
pub const SSH_MSG_KEX_HYBRID_INIT: u8 = 30;
/// Hybrid KEX reply, server → client.
pub const SSH_MSG_KEX_HYBRID_REPLY: u8 = 31;

/// `SSH_DISCONNECT_PROTOCOL_ERROR` (RFC 4253 §11.1).
pub const DISCONNECT_PROTOCOL_ERROR: u32 = 2;
/// `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (RFC 4253 §11.1) — the single
/// code ADR-0021 binds to every negotiation rejection.
pub const DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;

/// The only real key exchange offered (ADR-0021).
pub const KEX_ALGORITHM: &str = "mlkem768x25519-sha256";
/// Server-side strict-kex marker (Terrapin defence).
pub const STRICT_KEX_SERVER: &str = "kex-strict-s-v00@openssh.com";
/// Client-side strict-kex marker, required on the initial KEXINIT.
pub const STRICT_KEX_CLIENT: &str = "kex-strict-c-v00@openssh.com";
/// Client indicator that it accepts `SSH_MSG_EXT_INFO` (RFC 8308) —
/// the gate for the server's `server-sig-algs` send.
pub const EXT_INFO_CLIENT: &str = "ext-info-c";

/// `kex_algorithms` as advertised (ADR-0021 §1).
pub const KEX_LIST: &str = "mlkem768x25519-sha256,kex-strict-s-v00@openssh.com";
/// `server_host_key_algorithms` (ADR-0021 §2).
pub const HOST_KEY_LIST: &str = "ssh-ed25519";
/// `encryption_algorithms_*`, both directions (ADR-0021 §3–4).
pub const ENCRYPTION_LIST: &str = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com";
/// `mac_algorithms_*`, both directions — nominal only, never
/// exercised under the AEAD-only profile (ADR-0021 §5–6).
pub const MAC_LIST: &str = "hmac-sha2-512-etm@openssh.com";
/// `compression_algorithms_*`, both directions (ADR-0021 §7–8).
pub const COMPRESSION_LIST: &str = "none";

/// Per-list parse bound: a single KEXINIT name-list longer than this
/// is hostile (OpenSSH's complete lists are under 2 KiB).
const NAME_LIST_BOUND: usize = 8192;

/// A negotiation rejection: the reason (for the `kex.failed` audit
/// event) and the disconnect code to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Structured reason string (ADR-0024 `kex.failed.reason`).
    pub reason: &'static str,
    /// SSH disconnect reason code to send.
    pub disconnect_code: u32,
}

impl Rejection {
    const fn kex_failed(reason: &'static str) -> Self {
        Self {
            reason,
            disconnect_code: DISCONNECT_KEY_EXCHANGE_FAILED,
        }
    }
}

/// Errors from parsing or negotiating a peer KEXINIT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KexError {
    /// The KEXINIT payload is malformed at the wire level.
    Wire(wire::WireError),
    /// The negotiation rejected the peer (fail closed).
    Rejected(Rejection),
}

impl From<wire::WireError> for KexError {
    fn from(e: wire::WireError) -> Self {
        Self::Wire(e)
    }
}

impl std::fmt::Display for KexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "malformed KEXINIT: {e}"),
            Self::Rejected(r) => write!(f, "negotiation rejected: {}", r.reason),
        }
    }
}

impl std::error::Error for KexError {}

/// The peer's parsed KEXINIT (zero-copy over its payload).
#[derive(Debug)]
pub struct PeerKexInit<'a> {
    /// Peer `kex_algorithms`, markers included (filtered at
    /// negotiation, not at parse).
    pub kex_algorithms: wire::NameList<'a>,
    /// Peer `server_host_key_algorithms`.
    pub server_host_key_algorithms: wire::NameList<'a>,
    /// Peer `encryption_algorithms_client_to_server`.
    pub encryption_c2s: wire::NameList<'a>,
    /// Peer `encryption_algorithms_server_to_client`.
    pub encryption_s2c: wire::NameList<'a>,
    /// `first_kex_packet_follows` (RFC 4253 §7.1).
    pub first_kex_packet_follows: bool,
}

/// The negotiation outcome the transport machine proceeds with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// Always [`KEX_ALGORITHM`] — kept explicit for the
    /// `kex.completed` log event.
    pub kex_algorithm: &'static str,
    /// Always `ssh-ed25519` in Phase 1.
    pub host_key_algorithm: &'static str,
    /// Cipher for client→server, client's preference.
    pub cipher_c2s: String,
    /// Cipher for server→client, client's preference.
    pub cipher_s2c: String,
    /// The client offered `ext-info-c`: send one `SSH_MSG_EXT_INFO`
    /// after our first NEWKEYS (ADR-0021).
    pub ext_info: bool,
    /// The peer sent `first_kex_packet_follows = TRUE` with a wrong
    /// guess: the transport must silently skip its next KEX packet
    /// (RFC 4253 §7.1; ADR-0021).
    pub skip_guessed_packet: bool,
}

/// Builds our KEXINIT payload (message byte + cookie + the ADR-0021
/// profile), returning the exact bytes — the caller keeps them as
/// `I_S` for the exchange hash.
///
/// # Errors
///
/// Fails only if the OS random source fails to produce the 16-byte
/// cookie (RFC 4253 §7.1 requires it to be random).
pub fn build_kexinit() -> Result<Vec<u8>, KexError> {
    let mut cookie = [0u8; 16];
    getrandom::fill(&mut cookie).map_err(|_| KexError::Wire(wire::WireError::Truncated))?;

    let mut w = Writer::new();
    w.put_byte(SSH_MSG_KEXINIT);
    w.put_bytes(&cookie);
    w.put_name_list(KEX_LIST);
    w.put_name_list(HOST_KEY_LIST);
    w.put_name_list(ENCRYPTION_LIST);
    w.put_name_list(ENCRYPTION_LIST);
    w.put_name_list(MAC_LIST);
    w.put_name_list(MAC_LIST);
    w.put_name_list(COMPRESSION_LIST);
    w.put_name_list(COMPRESSION_LIST);
    w.put_name_list(""); // languages_client_to_server
    w.put_name_list(""); // languages_server_to_client
    w.put_boolean(false); // first_kex_packet_follows (ADR-0021)
    w.put_uint32(0); // reserved
    Ok(w.into_bytes())
}

/// Parses a peer KEXINIT payload (starting at the message byte).
///
/// # Errors
///
/// [`KexError::Wire`] on any malformed, truncated, oversized, or
/// trailing-garbage payload — fail closed, no tolerance parsing.
pub fn parse_kexinit(payload: &[u8]) -> Result<PeerKexInit<'_>, KexError> {
    let mut r = Reader::new(payload);
    let msg = r.byte()?;
    if msg != SSH_MSG_KEXINIT {
        return Err(KexError::Wire(wire::WireError::Truncated));
    }
    let _cookie = r.bytes(16)?;
    let kex_algorithms = r.name_list(NAME_LIST_BOUND)?;
    let server_host_key_algorithms = r.name_list(NAME_LIST_BOUND)?;
    let encryption_c2s = r.name_list(NAME_LIST_BOUND)?;
    let encryption_s2c = r.name_list(NAME_LIST_BOUND)?;
    let _mac_c2s = r.name_list(NAME_LIST_BOUND)?;
    let _mac_s2c = r.name_list(NAME_LIST_BOUND)?;
    let _compression_c2s = r.name_list(NAME_LIST_BOUND)?;
    let _compression_s2c = r.name_list(NAME_LIST_BOUND)?;
    let _languages_c2s = r.name_list(NAME_LIST_BOUND)?;
    let _languages_s2c = r.name_list(NAME_LIST_BOUND)?;
    let first_kex_packet_follows = r.boolean()?;
    let _reserved = r.uint32()?;
    r.finish()?;
    Ok(PeerKexInit {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_c2s,
        encryption_s2c,
        first_kex_packet_follows,
    })
}

/// True for the marker pseudo-algorithms that are never selectable as
/// a key exchange (RFC 8308 §2.2; strict-kex extension).
fn is_marker(name: &str) -> bool {
    name.starts_with("kex-strict-") || name.starts_with("ext-info-")
}

/// Negotiates against a peer KEXINIT per ADR-0021.
///
/// `initial` distinguishes the first KEXINIT (strict-kex marker
/// required; `ext-info-c` honoured) from re-key KEXINITs (markers
/// ignored entirely, per the strict-kex extension).
///
/// # Errors
///
/// [`KexError::Rejected`] with `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`
/// (3) on every rejection path: no hybrid KEX offered, no strict-kex
/// marker on the initial KEXINIT, or an empty intersection on a
/// required list (host key, encryption). The MAC and language lists
/// never fail (ADR-0021).
pub fn negotiate(peer: &PeerKexInit<'_>, initial: bool) -> Result<Negotiated, KexError> {
    // Markers are filtered BEFORE selection and before any emptiness
    // check: a hostile client echoing our own markers must not produce
    // a non-empty intersection (ADR-0021; RFC 8308 §2.2).
    let mut peer_real_kex = peer.kex_algorithms.names().filter(|n| !is_marker(n));

    // The negotiated KEX must be the hybrid — client-list-wins is
    // trivial with a single server entry, but the check is on the
    // peer's REAL algorithms only.
    if !peer_real_kex.any(|n| n == KEX_ALGORITHM) {
        return Err(KexError::Rejected(Rejection::kex_failed("no-hybrid-kex")));
    }

    // strict-kex is required, not merely offered — on the initial
    // KEXINIT only (the marker is ignored when re-keying).
    if initial && !peer.kex_algorithms.contains(STRICT_KEX_CLIENT) {
        return Err(KexError::Rejected(Rejection::kex_failed("no-strict-kex")));
    }

    // Host key: client-list-wins against our single entry.
    if !peer.server_host_key_algorithms.contains(HOST_KEY_LIST) {
        return Err(KexError::Rejected(Rejection::kex_failed(
            "no-host-key-algorithm",
        )));
    }

    // Ciphers: the first entry on the CLIENT's list that we offer
    // (RFC 4253 §7.1) — our list order expresses nothing.
    let ours: Vec<&str> = ENCRYPTION_LIST.split(',').collect();
    let pick = |peer_list: &wire::NameList<'_>| -> Option<String> {
        peer_list
            .names()
            .find(|n| ours.contains(n))
            .map(str::to_owned)
    };
    let Some(cipher_c2s) = pick(&peer.encryption_c2s) else {
        return Err(KexError::Rejected(Rejection::kex_failed("no-cipher-c2s")));
    };
    let Some(cipher_s2c) = pick(&peer.encryption_s2c) else {
        return Err(KexError::Rejected(Rejection::kex_failed("no-cipher-s2c")));
    };

    // MAC: never consulted — both ciphers are AEAD, selection is
    // skipped entirely and an empty intersection is never fatal
    // (ADR-0021). Languages: never participate.

    // ext-info-c is only meaningful on the initial KEXINIT.
    let ext_info = initial && peer.kex_algorithms.contains(EXT_INFO_CLIENT);

    // first_kex_packet_follows: the guess is wrong unless the peer's
    // FIRST kex algorithm and FIRST host-key algorithm match the
    // negotiated ones (RFC 4253 §7.1). With our single-entry lists,
    // that means first-real-kex == hybrid and first-host-key ==
    // ssh-ed25519; a wrong guess means the transport silently skips
    // the peer's next KEX packet.
    let skip_guessed_packet = peer.first_kex_packet_follows && {
        let first_kex = peer.kex_algorithms.names().next();
        let first_hostkey = peer.server_host_key_algorithms.names().next();
        first_kex != Some(KEX_ALGORITHM) || first_hostkey != Some(HOST_KEY_LIST)
    };

    Ok(Negotiated {
        kex_algorithm: KEX_ALGORITHM,
        host_key_algorithm: HOST_KEY_LIST,
        cipher_c2s,
        cipher_s2c,
        ext_info,
        skip_guessed_packet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a client KEXINIT payload for tests.
    fn client_kexinit(kex: &str, host_keys: &str, ciphers: &str, first_follows: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_byte(SSH_MSG_KEXINIT);
        w.put_bytes(&[0u8; 16]);
        w.put_name_list(kex);
        w.put_name_list(host_keys);
        w.put_name_list(ciphers);
        w.put_name_list(ciphers);
        w.put_name_list("hmac-sha2-256-etm@openssh.com");
        w.put_name_list("hmac-sha2-256-etm@openssh.com");
        w.put_name_list("none,zlib@openssh.com");
        w.put_name_list("none,zlib@openssh.com");
        w.put_name_list("");
        w.put_name_list("");
        w.put_boolean(first_follows);
        w.put_uint32(0);
        w.into_bytes()
    }

    const OPENSSH_KEX: &str = "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com";
    const OPENSSH_HOSTKEYS: &str = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256";
    const OPENSSH_CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com";

    #[test]
    fn our_kexinit_matches_the_adr_0021_profile() {
        let payload = build_kexinit().unwrap();
        let parsed = parse_kexinit(&payload).unwrap();
        assert!(parsed.kex_algorithms.contains(KEX_ALGORITHM));
        assert!(parsed.kex_algorithms.contains(STRICT_KEX_SERVER));
        assert!(!parsed.kex_algorithms.contains(STRICT_KEX_CLIENT));
        assert!(!parsed.first_kex_packet_follows);
        // Two distinct builds differ (random cookie).
        let second = build_kexinit().unwrap();
        assert_ne!(payload, second);
        assert_eq!(payload.len(), second.len());
    }

    #[test]
    fn negotiates_with_a_stock_openssh_offer() {
        let payload = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
        let peer = parse_kexinit(&payload).unwrap();
        let n = negotiate(&peer, true).unwrap();
        assert_eq!(n.kex_algorithm, "mlkem768x25519-sha256");
        assert_eq!(n.host_key_algorithm, "ssh-ed25519");
        // Client's list puts chacha20 first → client preference wins.
        assert_eq!(n.cipher_c2s, "chacha20-poly1305@openssh.com");
        assert!(n.ext_info);
        assert!(!n.skip_guessed_packet);
    }

    #[test]
    fn client_cipher_preference_wins_not_ours() {
        // Client prefers AES-GCM; our list has chacha20 first. The
        // client's order must decide (RFC 4253 §7.1 — the inversion
        // the ADR-0021 review caught).
        let ciphers = "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com";
        let payload = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, ciphers, false);
        let peer = parse_kexinit(&payload).unwrap();
        let n = negotiate(&peer, true).unwrap();
        assert_eq!(n.cipher_c2s, "aes256-gcm@openssh.com");
        assert_eq!(n.cipher_s2c, "aes256-gcm@openssh.com");
    }

    #[test]
    fn hostile_marker_echo_cannot_be_negotiated() {
        // The attack from the ADR-0021 review: a client echoing our
        // own markers, with no real KEX, must be rejected — the
        // literal intersection is non-empty but contains no real
        // algorithm.
        for kex in [
            "kex-strict-s-v00@openssh.com",
            "ext-info-s",
            "kex-strict-s-v00@openssh.com,ext-info-s,kex-strict-c-v00@openssh.com",
        ] {
            let payload = client_kexinit(kex, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
            let peer = parse_kexinit(&payload).unwrap();
            let err = negotiate(&peer, true).unwrap_err();
            assert_eq!(
                err,
                KexError::Rejected(Rejection {
                    reason: "no-hybrid-kex",
                    disconnect_code: DISCONNECT_KEY_EXCHANGE_FAILED,
                }),
                "marker echo {kex:?} must fail closed"
            );
        }
    }

    #[test]
    fn non_hybrid_client_gets_key_exchange_failed() {
        // The ADR-0020 negative interop case: classical-only client.
        let payload = client_kexinit(
            "curve25519-sha256,ecdh-sha2-nistp256,kex-strict-c-v00@openssh.com",
            OPENSSH_HOSTKEYS,
            OPENSSH_CIPHERS,
            false,
        );
        let peer = parse_kexinit(&payload).unwrap();
        let err = negotiate(&peer, true).unwrap_err();
        let KexError::Rejected(r) = err else {
            panic!("expected rejection")
        };
        assert_eq!(r.reason, "no-hybrid-kex");
        assert_eq!(r.disconnect_code, DISCONNECT_KEY_EXCHANGE_FAILED);
    }

    #[test]
    fn missing_strict_kex_is_rejected_on_initial_but_ignored_on_rekey() {
        let kex_no_strict = "mlkem768x25519-sha256,ext-info-c";
        let payload = client_kexinit(kex_no_strict, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
        let peer = parse_kexinit(&payload).unwrap();

        // Initial: required (ADR-0021), code 3.
        let err = negotiate(&peer, true).unwrap_err();
        let KexError::Rejected(r) = err else {
            panic!("expected rejection")
        };
        assert_eq!(r.reason, "no-strict-kex");
        assert_eq!(r.disconnect_code, DISCONNECT_KEY_EXCHANGE_FAILED);

        // Re-key: the marker's absence is ignored (OpenSSH omits it).
        negotiate(&peer, false).unwrap();
    }

    #[test]
    fn legacy_cipher_only_client_fails_closed_with_code_3() {
        // The flagship zero-legacy rejection from the ADR-0021 review:
        // `ssh -c aes128-ctr` passes the KEX check, then hits an empty
        // cipher intersection — which must be explicit, not undefined.
        let payload = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, "aes128-ctr", false);
        let peer = parse_kexinit(&payload).unwrap();
        let err = negotiate(&peer, true).unwrap_err();
        let KexError::Rejected(r) = err else {
            panic!("expected rejection")
        };
        assert_eq!(r.reason, "no-cipher-c2s");
        assert_eq!(r.disconnect_code, DISCONNECT_KEY_EXCHANGE_FAILED);
    }

    #[test]
    fn mac_mismatch_never_fails() {
        // Client offers only a MAC we do not list: under the AEAD-only
        // profile MAC selection is skipped entirely (ADR-0021 — the
        // 'discarded vs skipped' review finding). The helper already
        // writes a MAC list we don't offer; negotiation must succeed.
        let payload = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
        let peer = parse_kexinit(&payload).unwrap();
        negotiate(&peer, true).unwrap();
    }

    #[test]
    fn ext_info_only_honoured_on_initial_kexinit() {
        let payload = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
        let peer = parse_kexinit(&payload).unwrap();
        assert!(negotiate(&peer, true).unwrap().ext_info);
        assert!(!negotiate(&peer, false).unwrap().ext_info);
    }

    #[test]
    fn wrong_guess_is_skipped_right_guess_is_not() {
        // Wrong guess: client's first kex entry is not the hybrid.
        let wrong = client_kexinit(
            "curve25519-sha256,mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
            OPENSSH_HOSTKEYS,
            OPENSSH_CIPHERS,
            true,
        );
        let peer = parse_kexinit(&wrong).unwrap();
        assert!(negotiate(&peer, true).unwrap().skip_guessed_packet);

        // Right guess: hybrid first, ssh-ed25519 first.
        let right = client_kexinit(
            "mlkem768x25519-sha256,kex-strict-c-v00@openssh.com",
            "ssh-ed25519",
            OPENSSH_CIPHERS,
            true,
        );
        let peer = parse_kexinit(&right).unwrap();
        assert!(!negotiate(&peer, true).unwrap().skip_guessed_packet);

        // No guess flag: never skipped.
        let none = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
        let peer = parse_kexinit(&none).unwrap();
        assert!(!negotiate(&peer, true).unwrap().skip_guessed_packet);
    }

    #[test]
    fn malformed_kexinit_payloads_fail_closed() {
        // Truncated, wrong message byte, trailing garbage.
        assert!(parse_kexinit(&[]).is_err());
        assert!(parse_kexinit(&[99]).is_err());
        let mut ok = client_kexinit(OPENSSH_KEX, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, false);
        ok.push(0xFF);
        assert!(parse_kexinit(&ok).is_err());
    }
}
