//! Wire-level encoding: sshtype primitives (RFC 4251 §5), the Binary
//! Packet Protocol framing (RFC 4253 §6), and the version exchange
//! (RFC 4253 §4.2).
//!
//! This module is the entry of the pre-authentication path — the
//! highest-trust surface in the threat model (§4.1). Its rules are
//! structural, not advisory:
//!
//! - **Pure functions over byte slices.** Parsing never performs I/O,
//!   so every function here is fuzzable by construction.
//! - **No allocation sized by attacker-controlled lengths without an
//!   explicit bound.** [`Reader`] requires a caller-supplied bound on
//!   every variable-length read; there is no unbounded entry point.
//! - **No panics on input.** Every malformed, truncated, or oversized
//!   input returns a typed [`WireError`]. Indexing is always preceded
//!   by length checks.
//! - **Strict parsing, fail closed.** Non-canonical encodings
//!   (redundant mpint leading bytes, non-ASCII name-lists) are
//!   rejected, not normalised.

use std::fmt;

/// Hard upper bound on `packet_length`.
///
/// RFC 4253 §6.1 requires supporting a total packet size of 35000
/// bytes; that floor is enforced here as the *maximum*, fail-closed.
pub const MAX_PACKET: u32 = 35_000;

/// Minimum padding the Binary Packet Protocol requires (RFC 4253 §6).
pub const MIN_PADDING: u8 = 4;

/// Cipher-block granularity for the unencrypted (pre-NEWKEYS) phase:
/// "a multiple of the cipher block size or 8, whichever is larger"
/// (RFC 4253 §6) — with no cipher yet, 8.
pub const PLAINTEXT_BLOCK: usize = 8;

/// The server identification string, without trailing CRLF
/// (RFC 4253 §4.2).
pub const SERVER_ID: &str = concat!("SSH-2.0-quantumssh_", env!("CARGO_PKG_VERSION"));

/// Maximum length of the peer's identification line including CRLF
/// (RFC 4253 §4.2: "MUST be able to process" lines up to 255 bytes;
/// we enforce 255 as the maximum, fail-closed).
pub const MAX_ID_LINE: usize = 255;

/// Typed wire-parsing error. Every variant is a protocol violation or
/// resource-bound violation by the peer; none is recoverable within
/// the same connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Input ended before a declared or required length.
    Truncated,
    /// A declared length exceeds the caller-supplied bound.
    Oversized {
        /// Length the peer declared.
        declared: usize,
        /// Bound the caller imposed.
        bound: usize,
    },
    /// `packet_length` outside `1..=MAX_PACKET`.
    BadPacketLength(u32),
    /// Padding shorter than 4, longer than the packet, or the packet
    /// is not block-aligned.
    BadPadding,
    /// Trailing bytes remained after a complete parse.
    TrailingBytes(usize),
    /// An `mpint` violated canonical encoding (RFC 4251 §5).
    BadMpint,
    /// A name-list contained non-ASCII bytes, empty names, or a
    /// leading/trailing/double comma (RFC 4251 §5).
    BadNameList,
    /// The peer's identification line is not a well-formed
    /// `SSH-2.0-…` line within [`MAX_ID_LINE`] bytes.
    BadIdentification,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "input truncated"),
            Self::Oversized { declared, bound } => {
                write!(f, "declared length {declared} exceeds bound {bound}")
            }
            Self::BadPacketLength(len) => write!(f, "invalid packet_length {len}"),
            Self::BadPadding => write!(f, "invalid packet padding"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after message"),
            Self::BadMpint => write!(f, "non-canonical mpint"),
            Self::BadNameList => write!(f, "malformed name-list"),
            Self::BadIdentification => write!(f, "malformed identification line"),
        }
    }
}

impl std::error::Error for WireError {}

/// Result alias for wire operations.
pub type Result<T> = std::result::Result<T, WireError>;

/// Zero-copy reader over an sshtype-encoded byte slice.
///
/// Every variable-length read takes an explicit `bound`: the maximum
/// the *caller* is willing to accept for that field. This makes the
/// threat-model §4.1 rule ("no allocation sized by attacker-controlled
/// lengths without an explicit bound") a property of the API — there
/// is no way to read a peer-sized field without stating a bound. The
/// reader itself never allocates: it returns subslices of the input.
#[derive(Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Creates a reader over `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len()
    }

    const fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.input.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, tail) = self.input.split_at(n);
        self.input = tail;
        Ok(head)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// [`WireError::Truncated`] if the input is exhausted.
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads a boolean (RFC 4251 §5: zero is false, any non-zero
    /// value MUST be interpreted as true on receipt).
    ///
    /// # Errors
    ///
    /// [`WireError::Truncated`] if the input is exhausted.
    pub fn boolean(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    /// Reads a big-endian `uint32`.
    ///
    /// # Errors
    ///
    /// [`WireError::Truncated`] if fewer than 4 bytes remain.
    pub fn uint32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a big-endian `uint64`.
    ///
    /// # Errors
    ///
    /// [`WireError::Truncated`] if fewer than 8 bytes remain.
    pub fn uint64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads `n` raw bytes (fixed-length field, e.g. the KEXINIT
    /// cookie).
    ///
    /// # Errors
    ///
    /// [`WireError::Truncated`] if fewer than `n` bytes remain.
    pub const fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    /// Reads an RFC 4251 `string`, rejecting declared lengths above
    /// `bound` before touching the data.
    ///
    /// # Errors
    ///
    /// [`WireError::Oversized`] if the declared length exceeds `bound`;
    /// [`WireError::Truncated`] if the input is shorter than declared.
    pub fn string(&mut self, bound: usize) -> Result<&'a [u8]> {
        let declared = self.uint32()? as usize;
        if declared > bound {
            return Err(WireError::Oversized { declared, bound });
        }
        self.take(declared)
    }

    /// Reads an RFC 4251 `name-list` (comma-separated, US-ASCII,
    /// non-empty names) bounded by `bound`, returning the raw list.
    ///
    /// An empty list is valid (e.g. the `languages` fields). Empty
    /// *names* — a leading/trailing/double comma — are rejected.
    ///
    /// # Errors
    ///
    /// [`WireError::BadNameList`] on malformed content, plus the
    /// [`Reader::string`] errors for length violations.
    pub fn name_list(&mut self, bound: usize) -> Result<NameList<'a>> {
        let raw = self.string(bound)?;
        if raw.is_empty() {
            return Ok(NameList { raw: b"" });
        }
        let mut previous_was_comma = true; // guards a leading comma
        for &b in raw {
            match b {
                b',' => {
                    if previous_was_comma {
                        return Err(WireError::BadNameList);
                    }
                    previous_was_comma = true;
                }
                0x21..=0x7E => previous_was_comma = false,
                _ => return Err(WireError::BadNameList),
            }
        }
        if previous_was_comma {
            return Err(WireError::BadNameList); // trailing comma
        }
        Ok(NameList { raw })
    }

    /// Reads an RFC 4251 `mpint` bounded by `bound`, returning its
    /// canonical big-endian magnitude bytes.
    ///
    /// Phase 1 accepts only non-negative values (every mpint in the
    /// implemented protocol surface is a hash, key, or signature
    /// component). Enforced canonical form, fail closed:
    /// no `0x00` redundant leading byte, no negative values, zero is
    /// the empty string.
    ///
    /// # Errors
    ///
    /// [`WireError::BadMpint`] on non-canonical or negative encodings,
    /// plus the [`Reader::string`] errors for length violations.
    pub fn mpint(&mut self, bound: usize) -> Result<&'a [u8]> {
        let raw = self.string(bound)?;
        match raw {
            [0x00] => Err(WireError::BadMpint), // zero MUST be empty
            [0x00, second, ..] if *second & 0x80 == 0 => Err(WireError::BadMpint),
            [first, ..] if *first & 0x80 != 0 => Err(WireError::BadMpint), // negative
            _ => Ok(raw), // empty (zero) or canonical positive
        }
    }

    /// Asserts the input is fully consumed.
    ///
    /// # Errors
    ///
    /// [`WireError::TrailingBytes`] if unconsumed bytes remain.
    pub const fn finish(self) -> Result<()> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes(self.input.len()))
        }
    }
}

/// A validated RFC 4251 name-list (ASCII, well-formed commas).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameList<'a> {
    raw: &'a [u8],
}

impl<'a> NameList<'a> {
    /// Iterates the names in list order.
    pub fn names(&self) -> impl Iterator<Item = &'a str> {
        // Validated as ASCII at parse time, so from_utf8 cannot fail;
        // split on an empty list yields one empty chunk, filtered out.
        self.raw
            .split(|&b| b == b',')
            .filter(|name| !name.is_empty())
            .map(|name| std::str::from_utf8(name).unwrap_or(""))
    }

    /// True if `name` appears in the list.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names().any(|n| n == name)
    }

    /// The raw bytes of the list (for hashing into `I_C`/`I_S`).
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
}

/// Growable sshtype writer (server-side message construction —
/// lengths here are chosen by us, not the peer).
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Creates an empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends one byte.
    pub fn put_byte(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Appends a boolean.
    pub fn put_boolean(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    /// Appends a big-endian `uint32`.
    pub fn put_uint32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Appends a big-endian `uint64`.
    pub fn put_uint64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Appends raw bytes (fixed-length field).
    pub fn put_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Appends an RFC 4251 `string`.
    ///
    /// # Panics
    ///
    /// Panics if `v` exceeds `u32::MAX` bytes — impossible for
    /// server-constructed messages, which are bounded well below
    /// [`MAX_PACKET`].
    pub fn put_string(&mut self, v: &[u8]) {
        let len = u32::try_from(v.len()).expect("server-constructed string exceeds u32");
        self.put_uint32(len);
        self.buf.extend_from_slice(v);
    }

    /// Appends an RFC 4251 `name-list` from its already-joined form.
    pub fn put_name_list(&mut self, joined: &str) {
        self.put_string(joined.as_bytes());
    }

    /// Appends an RFC 4251 `mpint` from a big-endian non-negative
    /// magnitude, canonicalising (strips leading zeros; prepends
    /// `0x00` when the high bit is set; zero encodes as empty).
    ///
    /// # Panics
    ///
    /// Panics if the magnitude exceeds `u32::MAX` bytes — impossible
    /// for server-constructed values, bounded well below [`MAX_PACKET`].
    pub fn put_mpint(&mut self, magnitude: &[u8]) {
        let stripped: &[u8] = {
            let mut s = magnitude;
            while let [0x00, rest @ ..] = s {
                s = rest;
            }
            s
        };
        match stripped {
            [] => self.put_uint32(0),
            [first, ..] if *first & 0x80 != 0 => {
                let len = u32::try_from(stripped.len() + 1)
                    .expect("server-constructed mpint exceeds u32");
                self.put_uint32(len);
                self.buf.push(0x00);
                self.buf.extend_from_slice(stripped);
            }
            _ => self.put_string(stripped),
        }
    }

    /// Consumes the writer, returning the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Encodes one unencrypted Binary Packet Protocol packet.
///
/// RFC 4253 §6: `packet_length ‖ padding_length ‖ payload ‖ random
/// padding`, block-aligned to [`PLAINTEXT_BLOCK`] with at least
/// [`MIN_PADDING`] bytes of padding.
///
/// # Errors
///
/// Returns [`WireError::BadPacketLength`] if the payload cannot fit
/// within [`MAX_PACKET`], and [`WireError::Truncated`] only if the
/// system random source fails (never expected in practice).
pub fn encode_packet(payload: &[u8]) -> Result<Vec<u8>> {
    // packet_length counts padding_length + payload + padding.
    // Choose the smallest padding >= MIN_PADDING that aligns the
    // whole packet (including the 4 length bytes) to the block size.
    let unpadded = 4 + 1 + payload.len();
    let mut padding = PLAINTEXT_BLOCK - (unpadded % PLAINTEXT_BLOCK);
    while padding < usize::from(MIN_PADDING) {
        padding += PLAINTEXT_BLOCK;
    }
    let packet_length = 1 + payload.len() + padding;
    let total = u32::try_from(packet_length).map_err(|_| WireError::BadPacketLength(u32::MAX))?;
    if total > MAX_PACKET {
        return Err(WireError::BadPacketLength(total));
    }

    let mut out = Vec::with_capacity(4 + packet_length);
    out.extend_from_slice(&total.to_be_bytes());
    // padding fits in u8: at most PLAINTEXT_BLOCK + MIN_PADDING.
    out.push(u8::try_from(padding).map_err(|_| WireError::BadPadding)?);
    out.extend_from_slice(payload);
    let mut pad = vec![0u8; padding];
    getrandom::fill(&mut pad).map_err(|_| WireError::Truncated)?;
    out.extend_from_slice(&pad);
    Ok(out)
}

/// Validates an unencrypted packet's `packet_length` field, read
/// ahead of the body (RFC 4253 §6). Returns how many further bytes
/// the packet occupies.
///
/// This is the *first* attacker-controlled length the server ever
/// observes; it is bounded before any allocation or further read.
///
/// # Errors
///
/// Returns [`WireError::BadPacketLength`] outside `1..=MAX_PACKET`,
/// or [`WireError::BadPadding`] if the total is not block-aligned.
pub const fn validate_packet_length(packet_length: u32) -> Result<usize> {
    if packet_length == 0 || packet_length > MAX_PACKET {
        return Err(WireError::BadPacketLength(packet_length));
    }
    let total = 4 + packet_length as usize;
    if !total.is_multiple_of(PLAINTEXT_BLOCK) {
        return Err(WireError::BadPadding);
    }
    Ok(packet_length as usize)
}

/// Extracts the payload from an unencrypted packet body (everything
/// after the 4 `packet_length` bytes, whose value was already
/// validated by [`validate_packet_length`]).
///
/// # Errors
///
/// Returns [`WireError::BadPadding`] when `padding_length` violates
/// RFC 4253 §6 (less than [`MIN_PADDING`] or no room for the payload),
/// or [`WireError::Truncated`] if `body` is shorter than declared.
pub fn decode_packet_body(body: &[u8]) -> Result<&[u8]> {
    let Some((&padding_length, rest)) = body.split_first() else {
        return Err(WireError::Truncated);
    };
    if padding_length < MIN_PADDING {
        return Err(WireError::BadPadding);
    }
    let padding = usize::from(padding_length);
    let Some(payload_len) = rest.len().checked_sub(padding) else {
        return Err(WireError::BadPadding);
    };
    Ok(&rest[..payload_len])
}

/// The peer's parsed identification line (RFC 4253 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerId {
    /// Protocol version — must be `2.0` (or the `1.99` compatibility
    /// form, which Phase 1 rejects: zero legacy).
    pub protoversion: String,
    /// Software version token.
    pub softwareversion: String,
}

/// Parses the peer's identification line (without CRLF).
///
/// Accepts exactly `SSH-2.0-softwareversion[ comments]` per
/// RFC 4253 §4.2. `SSH-1.99` — the compatibility marker — is
/// rejected: `QuantumSSH` is zero-legacy and never interoperates with
/// protocol 1 clients.
///
/// # Errors
///
/// Returns [`WireError::BadIdentification`] for anything that is not
/// a well-formed `SSH-2.0` identification line.
pub fn parse_peer_id(line: &[u8]) -> Result<PeerId> {
    if line.len() > MAX_ID_LINE {
        return Err(WireError::BadIdentification);
    }
    let line = std::str::from_utf8(line).map_err(|_| WireError::BadIdentification)?;
    let rest = line
        .strip_prefix("SSH-2.0-")
        .ok_or(WireError::BadIdentification)?;
    let softwareversion = rest.split(' ').next().unwrap_or("");
    if softwareversion.is_empty() || !softwareversion.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(WireError::BadIdentification);
    }
    Ok(PeerId {
        protoversion: "2.0".to_owned(),
        softwareversion: softwareversion.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Reader primitives ----

    #[test]
    fn reads_fixed_width_primitives() {
        let mut r = Reader::new(&[0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07]);
        assert_eq!(r.byte().unwrap(), 0x01);
        assert!(!r.boolean().unwrap());
        assert_eq!(r.byte().unwrap(), 0x02);
        assert_eq!(r.uint32().unwrap(), 7);
        r.finish().unwrap();
    }

    #[test]
    fn nonzero_boolean_is_true() {
        assert!(Reader::new(&[0x2a]).boolean().unwrap());
    }

    #[test]
    fn uint64_roundtrip() {
        let mut w = Writer::new();
        w.put_uint64(0x0102_0304_0506_0708);
        let bytes = w.into_bytes();
        assert_eq!(Reader::new(&bytes).uint64().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn truncated_primitives_fail() {
        assert_eq!(Reader::new(&[]).byte(), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[0, 0, 0]).uint32(), Err(WireError::Truncated));
        assert_eq!(
            Reader::new(&[0, 0, 0, 0, 0, 0, 0]).uint64(),
            Err(WireError::Truncated)
        );
    }

    // ---- string bounds ----

    #[test]
    fn string_roundtrip_within_bound() {
        let mut w = Writer::new();
        w.put_string(b"hello");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.string(16).unwrap(), b"hello");
        r.finish().unwrap();
    }

    #[test]
    fn string_over_bound_is_rejected_before_reading_data() {
        // Declares 200 bytes; the body is absent. The bound must trip
        // first — Oversized, not Truncated — proving no read/alloc of
        // the attacker-declared size was attempted.
        let mut w = Writer::new();
        w.put_uint32(200);
        let bytes = w.into_bytes();
        assert_eq!(
            Reader::new(&bytes).string(64),
            Err(WireError::Oversized {
                declared: 200,
                bound: 64
            })
        );
    }

    #[test]
    fn string_declared_longer_than_input_is_truncated() {
        let mut w = Writer::new();
        w.put_uint32(8);
        w.put_bytes(b"abc");
        let bytes = w.into_bytes();
        assert_eq!(Reader::new(&bytes).string(64), Err(WireError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let mut r = Reader::new(&[0x01, 0x02]);
        r.byte().unwrap();
        assert_eq!(r.finish(), Err(WireError::TrailingBytes(1)));
    }

    // ---- name-list ----

    #[test]
    fn name_list_roundtrip_and_contains() {
        let mut w = Writer::new();
        w.put_name_list("mlkem768x25519-sha256,kex-strict-s-v00@openssh.com");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let list = r.name_list(1024).unwrap();
        assert!(list.contains("mlkem768x25519-sha256"));
        assert!(list.contains("kex-strict-s-v00@openssh.com"));
        assert!(!list.contains("ssh-rsa"));
        assert_eq!(list.names().count(), 2);
    }

    #[test]
    fn empty_name_list_is_valid_and_empty() {
        let mut w = Writer::new();
        w.put_name_list("");
        let bytes = w.into_bytes();
        let list = Reader::new(&bytes).name_list(16).unwrap();
        assert_eq!(list.names().count(), 0);
    }

    #[test]
    fn malformed_name_lists_are_rejected() {
        for raw in [&b",a"[..], b"a,", b"a,,b", b"a\xffb", b"a b"] {
            let mut w = Writer::new();
            w.put_string(raw);
            let bytes = w.into_bytes();
            assert_eq!(
                Reader::new(&bytes).name_list(64),
                Err(WireError::BadNameList),
                "should reject {raw:?}"
            );
        }
    }

    // ---- mpint ----

    #[test]
    fn mpint_canonical_roundtrips() {
        // RFC 4251 §5 worked examples.
        let cases: &[(&[u8], &[u8])] = &[
            (&[], &[]), // zero
            (&[0x09, 0xa3, 0x78, 0xf9], &[0x09, 0xa3, 0x78, 0xf9]),
            (&[0x80], &[0x00, 0x80]),       // high bit → 0x00 prefix
            (&[0x00, 0x00, 0x7f], &[0x7f]), // leading zeros stripped
        ];
        for (magnitude, expected_body) in cases {
            let mut w = Writer::new();
            w.put_mpint(magnitude);
            let bytes = w.into_bytes();
            let mut expected = Writer::new();
            expected.put_string(expected_body);
            assert_eq!(bytes, expected.into_bytes(), "encoding of {magnitude:?}");
            // And it parses back.
            Reader::new(&bytes).mpint(16).unwrap();
        }
    }

    #[test]
    fn non_canonical_mpints_are_rejected() {
        // 0x00 alone (zero must be empty), redundant leading 0x00,
        // and a negative value (high bit without 0x00 prefix).
        for body in [&[0x00][..], &[0x00, 0x7f], &[0x80]] {
            let mut w = Writer::new();
            w.put_string(body);
            let bytes = w.into_bytes();
            assert_eq!(
                Reader::new(&bytes).mpint(16),
                Err(WireError::BadMpint),
                "should reject {body:?}"
            );
        }
    }

    // ---- packet framing ----

    #[test]
    fn packet_roundtrip() {
        let payload = b"\x14quantumssh test payload";
        let packet = encode_packet(payload).unwrap();
        assert_eq!(packet.len() % PLAINTEXT_BLOCK, 0);
        let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let body_len = validate_packet_length(len).unwrap();
        assert_eq!(body_len, packet.len() - 4);
        assert_eq!(decode_packet_body(&packet[4..]).unwrap(), payload);
    }

    #[test]
    fn empty_payload_roundtrips() {
        let packet = encode_packet(b"").unwrap();
        assert_eq!(decode_packet_body(&packet[4..]).unwrap(), b"");
    }

    #[test]
    fn oversized_packet_length_is_rejected() {
        assert_eq!(
            validate_packet_length(MAX_PACKET + 1),
            Err(WireError::BadPacketLength(MAX_PACKET + 1))
        );
        assert_eq!(
            validate_packet_length(u32::MAX),
            Err(WireError::BadPacketLength(u32::MAX))
        );
        assert_eq!(
            validate_packet_length(0),
            Err(WireError::BadPacketLength(0))
        );
    }

    #[test]
    fn misaligned_packet_length_is_rejected() {
        // 4 + 9 = 13, not a multiple of 8.
        assert_eq!(validate_packet_length(9), Err(WireError::BadPadding));
    }

    #[test]
    fn padding_attacks_are_rejected() {
        // padding_length < 4.
        assert_eq!(
            decode_packet_body(&[3, 0, 0, 0]),
            Err(WireError::BadPadding)
        );
        // padding_length larger than the body.
        assert_eq!(
            decode_packet_body(&[200, 1, 2, 3]),
            Err(WireError::BadPadding)
        );
        // Empty body.
        assert_eq!(decode_packet_body(&[]), Err(WireError::Truncated));
    }

    #[test]
    fn oversized_payload_cannot_be_encoded() {
        let too_big = vec![0u8; MAX_PACKET as usize];
        assert!(matches!(
            encode_packet(&too_big),
            Err(WireError::BadPacketLength(_))
        ));
    }

    // ---- identification line ----

    #[test]
    fn server_id_is_wellformed_and_short() {
        assert!(SERVER_ID.starts_with("SSH-2.0-"));
        assert!(SERVER_ID.len() + 2 <= MAX_ID_LINE);
        parse_peer_id(SERVER_ID.as_bytes()).unwrap();
    }

    #[test]
    fn parses_openssh_style_id() {
        let id = parse_peer_id(b"SSH-2.0-OpenSSH_10.0p1 Debian-1").unwrap();
        assert_eq!(id.protoversion, "2.0");
        assert_eq!(id.softwareversion, "OpenSSH_10.0p1");
    }

    #[test]
    fn rejects_legacy_and_malformed_ids() {
        for line in [
            &b"SSH-1.99-old"[..],
            b"SSH-1.5-ancient",
            b"HTTP/1.1 400",
            b"SSH-2.0-",
            b"",
        ] {
            assert_eq!(
                parse_peer_id(line),
                Err(WireError::BadIdentification),
                "should reject {line:?}"
            );
        }
    }

    #[test]
    fn rejects_id_line_over_255_bytes() {
        let mut line = b"SSH-2.0-".to_vec();
        line.extend(std::iter::repeat_n(b'x', 300));
        assert_eq!(parse_peer_id(&line), Err(WireError::BadIdentification));
    }
}
