#!/usr/bin/env python3
"""Writes the fuzz targets' fixtures and seed inputs (ADR-0060 §6).

Every file under fuzz/fixtures/ and fuzz/seeds/ comes from this script,
so the script is the record of how each seed was produced. It uses only
the standard library and is deterministic: running it again writes the
same bytes.

Sources:
  * The OpenSSH 10.6p1 client's identification line, KEXINIT and hybrid
    init, and a composite public key, from the golden vector
    crates/quantumssh-core/tests/vectors/mlkem768x25519-sha256-openssh.txt
    (scripts/capture-openssh-kex-vector.sh). The composite key is the
    fixture CA of the user_certificate target.
  * The Ed25519 public key of RFC 8032 §7.1 TEST 1, the fixture
    authorized key of the userauth_request target.
  * Everything else is built here from the SSH wire grammar (RFC 4251
    §5, RFC 4253 §6, RFC 4252 §7, RFC 4254 §8, draft-ietf-sshm-cert,
    draft-ietf-secsh-filexfer-02), as the integration tests' encoders in
    crates/quantumssh-core/tests/support/mod.rs build the same messages.

Usage: python3 scripts/fuzz-seeds.py   (from the repository root)
"""

import base64
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTOR = ROOT / "crates/quantumssh-core/tests/vectors/mlkem768x25519-sha256-openssh.txt"
FUZZ = ROOT / "fuzz"

# RFC 8032 §7.1, TEST 1: the public key.
ED25519_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_HYBRID_INIT = 30
SSH_MSG_USERAUTH_REQUEST = 50

CERT_ALGORITHM = b"ssh-ed25519-cert-v01@openssh.com"
COMPOSITE_ALGORITHM = b"ssh-mldsa44-ed25519"
COMPOSITE_SIGNATURE_LEN = 2420 + 64


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def string(b):
    return u32(len(b)) + b


def boolean(v):
    return b"\x01" if v else b"\x00"


def frame(payload):
    """A plaintext binary packet (RFC 4253 §6) with zero padding."""
    padding = 8 - (5 + len(payload)) % 8
    if padding < 4:
        padding += 8
    return u32(1 + len(payload) + padding) + bytes([padding]) + payload + bytes(padding)


def read_vector():
    fields = {}
    for line in VECTOR.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = (part.strip() for part in line.split("=", 1))
            fields[key] = bytes.fromhex(value)
    return fields


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    v = read_vector()
    ed25519_blob = string(b"ssh-ed25519") + string(ED25519_PUBLIC)
    ca_blob = v["host_key_blob"]

    write(
        FUZZ / "fixtures/authorized_keys",
        b"ssh-ed25519 " + base64.b64encode(ed25519_blob) + b" fuzz\n",
    )
    write(
        FUZZ / "fixtures/trusted_user_ca_keys",
        COMPOSITE_ALGORITHM + b" " + base64.b64encode(ca_blob) + b" fuzz-ca\n",
    )

    seeds = FUZZ / "seeds"
    client_id = v["client_id"]
    client_kexinit = v["client_kexinit"]
    hybrid_init = bytes([SSH_MSG_KEX_HYBRID_INIT]) + string(v["client_init"])
    assert client_kexinit[0] == SSH_MSG_KEXINIT

    write(seeds / "peer_id/openssh-10.6p1", client_id)
    write(seeds / "packet/kexinit-openssh-10.6p1", frame(client_kexinit))
    write(seeds / "packet/newkeys", frame(bytes([SSH_MSG_NEWKEYS])))
    write(seeds / "kexinit/openssh-10.6p1", client_kexinit)
    write(seeds / "hybrid_init/openssh-10.6p1", v["client_init"])
    write(
        seeds / "handshake/openssh-10.6p1",
        client_id
        + b"\r\n"
        + frame(client_kexinit)
        + frame(hybrid_init)
        + frame(bytes([SSH_MSG_NEWKEYS])),
    )

    # sealed_frame: selector (even: ChaCha20-Poly1305, odd: AES-256-GCM),
    # sequence number, the four length bytes, then the body and tag.
    gcm_length = 32  # a multiple of the 16-byte block, at least 5
    for selector, name in ((0, "chacha20-poly1305"), (1, "aes256-gcm")):
        write(
            seeds / f"sealed_frame/{name}",
            bytes([selector]) + u32(3) + u32(gcm_length) + bytes(gcm_length + 16),
        )

    write(
        seeds / "service_request/ssh-userauth",
        bytes([SSH_MSG_SERVICE_REQUEST]) + string(b"ssh-userauth"),
    )

    def userauth(method, tail=b""):
        return (
            bytes([SSH_MSG_USERAUTH_REQUEST])
            + string(b"alice")
            + string(b"ssh-connection")
            + string(method)
            + tail
        )

    probe = boolean(False) + string(b"ssh-ed25519") + string(ed25519_blob)
    signed = (
        boolean(True)
        + string(b"ssh-ed25519")
        + string(ed25519_blob)
        + string(string(b"ssh-ed25519") + string(bytes(64)))
    )
    write(seeds / "userauth_request/probe", userauth(b"publickey", probe))
    write(seeds / "userauth_request/signed", userauth(b"publickey", signed))
    write(seeds / "userauth_request/none", userauth(b"none"))

    # A structurally valid user certificate from the fixture CA, with a
    # signature of the right length that does not verify.
    certificate = (
        string(CERT_ALGORITHM)
        + string(bytes(range(32)))  # nonce
        + string(ED25519_PUBLIC)
        + u64(1)  # serial
        + u32(1)  # user certificate
        + string(b"fuzz-key-id")
        + string(string(b"fuzz"))  # principals
        + u64(0)  # valid after
        + u64(2**64 - 1)  # valid before
        + string(b"")  # critical options
        + string(string(b"permit-pty") + string(b""))  # extensions
        + string(b"")  # reserved
        + string(ca_blob)
        + string(string(COMPOSITE_ALGORITHM) + string(bytes(COMPOSITE_SIGNATURE_LEN)))
    )
    write(seeds / "user_certificate/composite-ca", certificate)

    # SFTP: framed packets (uint32 length, then the packet).
    def sftp(packet):
        return u32(len(packet)) + packet

    all_attrs = u32(0x1 | 0x2 | 0x4 | 0x8 | 0x8000_0000) + u64(4096)
    all_attrs += u32(1000) + u32(1000) + u32(0o644) + u32(1) + u32(2)
    all_attrs += u32(1) + string(b"name@example.com") + string(b"data")
    write(
        seeds / "sftp/session",
        sftp(b"\x01" + u32(3))  # INIT, version 3
        + sftp(b"\x03" + u32(1) + string(b"file") + u32(0x1 | 0x8) + u32(0))  # OPEN
        + sftp(b"\x09" + u32(2) + string(b"file") + all_attrs)  # SETSTAT
        + sftp(b"\x10" + u32(3) + string(b"~/dir")),  # REALPATH
    )

    # pty-req terminal modes (RFC 4254 §8): VINTR 3, ECHO 1, TTY_OP_END.
    write(seeds / "pty_modes/modes", b"\x01" + u32(3) + b"\x35" + u32(1) + b"\x00")
    write(seeds / "pty_modes/term", b"xterm-256color")


if __name__ == "__main__":
    main()
