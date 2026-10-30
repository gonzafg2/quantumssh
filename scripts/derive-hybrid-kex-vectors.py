#!/usr/bin/env python3
"""Derives known-answer vectors for mlkem768x25519-sha256 (#216).

Threat model §5.2.4 asks for the hybrid combiner K = HASH(K_PQ || K_CL)
and the exchange hash H to be testable against fixed inputs. Neither
RFC 10042 nor its draft publishes vectors, so this script builds them
from the two published component vectors:

- ML-KEM-768: the first [encapsulation] case of
  crates/quantumssh-core/tests/vectors/ml-kem-768-acvp.txt (NIST ACVP),
  which gives ek, the encapsulation seed m, the ciphertext c and K_PQ;
- X25519: RFC 7748 §6.1, with Alice as the client and Bob as the
  server, which gives both key pairs and K_CL.

It computes C_INIT and S_REPLY (RFC 10042 §2.1), K (§2.4), H over fixed
stand-in inputs (§2.5) and one derived key (RFC 4253 §7.2) with
hashlib, independently of the code under test, and writes them in the
`name = hex` format crates/quantumssh-core/src/kex.rs reads.

Usage:
  derive-hybrid-kex-vectors.py ACVP_TXT RFC7748_TXT > OUT

RFC7748_TXT is https://www.rfc-editor.org/rfc/rfc7748.txt. The output
header records the SHA-256 of both inputs.
"""

import hashlib
import re
import struct
import sys

# The stand-in inputs of H. H hashes each one as an opaque SSH string,
# so any fixed bytes do; these read like the real ones.
CLIENT_ID = b"SSH-2.0-OpenSSH_10.6"
SERVER_ID = b"SSH-2.0-QuantumSSH_0.0.1"
CLIENT_KEXINIT = b"client SSH_MSG_KEXINIT payload"
SERVER_KEXINIT = b"server SSH_MSG_KEXINIT payload"
HOST_KEY_ALGORITHM = b"ssh-ed25519"
HOST_KEY = bytes(range(32))

# One derived key: the client-to-server encryption key (RFC 4253 §7.2
# letter "C"), 64 bytes as chacha20-poly1305@openssh.com takes, so the
# extension step K2 = HASH(K || H || K1) runs too. The first exchange's
# H is the session identifier.
KEY_LETTER = b"C"
KEY_LENGTH = 64


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def ssh_string(data):
    return struct.pack(">I", len(data)) + data


def first_encapsulation_case(path):
    """The fields of the first case in the [encapsulation] section."""
    section, case = None, {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                if section == "encapsulation" and case:
                    break
                section = line.strip("[]")
                continue
            if section != "encapsulation":
                continue
            name, value = line.split(" = ")
            if name == "tcId" and case:
                break
            case[name] = value
    if not case:
        sys.exit(f"{path}: no [encapsulation] case")
    return case


def rfc7748_curve25519_vector(path):
    """The five values of RFC 7748 §6.1's test vector, by their labels."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # The headings at the start of a line, not the table of contents.
    start = re.search(r"^6\.1\.  Curve25519$", text, re.M)
    end = re.search(r"^6\.2\.  Curve448$", text, re.M)
    if not start or not end:
        sys.exit(f"{path}: no §6.1 heading")
    section = text[start.start() : end.start()]
    labels = {
        "alice_secret": "Alice's private key, a:",
        "alice_public": "Alice's public key, X25519(a, 9):",
        "bob_secret": "Bob's private key, b:",
        "bob_public": "Bob's public key, X25519(b, 9):",
        "shared": "Their shared secret, K:",
    }
    values = {}
    for name, label in labels.items():
        match = re.search(re.escape(label) + r"\s+([0-9a-f]{64})", section)
        if not match:
            sys.exit(f"{path}: no {label!r} in §6.1")
        values[name] = bytes.fromhex(match.group(1))
    return values


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    acvp_path, rfc_path = sys.argv[1:]
    case = first_encapsulation_case(acvp_path)
    x25519 = rfc7748_curve25519_vector(rfc_path)

    ek = bytes.fromhex(case["ek"])
    ciphertext = bytes.fromhex(case["c"])
    k_pq = bytes.fromhex(case["k"])
    k_cl = x25519["shared"]

    client_init = ek + x25519["alice_public"]
    server_reply = ciphertext + x25519["bob_public"]
    k = hashlib.sha256(k_pq + k_cl).digest()

    host_key_blob = ssh_string(HOST_KEY_ALGORITHM) + ssh_string(HOST_KEY)
    h = hashlib.sha256(
        b"".join(
            ssh_string(field)
            for field in (
                CLIENT_ID,
                SERVER_ID,
                CLIENT_KEXINIT,
                SERVER_KEXINIT,
                host_key_blob,
                client_init,
                server_reply,
                k,
            )
        )
    ).digest()

    k_string = ssh_string(k)
    key = hashlib.sha256(k_string + h + KEY_LETTER + h).digest()
    while len(key) < KEY_LENGTH:
        key += hashlib.sha256(k_string + h + key).digest()
    key = key[:KEY_LENGTH]

    print("# mlkem768x25519-sha256 known-answer vectors (#216), derived from")
    print("# published component vectors by scripts/derive-hybrid-kex-vectors.py:")
    print(f"#   ML-KEM-768: ml-kem-768-acvp.txt [encapsulation] tcId {case['tcId']}")
    print(f"#     sha256 {sha256_file(acvp_path)}")
    print("#   X25519: RFC 7748 §6.1, the client is Alice and the server Bob")
    print(f"#     rfc7748.txt sha256 {sha256_file(rfc_path)}")
    print("# K, H and key_c are computed with Python's hashlib. H's identification")
    print("# lines, KEXINIT payloads and host key are fixed stand-ins; key_c is the")
    print(f"# letter-C key, {KEY_LENGTH} bytes, with H as the session identifier.")
    print("# Do not edit by hand.")
    print()
    rows = [
        ("m", bytes.fromhex(case["m"])),
        ("server_x25519_b", x25519["bob_secret"]),
        ("client_init", client_init),
        ("server_reply", server_reply),
        ("k_pq", k_pq),
        ("k_cl", k_cl),
        ("k", k),
        ("client_id", CLIENT_ID),
        ("server_id", SERVER_ID),
        ("client_kexinit", CLIENT_KEXINIT),
        ("server_kexinit", SERVER_KEXINIT),
        ("host_key_blob", host_key_blob),
        ("h", h),
        ("key_c", key),
    ]
    for name, value in rows:
        print(f"{name} = {value.hex()}")


if __name__ == "__main__":
    main()
