#!/usr/bin/env python3
"""The two halves of scripts/capture-openssh-kex-vector.sh (#216).

relay HOST PORT DIR
    The ssh ProxyCommand. It joins ssh's stdin and stdout to HOST:PORT
    and records each direction's bytes in DIR/c2s.bin and DIR/s2c.bin.

extract DIR COMMIT CLIENT IMAGE
    Reads the two recordings and the server's draw log DIR/draws.log
    (scripts/fixed-getrandom.c). It writes the golden vector in the
    `name = hex` format that crates/quantumssh-core/src/kex.rs reads,
    with COMMIT, CLIENT (`ssh -V`) and IMAGE as provenance.

The vector holds the captured transcript up to both NEWKEYS, the two
draws the server's hybrid exchange consumed (the ML-KEM encapsulation
seed m, then the X25519 secret), and the bytes the client sent after its
NEWKEYS. The draws are found without ML-KEM: the X25519 secret is the
draw whose public key is the second half of S_REPLY, and m is the draw
before it on the same thread.
"""

import os
import socket
import struct
import sys
import threading

SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_HYBRID_INIT = 30
SSH_MSG_KEX_HYBRID_REPLY = 31
MLKEM_CT_LEN = 1088

# RFC 7748 §5, X25519 with u = 9.
P = 2**255 - 19
A24 = 121665


def x25519_base(scalar):
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        da, cb = (x3 - z3) * a % P, (x3 + z3) * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


# RFC 7748 §6.1, Alice's key pair: the ladder above must reproduce it.
assert x25519_base(
    bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
) == bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")


def relay(host, port, directory):
    sock = socket.create_connection((host, int(port)))

    def pump(read, write, path):
        with open(path, "wb") as record:
            while data := read(65536):
                record.write(data)
                record.flush()
                write(data)

    def client_to_server():
        pump(lambda n: os.read(0, n), sock.sendall, os.path.join(directory, "c2s.bin"))
        sock.shutdown(socket.SHUT_WR)

    def write_stdout(data):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    upstream = threading.Thread(target=client_to_server, daemon=True)
    upstream.start()
    pump(sock.recv, write_stdout, os.path.join(directory, "s2c.bin"))
    upstream.join(timeout=5)


def split_id_line(stream):
    end = stream.index(b"\r\n")
    line = stream[:end]
    if not line.startswith(b"SSH-2.0-"):
        sys.exit(f"not an SSH-2.0 identification line: {line!r}")
    return line, stream[end + 2 :]


def plaintext_payloads(stream):
    """The payloads up to and including NEWKEYS, and the bytes after it.

    Before NEWKEYS the packets carry no MAC (RFC 4253 §6)."""
    payloads = []
    while True:
        length, padding = struct.unpack(">IB", stream[:5])
        payloads.append(stream[5 : 4 + length - padding])
        stream = stream[4 + length :]
        if payloads[-1] == bytes([SSH_MSG_NEWKEYS]):
            return payloads, stream


def ssh_strings(data, count):
    fields = []
    for _ in range(count):
        (length,) = struct.unpack(">I", data[:4])
        fields.append(data[4 : 4 + length])
        data = data[4 + length :]
    if data:
        sys.exit("trailing bytes after the expected fields")
    return fields


def expect_types(payloads, types, direction):
    found = [payload[0] for payload in payloads]
    if found != types:
        sys.exit(f"{direction}: message types {found}, expected {types}")


def hybrid_draws(log_path, server_x25519_public):
    with open(log_path, encoding="ascii") as f:
        draws = [line.split() for line in f]
    for i, (thread, length, value) in enumerate(draws):
        if length != "32" or x25519_base(bytes.fromhex(value)) != server_x25519_public:
            continue
        earlier = [d for d in draws[:i] if d[0] == thread]
        if not earlier or earlier[-1][1] != "32":
            sys.exit("the X25519 draw is not preceded by a 32-byte draw on its thread")
        return bytes.fromhex(earlier[-1][2]), bytes.fromhex(value)
    sys.exit("no draw yields the server's X25519 public key")


def extract(directory, commit, client, image):
    with open(os.path.join(directory, "c2s.bin"), "rb") as f:
        c2s = f.read()
    with open(os.path.join(directory, "s2c.bin"), "rb") as f:
        s2c = f.read()

    client_id, c2s = split_id_line(c2s)
    server_id, s2c = split_id_line(s2c)
    client_payloads, client_sealed = plaintext_payloads(c2s)
    server_payloads, _ = plaintext_payloads(s2c)
    expect_types(
        client_payloads,
        [SSH_MSG_KEXINIT, SSH_MSG_KEX_HYBRID_INIT, SSH_MSG_NEWKEYS],
        "client",
    )
    expect_types(
        server_payloads,
        [SSH_MSG_KEXINIT, SSH_MSG_KEX_HYBRID_REPLY, SSH_MSG_NEWKEYS],
        "server",
    )
    (client_init,) = ssh_strings(client_payloads[1][1:], 1)
    host_key_blob, server_reply, signature_blob = ssh_strings(server_payloads[1][1:], 3)
    m, server_x25519_b = hybrid_draws(
        os.path.join(directory, "draws.log"), server_reply[MLKEM_CT_LEN:]
    )

    print("# mlkem768x25519-sha256 golden vector (#216), captured against an")
    print("# OpenSSH peer by scripts/capture-openssh-kex-vector.sh:")
    print(f"#   client: {client}")
    print(f"#   server: quantumssh release binary at {commit}")
    print(f"#   image: {image}")
    print("# The server ran under the fixed-RNG profile of")
    print("# scripts/fixed-getrandom.c; m and server_x25519_b are the two draws")
    print("# its hybrid exchange consumed. The session ran a command and exited 0,")
    print("# so the client verified signature_blob over its own H and the two")
    print("# sides derived the same keys. client_sealed is every byte the client")
    print("# sent after its NEWKEYS. Do not edit by hand.")
    print()
    rows = [
        ("client_id", client_id),
        ("server_id", server_id),
        ("client_kexinit", client_payloads[0]),
        ("server_kexinit", server_payloads[0]),
        ("host_key_blob", host_key_blob),
        ("client_init", client_init),
        ("m", m),
        ("server_x25519_b", server_x25519_b),
        ("server_reply", server_reply),
        ("signature_blob", signature_blob),
        ("client_sealed", client_sealed),
    ]
    for name, value in rows:
        print(f"{name} = {value.hex()}")


def main():
    if sys.argv[1:2] == ["relay"] and len(sys.argv) == 5:
        relay(*sys.argv[2:])
    elif sys.argv[1:2] == ["extract"] and len(sys.argv) == 6:
        extract(*sys.argv[2:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
