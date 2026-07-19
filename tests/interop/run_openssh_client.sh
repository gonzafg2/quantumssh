#!/usr/bin/env bash
# OpenSSH interop hard gate (ADR-0020).
#
# Drives a *real* OpenSSH client through connect → publickey auth → exec
# → clean close against the quantumssh release binary. Reproducible both
# locally (any OpenSSH 10.x that speaks mlkem768x25519-sha256) and in the
# pinned CI container. Asserts the three hard subset checks ADR-0020
# names — openssh_smoke, openssh_verbose_kex, negative_no_hybrid — plus
# exit-status propagation (ADR-0023).
#
# Env overrides: QUANTUMSSH_BIN (default ./target/release/quantumssh),
# QUANTUMSSH_PORT (default 2222).
set -euo pipefail

BIN="${QUANTUMSSH_BIN:-./target/release/quantumssh}"
PORT="${QUANTUMSSH_PORT:-2222}"
# The StrictModes walk (ADR-0029) checks every ancestor directory, so a
# workdir under the world-writable /tmp would refuse to start; the
# workdir lives under the repo's target/ instead (mktemp makes it 0700).
mkdir -p target
WORK="$(mktemp -d "$PWD/target/interop.XXXXXX")"
SRV=0
cleanup() {
    [ "$SRV" -ne 0 ] && kill "$SRV" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Fresh host key and client key; authorize the client key.
ssh-keygen -t ed25519 -N "" -f "$WORK/hostkey" -q
ssh-keygen -t ed25519 -N "" -f "$WORK/clientkey" -q
cat "$WORK/clientkey.pub" > "$WORK/authorized_keys"

"$BIN" --listen "127.0.0.1:$PORT" \
       --host-key "$WORK/hostkey" \
       --authorized-keys "$WORK/authorized_keys" \
       --log-format human \
       > "$WORK/server.log" 2>&1 &
SRV=$!

# Wait for the listener (bash /dev/tcp; no nc dependency).
ready=0
for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        exec 3>&- 3<&-
        ready=1
        break
    fi
    sleep 0.1
done
[ "$ready" -eq 1 ] || { echo "INTEROP FAIL: server never listened" >&2; cat "$WORK/server.log" >&2; exit 1; }

SSH_OPTS=(-i "$WORK/clientkey" -p "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o ConnectTimeout=10)

fail() { echo "INTEROP FAIL: $1" >&2; cat "$WORK/server.log" >&2; exit 1; }

# 1. openssh_smoke: `ssh … echo hello` → hello, exit 0.
out="$(ssh "${SSH_OPTS[@]}" tester@127.0.0.1 'echo hello')" || fail "smoke: ssh exited $?"
[ "$out" = "hello" ] || fail "smoke: output '$out' != 'hello'"
echo "ok: openssh_smoke"

# 2. openssh_verbose_kex: the negotiated KEX is the hybrid.
ssh -v "${SSH_OPTS[@]}" tester@127.0.0.1 'true' 2>&1 \
    | grep -q "kex: algorithm: mlkem768x25519-sha256" \
    || fail "verbose_kex: hybrid KEX not negotiated"
echo "ok: openssh_verbose_kex"

# 3. negative_no_hybrid: a classical-only client is rejected (no downgrade).
if ssh "${SSH_OPTS[@]}" -o KexAlgorithms=curve25519-sha256 \
       tester@127.0.0.1 'true' 2>/dev/null; then
    fail "negative_no_hybrid: classical-only client was NOT rejected"
fi
echo "ok: negative_no_hybrid"

# 4. exit-status propagation (ADR-0023): `exit 3` reports 3.
rc=0
ssh "${SSH_OPTS[@]}" tester@127.0.0.1 'exit 3' || rc=$?
[ "$rc" -eq 3 ] || fail "exit_status: got $rc, want 3"
echo "ok: exit_status_propagation"

# 5. re-keying (ADR-0026): a low client RekeyLimit forces several
# client-initiated re-keys mid-transfer; the server must respond and the
# stream must survive intact.
n=$(ssh "${SSH_OPTS[@]}" -o RekeyLimit=16K tester@127.0.0.1 'head -c 262144 /dev/zero' | wc -c | tr -d ' ')
[ "$n" = "262144" ] || fail "rekey: got $n bytes across re-keys, want 262144"
echo "ok: openssh_rekey"

echo "INTEROP PASS"
