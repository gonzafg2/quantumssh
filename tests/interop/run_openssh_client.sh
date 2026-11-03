#!/usr/bin/env bash
# OpenSSH interop hard gate (ADR-0020).
#
# Drives a *real* OpenSSH client through connect → publickey auth → exec
# → clean close against the quantumssh release binary. Reproducible both
# locally (OpenSSH 10.6 or later, which speaks mlkem768x25519-sha256 and
# ssh-mldsa44-ed25519) and in the pinned CI container. Asserts the three
# hard subset checks ADR-0020 names — openssh_smoke, openssh_verbose_kex,
# negative_no_hybrid — the two ADR-0047 adds for the composite host key —
# openssh_hostkey_composite, negative_ed25519_hostkey — plus exit-status
# propagation (ADR-0023), and that `quantumssh keygen` writes a key
# ssh-keygen 10.6 reads and a server serves (RFC-0018 §6, ADR-0058 §4).
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
# Under umask 002 a fresh target/ would be group-writable and fail the
# ancestor walk; mktemp already makes WORK itself 0700.
chmod go-w target
WORK="$(mktemp -d "$PWD/target/interop.XXXXXX")"
SRV=0
cleanup() {
    [ "$SRV" -ne 0 ] && kill "$SRV" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Fresh composite host key (ADR-0047) and Ed25519 client key; authorize
# the client key.
ssh-keygen -t mldsa44-ed25519 -N "" -f "$WORK/hostkey" -q
ssh-keygen -t ed25519 -N "" -f "$WORK/clientkey" -q
cat "$WORK/clientkey.pub" > "$WORK/authorized_keys"

# A user CA the server trusts (ADR-0050 §3), composite only (§4), and a
# key that only its certificates authorize: it is not in authorized_keys.
ssh-keygen -t mldsa44-ed25519 -N "" -f "$WORK/ca" -q
cp "$WORK/ca.pub" "$WORK/trusted_user_ca_keys"
ssh-keygen -t ed25519 -N "" -f "$WORK/certkey" -q
# The gate opens its connections back to back, more than ADR-0028's
# default burst of 10 admits from one source.
printf 'schema_version = 1\n\n[auth]\ntrusted_user_ca_keys = "%s"\n\n[limits]\naccept_burst = 32\n' \
    "$WORK/trusted_user_ca_keys" > "$WORK/config.toml"

"$BIN" --config "$WORK/config.toml" \
       --listen "127.0.0.1:$PORT" \
       --host-key "$WORK/hostkey" \
       --authorized-keys "$WORK/authorized_keys" \
       --log-format human \
       > "$WORK/server.log" 2>&1 &
SRV=$!

LOG="$WORK/server.log"
fail() { echo "INTEROP FAIL: $1" >&2; cat "$LOG" >&2; exit 1; }

# Wait for a listener on port $1 (bash /dev/tcp; no nc dependency).
wait_listening() {
    for _ in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        sleep 0.1
    done
    fail "server never listened on port $1"
}
wait_listening "$PORT"

SSH_OPTS=(-i "$WORK/clientkey" -p "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o ConnectTimeout=10)

# 1. openssh_smoke: `ssh … echo hello` → hello, exit 0.
out="$(ssh "${SSH_OPTS[@]}" tester@127.0.0.1 'echo hello')" || fail "smoke: ssh exited $?"
[ "$out" = "hello" ] || fail "smoke: output '$out' != 'hello'"
echo "ok: openssh_smoke"

# 2. openssh_verbose_kex: the negotiated KEX is the hybrid, and the host
# key algorithm is the composite (ADR-0047, openssh_hostkey_composite).
verbose="$(ssh -v "${SSH_OPTS[@]}" tester@127.0.0.1 'true' 2>&1)" \
    || fail "verbose_kex: ssh exited $?"
grep -q "kex: algorithm: mlkem768x25519-sha256" <<<"$verbose" \
    || fail "verbose_kex: hybrid KEX not negotiated"
echo "ok: openssh_verbose_kex"
grep -q "kex: host key algorithm: ssh-mldsa44-ed25519" <<<"$verbose" \
    || fail "hostkey_composite: ssh-mldsa44-ed25519 not negotiated"
echo "ok: openssh_hostkey_composite"

# 3. negative_no_hybrid: a classical-only client is rejected (no downgrade).
if ssh "${SSH_OPTS[@]}" -o KexAlgorithms=curve25519-sha256 \
       tester@127.0.0.1 'true' 2>/dev/null; then
    fail "negative_no_hybrid: classical-only client was NOT rejected"
fi
echo "ok: negative_no_hybrid"

# 3b. negative_ed25519_hostkey (ADR-0047): a client limited to ssh-ed25519
# host keys finds no common algorithm; nothing falls back. The failure
# must be that negotiation, not any other one.
if refused="$(ssh "${SSH_OPTS[@]}" -o HostKeyAlgorithms=ssh-ed25519 \
       tester@127.0.0.1 'true' 2>&1)"; then
    fail "negative_ed25519_hostkey: an ssh-ed25519-only client was NOT rejected"
fi
grep -q "no matching host key type found. Their offer: ssh-mldsa44-ed25519" <<<"$refused" \
    || fail "negative_ed25519_hostkey: refused for another reason: $refused"
echo "ok: negative_ed25519_hostkey"

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

# 6. PTY (ADR-0038): `ssh -tt` allocates a pseudo-terminal; the command
# runs on it, with the slave as its controlling terminal.
out="$(ssh -tt "${SSH_OPTS[@]}" tester@127.0.0.1 'tty; : < /dev/tty && echo ctty-ok' </dev/null | tr -d '\r')" \
    || fail "pty: ssh exited $?"
case "$out" in
    /dev/*ctty-ok*) ;;
    *) fail "pty: unexpected output '$out'" ;;
esac
echo "ok: openssh_pty"

# 7. SFTP (ADR-0041): `sftp -b` and `scp` (which uses SFTP by default)
# against the server's own SFTP v3 helper, each checked byte for byte.
# Remote paths are absolute: the helper starts in the account's $HOME.
COPY_OPTS=(-i "$WORK/clientkey" -P "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o ConnectTimeout=10)
head -c 300000 /dev/urandom > "$WORK/payload"
cat > "$WORK/batch" <<EOF
mkdir $WORK/remote
put $WORK/payload $WORK/remote/a
rename $WORK/remote/a $WORK/remote/b
get $WORK/remote/b $WORK/got
ls -l $WORK/remote
rm $WORK/remote/b
rmdir $WORK/remote
EOF
sftp -b "$WORK/batch" "${COPY_OPTS[@]}" tester@127.0.0.1 >/dev/null || fail "sftp: batch exited $?"
cmp -s "$WORK/payload" "$WORK/got" || fail "sftp: downloaded bytes differ"
[ ! -e "$WORK/remote" ] || fail "sftp: rmdir left the directory"
echo "ok: openssh_sftp"

scp "${COPY_OPTS[@]}" "$WORK/payload" "tester@127.0.0.1:$WORK/scp-up" || fail "scp: upload exited $?"
cmp -s "$WORK/payload" "$WORK/scp-up" || fail "scp: uploaded bytes differ"
scp "${COPY_OPTS[@]}" "tester@127.0.0.1:$WORK/scp-up" "$WORK/scp-down" || fail "scp: download exited $?"
cmp -s "$WORK/payload" "$WORK/scp-down" || fail "scp: downloaded bytes differ"
echo "ok: openssh_scp"

# 8. User certificates (ADR-0050 §8): `ssh-keygen -s` signs for the
# `tester` principal with a validity window, and the exec round trip runs
# on the certificate alone. A certificate for another principal, an
# expired one, and one from a CA the server does not trust are refused.
ssh-keygen -t mldsa44-ed25519 -N "" -f "$WORK/untrusted_ca" -q
sign() { # sign <name> <ca> <principal> <validity>: writes $WORK/<name>-cert.pub
    cp "$WORK/certkey.pub" "$WORK/$1.pub"
    ssh-keygen -q -s "$WORK/$2" -I "tester@interop" -n "$3" -V "$4" "$WORK/$1.pub"
}
sign valid ca tester -5m:+5m
sign other ca someone-else -5m:+5m
sign expired ca tester 20200101:20200102
sign untrusted untrusted_ca tester -5m:+5m
CERT_OPTS=(-i "$WORK/certkey" -p "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o ConnectTimeout=10)
out="$(ssh "${CERT_OPTS[@]}" -o CertificateFile="$WORK/valid-cert.pub" \
    tester@127.0.0.1 'echo cert-ok')" || fail "cert: ssh exited $?"
[ "$out" = "cert-ok" ] || fail "cert: output '$out' != 'cert-ok'"
grep -q "cert_key_id=tester@interop" "$WORK/server.log" \
    || fail "cert: auth.succeeded lacks cert_key_id (ADR-0051)"
echo "ok: openssh_cert"
for refused in other expired untrusted; do
    if ssh "${CERT_OPTS[@]}" -o CertificateFile="$WORK/$refused-cert.pub" \
           tester@127.0.0.1 'true' 2>/dev/null; then
        fail "cert: the $refused certificate was NOT refused"
    fi
done
echo "ok: openssh_cert_refusals"

# 9. quantumssh keygen (RFC-0018 §6, ADR-0058 §4): ssh-keygen reads the key
# keygen wrote back to the same public key and fingerprint, and a server
# started with that key serves the stock client. The first server is
# stopped first, so a pass cannot come from it.
kill "$SRV" && wait "$SRV" 2>/dev/null || true
SRV=0
kg_out="$("$BIN" keygen "$WORK/kghk")" || fail "keygen: exited $?"
[ "$(ssh-keygen -y -f "$WORK/kghk")" = "$(cat "$WORK/kghk.pub")" ] \
    || fail "keygen: ssh-keygen -y does not reproduce kghk.pub"
kg_fp="$(tail -n 1 <<<"$kg_out")"
[ "$(ssh-keygen -lf "$WORK/kghk.pub" | awk '{print $2}')" = "$kg_fp" ] \
    || fail "keygen: ssh-keygen -lf disagrees with the fingerprint keygen printed"
echo "ok: keygen_read_by_ssh_keygen"

KG_PORT=$((PORT + 1))
LOG="$WORK/server-keygen.log"
"$BIN" --listen "127.0.0.1:$KG_PORT" \
       --host-key "$WORK/kghk" \
       --authorized-keys "$WORK/authorized_keys" \
       --log-format human \
       > "$LOG" 2>&1 &
SRV=$!
wait_listening "$KG_PORT"
KG_OPTS=(-i "$WORK/clientkey" -p "$KG_PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o ConnectTimeout=10)
verbose="$(ssh -v "${KG_OPTS[@]}" tester@127.0.0.1 'true' 2>&1)" \
    || fail "keygen: ssh against the keygen host key exited $?"
grep -q "Server host key: ssh-mldsa44-ed25519 $kg_fp" <<<"$verbose" \
    || fail "keygen: the server did not present the keygen host key"
echo "ok: keygen_host_key_serves"

echo "INTEROP PASS"
