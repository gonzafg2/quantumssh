#!/usr/bin/env bash
# Reference-unit check (ADR-0043 §7): the server under a real systemd,
# then account mode under its own unit (ADR-0067 §5).
#
# Runs as root inside a disposable container of the gate image
# (tests/gate-image/, ADR-0059), whose PID 1 is systemd. It installs
# QuantumSSH the way docs/deployment.md describes — a system account,
# /etc/quantumssh, /usr/local/bin and contrib/systemd/quantumssh.service,
# then test accounts and contrib/systemd/quantumssh-account-mode.service —
# so never run it on a real host. CI, the release workflow and a local run
# all drive it through tests/systemd/run_in_docker.sh, from the repository
# root.
#
# Env overrides: SRC (the checkout, default /src), QUANTUMSSH_BIN (the
# Linux release binary, default $SRC/target/release/quantumssh).
set -euo pipefail

[ "$(cat /proc/1/comm)" = systemd ] \
    || { echo "SYSTEMD FAIL: PID 1 is not systemd; run inside the tests/systemd container" >&2; exit 1; }
SRC="${SRC:-/src}"
BIN="${QUANTUMSSH_BIN:-$SRC/target/release/quantumssh}"
PORT=2222
DRAIN=4

fail() {
    echo "SYSTEMD FAIL: $1" >&2
    journalctl -u quantumssh --no-pager -o cat >&2 || true
    exit 1
}

# Install, as docs/deployment.md describes.
useradd --system --create-home --home-dir /var/lib/quantumssh \
    --shell /usr/sbin/nologin quantumssh
chmod 0700 /var/lib/quantumssh
install -m 0755 "$BIN" /usr/local/bin/quantumssh
install -d -m 0755 /etc/quantumssh
ssh-keygen -q -t mldsa44-ed25519 -N "" -f /etc/quantumssh/ssh_host_mldsa44_ed25519_key
chown quantumssh:quantumssh /etc/quantumssh/ssh_host_mldsa44_ed25519_key
WORK="$(mktemp -d)"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/client"
install -m 0644 "$WORK/client.pub" /etc/quantumssh/authorized_keys
cat > /etc/quantumssh/config.toml <<EOF
schema_version = 1

[server]
listen        = "127.0.0.1:$PORT"
host_key      = "/etc/quantumssh/ssh_host_mldsa44_ed25519_key"
drain_timeout = $DRAIN

[auth]
authorized_keys = "/etc/quantumssh/authorized_keys"
EOF
chmod 0644 /etc/quantumssh/config.toml
install -m 0644 "$SRC/contrib/systemd/quantumssh.service" /etc/systemd/system/
# A stop timeout shorter than the drain: only the STOPPING=1 extension
# keeps systemd from killing the server before the drain ends.
mkdir -p /etc/systemd/system/quantumssh.service.d
printf '[Service]\nTimeoutStopSec=2\n' > /etc/systemd/system/quantumssh.service.d/test.conf
systemctl daemon-reload

SSH=(ssh -i "$WORK/client" -p "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o LogLevel=ERROR)

# 1. Type=notify: `systemctl start` returns once READY=1 arrives, and the
# port accepts at that moment. The session runs as the account, in its
# home (RFC-0002), although systemd starts the server in `/`.
systemctl start quantumssh || fail "start"
[ "$(systemctl is-active quantumssh)" = active ] || fail "not active after start"
out="$("${SSH[@]}" tester@127.0.0.1 'id -un; pwd -P')" || fail "ssh exited $?"
[ "$out" = "quantumssh
/var/lib/quantumssh" ] || fail "session ran as/in '$out', want quantumssh in /var/lib/quantumssh"
echo "ok: systemd_notify_ready"

# 2. NoNewPrivileges= reaches every session.
nnp="$("${SSH[@]}" tester@127.0.0.1 'grep NoNewPrivs /proc/self/status')"
case "$nnp" in
    *1) ;;
    *) fail "NoNewPrivs not set in a session: '$nnp'" ;;
esac
echo "ok: systemd_no_new_privs"

# 3. Reload is restart-only (RFC-0010): the unit has no ExecReload=.
if systemctl reload quantumssh 2>/dev/null; then
    fail "reload was accepted"
fi
echo "ok: systemd_no_reload"

# 4. Stop. A session runs `sleep 300`, and another left a process
# outside its channel's process group (`setsid`).
"${SSH[@]}" tester@127.0.0.1 'setsid sleep 301 </dev/null >/dev/null 2>&1 &' \
    || fail "ssh (escape) exited $?"
"${SSH[@]}" tester@127.0.0.1 'sleep 300' &
session=$!
for _ in $(seq 1 100); do
    pgrep -u quantumssh -fx 'sleep 300' >/dev/null && break
    sleep 0.1
done
pgrep -u quantumssh -fx 'sleep 300' >/dev/null || fail "the session's sleep never started"
pgrep -u quantumssh -fx 'sleep 301' >/dev/null || fail "the escaped sleep is not running"

start=$(date +%s)
systemctl stop quantumssh
elapsed=$(( $(date +%s) - start ))
wait "$session" || true
result="$(systemctl show -p Result --value quantumssh)"
status="$(systemctl show -p ExecMainStatus --value quantumssh)"
# A SIGKILL at TimeoutStopSec=2 would read Result=timeout.
[ "$result" = success ] || fail "stop result '$result', want success"
[ "$status" = 0 ] || fail "exit status $status, want 0"
[ "$elapsed" -ge "$DRAIN" ] || fail "stopped after ${elapsed}s, before the ${DRAIN}s drain"
if pgrep -u quantumssh >/dev/null; then
    fail "processes of the account survived the stop: $(pgrep -u quantumssh -a)"
fi
log="$(journalctl -u quantumssh --no-pager -o cat)"
started=$(grep -c '"exec.started"' <<<"$log" || true)
finished=$(grep -c '"exec.finished"' <<<"$log" || true)
[ "$started" -eq 4 ] && [ "$finished" -eq 4 ] \
    || fail "exec.started=$started exec.finished=$finished, want 4 and 4"
echo "ok: systemd_stop_drain (${elapsed}s)"

# ---------------------------------------------------------------------
# Account mode (ADR-0067 §5): the account-mode unit, installed under the
# same name in place of the reference unit, with the same drop-in.
install -m 0644 "$SRC/contrib/systemd/quantumssh-account-mode.service" \
    /etc/systemd/system/quantumssh.service
systemctl daemon-reload

# 5. The service-account configuration, which lists no account, fails
# the start under this unit, and the journal names the flag.
since="$(date '+%Y-%m-%d %H:%M:%S')"
if systemctl start quantumssh 2>/dev/null; then
    fail "the account-mode unit started a configuration without accounts"
fi
systemctl stop quantumssh 2>/dev/null || true
systemctl reset-failed quantumssh 2>/dev/null || true
journalctl -u quantumssh --since "$since" --no-pager -o cat | grep -qF -- '--require-account-mode' \
    || fail "the refusal does not name --require-account-mode"
echo "ok: systemd_account_mode_requires_accounts"

# The accounts, their key files, and a configuration that lists them,
# all owned by root (RFC-0019 §8).
groupadd qssh-team
useradd --create-home --shell /bin/bash --groups qssh-team qssh-alice
useradd --create-home --shell /bin/sh qssh-bob
install -d -m 0755 /etc/quantumssh/keys
for name in alice bob; do
    ssh-keygen -q -t ed25519 -N "" -f "$WORK/$name"
    install -m 0644 "$WORK/$name.pub" "/etc/quantumssh/keys/qssh-$name"
done
cat > /etc/quantumssh/config.toml <<EOF
schema_version = 1

[server]
listen        = "127.0.0.1:$PORT"
host_key      = "/etc/quantumssh/ssh_host_mldsa44_ed25519_key"
drain_timeout = $DRAIN

[[account]]
name            = "qssh-alice"
authorized_keys = "/etc/quantumssh/keys/qssh-alice"

[[account]]
name            = "qssh-bob"
authorized_keys = "/etc/quantumssh/keys/qssh-bob"
EOF
chmod 0644 /etc/quantumssh/config.toml
ALICE=(ssh -i "$WORK/alice" -p "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o LogLevel=ERROR)

# 6. The unit runs, and a session runs as its account, in its home.
systemctl start quantumssh || fail "account mode: start"
[ "$(systemctl is-active quantumssh)" = active ] || fail "account mode: not active after start"
invocation="$(systemctl show -p InvocationID --value quantumssh)"
out="$("${ALICE[@]}" qssh-alice@127.0.0.1 'id -un; pwd -P')" || fail "account mode: ssh exited $?"
[ "$out" = "qssh-alice
/home/qssh-alice" ] || fail "account mode: session ran as/in '$out', want qssh-alice in /home/qssh-alice"
echo "ok: systemd_account_session"

# 7. The three processes: the launcher, the unit's main process, is
# root; the server is the service account with no_new_privs; a session
# has no no_new_privs.
main="$(systemctl show -p MainPID --value quantumssh)"
[ "$(stat -c %u /proc/"$main")" = 0 ] || fail "the main process is not root"
server="$(pgrep -o -f -- '--quantumssh-internal-network-server' || true)"
[ -n "$server" ] || fail "no network server process"
[ "$(stat -c %U /proc/"$server")" = quantumssh ] || fail "the server is not quantumssh"
grep -qP '^NoNewPrivs:\t1$' /proc/"$server"/status || fail "the server has no no_new_privs"
nnp="$("${ALICE[@]}" qssh-alice@127.0.0.1 'grep NoNewPrivs /proc/self/status')"
case "$nnp" in
    *0) ;;
    *) fail "NoNewPrivs set in an account session: '$nnp'" ;;
esac
echo "ok: systemd_account_processes"

# 8. Reload is refused here too.
if systemctl reload quantumssh 2>/dev/null; then
    fail "account mode: reload was accepted"
fi
echo "ok: systemd_account_no_reload"

# 9. Each session joins its own session keyring (ADR-0074). A key that a
# session of qssh-alice links into its @s is not found by a session of
# qssh-bob, which shared the unit's keyring before. Neither qssh-bob nor
# the service account can read it by its serial.
case "$(uname -m)" in
    x86_64) nrs="248 250" ;;
    aarch64) nrs="217 219" ;;
    *) fail "no keyring system call numbers for $(uname -m)" ;;
esac
# From the checkout next to this script: a release tarball has no tests/.
install -m 0644 "$(dirname "$0")/keyring_probe.pl" /usr/local/share/keyring_probe.pl
BOB=("${ALICE[@]}")
BOB[2]="$WORK/bob"
"${ALICE[@]}" qssh-alice@127.0.0.1 "perl /usr/local/share/keyring_probe.pl $nrs add" \
    >"$WORK/alice-key" 2>&1 &
keyholder=$!
for _ in $(seq 1 100); do
    [ -s "$WORK/alice-key" ] && break
    sleep 0.1
done
serial="$(head -1 "$WORK/alice-key")"
case "$serial" in
    '' | *[!0-9]*) kill "$keyholder" 2>/dev/null; fail "qssh-alice could not add a key: $(cat "$WORK/alice-key")" ;;
esac
search="$("${BOB[@]}" qssh-bob@127.0.0.1 "perl /usr/local/share/keyring_probe.pl $nrs search")"
read_bob="$("${BOB[@]}" qssh-bob@127.0.0.1 "perl /usr/local/share/keyring_probe.pl $nrs read $serial")"
# shellcheck disable=SC2086 # $nrs is two arguments
read_service="$(setpriv --reuid quantumssh --regid quantumssh --clear-groups \
    perl /usr/local/share/keyring_probe.pl $nrs read "$serial")"
kill "$keyholder" 2>/dev/null || true
wait "$keyholder" 2>/dev/null || true
[ "$search" = "errno 126" ] || fail "qssh-bob's search for qssh-alice's key gave '$search', want ENOKEY"
[ "$read_bob" = "errno 13" ] || fail "qssh-bob reading qssh-alice's key gave '$read_bob', want EACCES"
[ "$read_service" = "errno 13" ] || fail "the service account reading qssh-alice's key gave '$read_service', want EACCES"
echo "ok: systemd_account_own_keyring"

# 10. Stop, as in 4: a session runs, and another left a process outside
# its process group.
"${ALICE[@]}" qssh-alice@127.0.0.1 'setsid sleep 303 </dev/null >/dev/null 2>&1 &' \
    || fail "account mode: ssh (escape) exited $?"
"${ALICE[@]}" qssh-alice@127.0.0.1 'sleep 302' &
session=$!
for _ in $(seq 1 100); do
    pgrep -u qssh-alice -fx 'sleep 302' >/dev/null && break
    sleep 0.1
done
pgrep -u qssh-alice -fx 'sleep 302' >/dev/null || fail "account mode: the session's sleep never started"
pgrep -u qssh-alice -fx 'sleep 303' >/dev/null || fail "account mode: the escaped sleep is not running"

start=$(date +%s)
systemctl stop quantumssh
elapsed=$(( $(date +%s) - start ))
wait "$session" || true
result="$(systemctl show -p Result --value quantumssh)"
status="$(systemctl show -p ExecMainStatus --value quantumssh)"
[ "$result" = success ] || fail "account mode: stop result '$result', want success"
[ "$status" = 0 ] || fail "account mode: exit status $status, want 0"
[ "$elapsed" -ge "$DRAIN" ] || fail "account mode: stopped after ${elapsed}s, before the ${DRAIN}s drain"
for user in qssh-alice qssh-bob quantumssh; do
    if pgrep -u "$user" >/dev/null; then
        fail "processes of $user survived the stop: $(pgrep -u "$user" -a)"
    fi
done
log="$(journalctl _SYSTEMD_INVOCATION_ID="$invocation" --no-pager -o cat)"
started=$(grep -c '"exec.started"' <<<"$log" || true)
finished=$(grep -c '"exec.finished"' <<<"$log" || true)
[ "$started" -eq 7 ] && [ "$finished" -eq 7 ] \
    || fail "account mode: exec.started=$started exec.finished=$finished, want 7 and 7"
echo "ok: systemd_account_stop_drain (${elapsed}s)"

echo "SYSTEMD PASS"
