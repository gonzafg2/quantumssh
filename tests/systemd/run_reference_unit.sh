#!/usr/bin/env bash
# Reference-unit check (ADR-0043 §7): the server under a real systemd.
#
# Runs as root inside the disposable container tests/systemd/Dockerfile
# builds, whose PID 1 is systemd. It installs QuantumSSH the way
# docs/deployment.md describes — a system account, /etc/quantumssh,
# /usr/local/bin and contrib/systemd/quantumssh.service — so never run it
# on a real host. CI and a local run drive it the same way:
#
#   docker build -t quantumssh-systemd tests/systemd
#   docker run -d --name quantumssh-systemd --privileged --cgroupns=host \
#       -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$PWD":/src:ro quantumssh-systemd
#   docker exec quantumssh-systemd bash /src/tests/systemd/run_reference_unit.sh
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
ssh-keygen -q -t ed25519 -N "" -f /etc/quantumssh/ssh_host_ed25519_key
chown quantumssh:quantumssh /etc/quantumssh/ssh_host_ed25519_key
WORK="$(mktemp -d)"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/client"
install -m 0644 "$WORK/client.pub" /etc/quantumssh/authorized_keys
cat > /etc/quantumssh/config.toml <<EOF
schema_version = 1

[server]
listen        = "127.0.0.1:$PORT"
host_key      = "/etc/quantumssh/ssh_host_ed25519_key"
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
# port accepts at that moment.
systemctl start quantumssh || fail "start"
[ "$(systemctl is-active quantumssh)" = active ] || fail "not active after start"
out="$("${SSH[@]}" tester@127.0.0.1 'id -un')" || fail "ssh exited $?"
[ "$out" = quantumssh ] || fail "session ran as '$out', want quantumssh"
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

echo "SYSTEMD PASS"
