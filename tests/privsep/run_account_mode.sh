#!/usr/bin/env bash
# Account mode's processes (RFC-0020, ADR-0066), as root: the launcher
# stays root, the network server runs as the service account with
# no_new_privs, and SIGTERM to the launcher stops the server and every
# session. What a client sees is the conformance suite's account cases
# (ADR-0068), in tests/interop/.
#
# It creates accounts and writes under /etc, so it runs only inside the
# disposable container that tests/privsep/run_in_docker.sh starts, which
# sets QUANTUMSSH_PRIVSEP_CONTAINER=1. Never run it on a real host.
set -euo pipefail

fail() {
    echo "ACCOUNT MODE FAIL: $*" >&2
    [ -f "${LOG:-/nonexistent}" ] && tail -n 30 "$LOG" >&2
    exit 1
}
[ "${QUANTUMSSH_PRIVSEP_CONTAINER:-}" = 1 ] \
    || fail "run through tests/privsep/run_in_docker.sh, not on a host"
[ "$(id -u)" -eq 0 ] || fail "must run as root inside the container"

src="${QUANTUMSSH_BIN:-/src/target/release/quantumssh}"
bin=/usr/local/libexec/quantumssh-account/quantumssh
install -D -o root -g root -m 0755 "$src" "$bin"

useradd --system --no-create-home --shell /usr/sbin/nologin quantumssh
groupadd qssh-team
useradd --create-home --shell /bin/bash --groups qssh-team qssh-alice

etc=/etc/quantumssh-account
install -d -o root -g root -m 0755 "$etc" "$etc/keys"
"$bin" keygen "$etc/host_key" >/dev/null
chown quantumssh:quantumssh "$etc/host_key"
chmod 0600 "$etc/host_key"
work="$(mktemp -d)"
ssh-keygen -q -t ed25519 -N "" -f "$work/alice"
install -o root -g root -m 0644 "$work/alice.pub" "$etc/keys/qssh-alice"
cat >"$etc/config.toml" <<TOML
schema_version = 1

[server]
listen = "127.0.0.1:2222"
host_key = "$etc/host_key"

[[account]]
name = "qssh-alice"
authorized_keys = "$etc/keys/qssh-alice"
TOML
chmod 0644 "$etc/config.toml"

LOG="$work/server.log"
"$bin" --config "$etc/config.toml" --log-format json --require-account-mode >"$LOG" 2>&1 &
launcher=$!
for _ in $(seq 1 100); do
    (exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null && break
    sleep 0.1
done
(exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null || fail "never listened"

SSH=(ssh -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o BatchMode=yes -o IdentitiesOnly=yes -i "$work/alice" -p 2222)
unset SSH_AUTH_SOCK SSH_AGENT_PID

# A session that is still running when the launcher is stopped.
"${SSH[@]}" qssh-alice@127.0.0.1 'sleep 600' >/dev/null 2>&1 &
client=$!
for _ in $(seq 1 100); do
    pgrep -u qssh-alice -x sleep >/dev/null && break
    sleep 0.1
done
pgrep -u qssh-alice -x sleep >/dev/null || fail "the session never started"

# 1. The launcher is root; the network server is the service account,
#    with no_new_privs, no supplementary group and no capability.
server="$(pgrep -f -- '--quantumssh-internal-network-server' | head -1)"
[ -n "$server" ] || fail "no network server process"
[ "$(stat -c %U /proc/"$launcher")" = root ] || fail "launcher not root"
[ "$(stat -c %U /proc/"$server")" = quantumssh ] || fail "server not quantumssh"
status="$(tr '\t' ' ' </proc/"$server"/status)"
grep -qx 'NoNewPrivs: 1' <<<"$status" || fail "server without no_new_privs"
grep -qx 'Groups: *' <<<"$status" || fail "server with groups: $(grep Groups <<<"$status")"
for field in CapInh CapPrm CapEff; do
    grep -qx "$field: 0000000000000000" <<<"$status" || fail "server with $field"
done

# 2. SIGTERM to the launcher stops everything; no process of either
#    account is left.
kill -TERM "$launcher"
rc=0
wait "$launcher" || rc=$?
[ "$rc" -eq 0 ] || fail "launcher exited $rc"
! pgrep -u qssh-alice >/dev/null || fail "processes of qssh-alice left"
! pgrep -u quantumssh >/dev/null || fail "processes of quantumssh left"

wait "$client" 2>/dev/null || true
echo "ACCOUNT MODE OK: launcher root, server unprivileged, and the stop"
