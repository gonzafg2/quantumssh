#!/usr/bin/env bash
# Session-helper check (ADR-0065 §6): account mode's session helper, run
# as root, becomes a test account, proves that root cannot be regained,
# and runs the session.
#
# It creates a group and an account, so it runs only inside the
# disposable container that tests/privsep/run_in_docker.sh starts, which
# sets QUANTUMSSH_PRIVSEP_CONTAINER=1. Never run it on a real host.
#
# Env overrides: QUANTUMSSH_BIN (the Linux release binary, default
# /src/target/release/quantumssh).
set -euo pipefail

fail() { echo "PRIVSEP FAIL: $*" >&2; exit 1; }
[ "${QUANTUMSSH_PRIVSEP_CONTAINER:-}" = 1 ] \
    || fail "run through tests/privsep/run_in_docker.sh, not on a host"
[ "$(id -u)" -eq 0 ] || fail "must run as root inside the container"

# ADR-0066 §1: the launcher's executable is root-owned, in root-owned
# directories, as every session starts from it.
src="${QUANTUMSSH_BIN:-/src/target/release/quantumssh}"
helper=/usr/local/libexec/quantumssh-privsep/quantumssh
install -D -o root -g root -m 0755 "$src" "$helper"

groupadd qssh-team
useradd --create-home --shell /bin/bash --groups qssh-team qssh-alice
uid="$(id -u qssh-alice)"
gid="$(id -g qssh-alice)"
team="$(getent group qssh-team | cut -d: -f3)"
groups="$(printf '%s\n' "$gid" "$team" | sort -n | paste -sd,)"
home=/home/qssh-alice

# The environment the launcher sets (ADR-0065 §3).
session() {
    env -i HOME="$home" USER=qssh-alice LOGNAME=qssh-alice SHELL=/bin/bash \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin \
        "$helper" --quantumssh-internal-session "$@"
}

# 1. exec: the account's identity, every capability set empty, no
#    no_new_privs, the home directory, and argv[0] the shell's base name.
out="$(session exec pipes "$uid" "$gid" "$groups" "$home" /bin/bash \
    'grep -E "^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|NoNewPrivs):" /proc/self/status; pwd; echo "argv0=$0"')"
grep -qxP "Uid:\t$uid\t$uid\t$uid\t$uid" <<<"$out" || fail "Uid: $out"
grep -qxP "Gid:\t$gid\t$gid\t$gid\t$gid" <<<"$out" || fail "Gid: $out"
got="$(sed -n 's/^Groups:\t//p' <<<"$out" | tr ' ' '\n' | grep . | sort -n | paste -sd,)"
[ "$got" = "$groups" ] || fail "Groups: $got, want $groups"
for set in CapInh CapPrm CapEff; do
    grep -qxP "$set:\t0{16}" <<<"$out" || fail "$set not empty: $out"
done
grep -qxP "NoNewPrivs:\t0" <<<"$out" || fail "NoNewPrivs set: $out"
grep -qx "$home" <<<"$out" || fail "not in the home directory: $out"
grep -qx "argv0=bash" <<<"$out" || fail "argv[0]: $out"

# 2. exec passes the command's exit status through.
rc=0
session exec pipes "$uid" "$gid" "$groups" "$home" /bin/bash 'exit 7' || rc=$?
[ "$rc" -eq 7 ] || fail "exit status $rc, want 7"

# 3. shell: a login shell, argv[0] "-bash", reading stdin.
out="$(echo 'echo "argv0=$0 uid=$(id -u)"' \
    | session shell pipes "$uid" "$gid" "$groups" "$home" /bin/bash)"
grep -qx "argv0=-bash uid=$uid" <<<"$out" || fail "shell: $out"

# 4. sftp: the server answers SSH_FXP_INIT version 3 with SSH_FXP_VERSION,
#    type 2, the byte after the 4-byte length (draft-ietf-secsh-filexfer-02).
reply="$(printf '\x00\x00\x00\x05\x01\x00\x00\x00\x03' \
    | session sftp pipes "$uid" "$gid" "$groups" "$home" /bin/bash \
    | od -An -tu1 -j4 -N1 | tr -d ' ')"
[ "$reply" = 2 ] || fail "sftp reply type: '$reply', want 2"

# 5. A caller who is not root gets 127, and nothing else, at step 2.
rc=0
setpriv --reuid="$uid" --regid="$gid" --clear-groups \
    "$helper" --quantumssh-internal-session exec pipes 0 0 0 / /bin/sh 'echo escaped' \
    >/tmp/escaped 2>&1 || rc=$?
[ "$rc" -eq 127 ] || fail "non-root caller: exit $rc, want 127"
[ ! -s /tmp/escaped ] || fail "non-root caller printed: $(cat /tmp/escaped)"

# 6. Arguments the launcher could not have written: 127, before any
#    identity change. (uid_t)-1 would mean "leave unchanged".
rc=0
session exec pipes 4294967295 "$gid" "$groups" "$home" /bin/bash 'id -u' >/tmp/out 2>&1 || rc=$?
[ "$rc" -eq 127 ] && [ ! -s /tmp/out ] || fail "UID 4294967295: exit $rc, output $(cat /tmp/out)"

# 7. A capability the drop does not clear fails the check: with an
#    inheritable set, the session ends with 127 (ADR-0065 §2, step 5).
rc=0
setpriv --inh-caps=+net_raw env -i HOME="$home" PATH=/usr/bin:/bin \
    "$helper" --quantumssh-internal-session exec pipes "$uid" "$gid" "$groups" "$home" /bin/bash 'echo escaped' \
    >/tmp/inh 2>&1 || rc=$?
[ "$rc" -eq 127 ] && [ ! -s /tmp/inh ] || fail "inheritable capability: exit $rc, output $(cat /tmp/inh)"

echo "PRIVSEP OK: identity, groups, capabilities, home, exec, shell, sftp and refusals"
