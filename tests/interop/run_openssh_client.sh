#!/usr/bin/env bash
# The OpenSSH conformance suite (ADR-0062), grown from the interop hard
# gate of ADR-0020.
#
# Drives a *real* OpenSSH client against the quantumssh release binary,
# one case per behaviour. The catalogue, CASES.md, lists every case and
# the document it checks; the cases themselves are in cases.sh. This
# driver enforces the catalogue (ADR-0062 §3):
#
#   - before the first case, it fails if a case has no catalogue line or a
#     line has no case;
#   - it runs the cases in catalogue order;
#   - after the last, it fails unless every line reported `ok`, or a skip
#     that both its line and this leg allow.
#
# It needs bash (3.2 or later), coreutils, script(1), pgrep and the
# OpenSSH client set, 10.6 or later: ssh, ssh-keygen, ssh-keyscan,
# ssh-agent, sftp and scp. Nothing else, and no toolchain: the release
# gates run it on the artifacts (ADR-0055). The account cases (ADR-0068)
# also need root, useradd, groupadd, getent and perl.
#
# Env overrides:
#   QUANTUMSSH_BIN       the binary under test (default
#                        ./target/release/quantumssh)
#   QUANTUMSSH_PORT      the first of five consecutive ports (default 2222)
#   INTEROP_ALLOW_SKIP   the cases this leg may skip, space-separated. A
#                        skip that is not named here fails the run. The PR
#                        gate and the Linux release legs set none.
#   INTEROP_ACCOUNT_MODE 1 states that the run is inside a disposable
#                        container, where the account cases may create
#                        accounts and write under /etc (ADR-0068 §1).
#                        Without it, or off Linux, or not as root, they
#                        skip. Locally, run them through the gate image.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CATALOGUE="$HERE/CASES.md"
BIN="${QUANTUMSSH_BIN:-./target/release/quantumssh}"
PORT="${QUANTUMSSH_PORT:-2222}"
ALLOW_SKIP=" ${INTEROP_ALLOW_SKIP:-} "
HOST=tester@127.0.0.1

# The client sees nothing of the account it runs under: no ssh_config
# (every client run passes -F /dev/null) and no agent. An agent would
# reorder the keys a client offers, and a user's AddKeysToAgent would
# leave each run's throwaway keys in it.
unset SSH_AUTH_SOCK SSH_AGENT_PID

# The StrictModes walk (ADR-0029) checks every ancestor directory, so a
# workdir under the world-writable /tmp would refuse to start; the
# workdir lives under the repo's target/ instead (mktemp makes it 0700).
mkdir -p target
# Under umask 002 a fresh target/ would be group-writable and fail the
# ancestor walk; mktemp already makes WORK itself 0700.
chmod go-w target
WORK="$(mktemp -d "$PWD/target/interop.XXXXXX")"
LOG="$WORK/server.log"
SRV=0
CASE=setup
REPORTED=0
FINISHED=0

cleanup() {
    local status=$?
    # A command that failed under `set -e` did not go through fail():
    # say which case it was in, and show the server's side.
    if [ "$status" -ne 0 ] && [ "$REPORTED" -eq 0 ]; then
        echo "INTEROP FAIL: $CASE: a command failed (exit $status)" >&2
        [ -f "$LOG" ] && cat "$LOG" >&2
    fi
    # shellcheck disable=SC2046 # one PID per word is the point
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$WORK"
    # A run that stopped early without an error, such as a case that
    # called exit 0, did not run every case: that is a failure too.
    if [ "$status" -eq 0 ] && [ "$FINISHED" -eq 0 ]; then
        echo "INTEROP FAIL: $CASE: the run ended before every case reported" >&2
        exit 1
    fi
}
trap cleanup EXIT

fail() {
    REPORTED=1
    echo "INTEROP FAIL: $CASE: $1" >&2
    [ -f "$LOG" ] && cat "$LOG" >&2
    exit 1
}

# A case that cannot run on this client calls skip and returns.
skip() { CASE_SKIP="$1"; }

# wait_for <seconds> <command…>: poll until the command succeeds.
wait_for() {
    local tries=$(($1 * 10))
    shift
    while [ "$tries" -gt 0 ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
        tries=$((tries - 1))
    done
    return 1
}

# A listener on 127.0.0.1:<port> (bash /dev/tcp; no nc dependency).
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# start_server <port> <host key> <log> [--config <file>]: start the binary
# under test and wait for it to listen.
start_server() {
    local port=$1 key=$2 log=$3
    shift 3
    "$BIN" "$@" \
        --listen "127.0.0.1:$port" \
        --host-key "$key" \
        --authorized-keys "$WORK/authorized_keys" \
        --log-format json \
        >"$log" 2>&1 &
    SRV=$!
    LOG=$log
    wait_for 10 port_open "$port" || fail "server never listened on port $port"
}

stop_server() {
    [ "$SRV" -ne 0 ] || return 0
    kill "$SRV" 2>/dev/null || true
    wait "$SRV" 2>/dev/null || true
    SRV=0
}

# log_has <event> [<"field":value>…]: the server's audit log (RFC-0014)
# has a record of that event carrying every given field.
log_has() {
    local lines
    lines="$(grep -F "\"event\":\"$1\"" "$LOG" || true)"
    shift
    while [ "$#" -gt 0 ]; do
        lines="$(grep -F "$1" <<<"$lines" || true)"
        shift
    done
    [ -n "$lines" ]
}

# with_tty <shell command line>: run it on a terminal of its own, with no
# input. script(1) has two syntaxes, util-linux's and BSD's.
with_tty() {
    case "$(uname -s)" in
        Linux) script -qec "$1" /dev/null </dev/null ;;
        *) script -q /dev/null /bin/sh -c "$1" </dev/null ;;
    esac
}

# ---------------------------------------------------------------------
# Fixtures: a composite host key (ADR-0047), an Ed25519 client key that
# authorized_keys lists, and a user CA the server trusts (ADR-0050 §3),
# composite only (§4), with a key that only its certificates authorize.
ssh-keygen -t mldsa44-ed25519 -N "" -f "$WORK/hostkey" -q
ssh-keygen -t ed25519 -N "" -f "$WORK/clientkey" -q
cat "$WORK/clientkey.pub" >"$WORK/authorized_keys"
ssh-keygen -t mldsa44-ed25519 -N "" -f "$WORK/ca" -q
cp "$WORK/ca.pub" "$WORK/trusted_user_ca_keys"
ssh-keygen -t ed25519 -N "" -f "$WORK/certkey" -q
# The suite opens its connections back to back, far more than ADR-0028's
# default burst of 10 admits from one source.
printf 'schema_version = 1\n\n[auth]\ntrusted_user_ca_keys = "%s"\n\n[limits]\naccept_burst = 256\n' \
    "$WORK/trusted_user_ca_keys" >"$WORK/config.toml"

# Options every client run shares. COMMON has no identity and no port;
# SSH_OPTS is the authorized key for ssh, COPY_OPTS the same for sftp and
# scp, which spell the port -P.
COMMON=(-F /dev/null
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o PasswordAuthentication=no
    -o IdentitiesOnly=yes
    -o ConnectTimeout=10)
SSH_OPTS=(-i "$WORK/clientkey" -p "$PORT" "${COMMON[@]}")
COPY_OPTS=(-i "$WORK/clientkey" -P "$PORT" "${COMMON[@]}")

# ---------------------------------------------------------------------
# Account mode (ADR-0068): a second server, started as root, so it is a
# launcher. It is set up once, before the first account case, and serves
# every account case on its own port.
ACCT_DIR=/etc/quantumssh-interop
ACCT_BIN=/usr/local/libexec/quantumssh-interop/quantumssh
ACCT_PORT=$((10#$PORT + 4))
ACCT_LOG="$WORK/account-server.log"
ACCT_READY=0

# add_account <name> <login shell> [useradd options…]
add_account() {
    local name=$1 shell=$2
    shift 2
    getent passwd "$name" >/dev/null || useradd --create-home --shell "$shell" "$@" "$name"
}

# ADR-0068 §2: the service account, the test accounts, and the run's
# files under a root-owned directory that RFC-0019 §8 accepts.
account_setup() {
    install -D -o root -g root -m 0755 "$BIN" "$ACCT_BIN"
    getent passwd quantumssh >/dev/null \
        || useradd --system --no-create-home --shell /usr/sbin/nologin quantumssh
    getent group qssh-team >/dev/null || groupadd qssh-team
    add_account qssh-alice /bin/bash --groups qssh-team
    add_account qssh-deploy /bin/sh
    add_account qssh-nologin /usr/sbin/nologin
    add_account qssh-unlisted /bin/sh
    rm -rf "$ACCT_DIR"
    install -d -o root -g root -m 0755 "$ACCT_DIR" "$ACCT_DIR/keys"
    install -o quantumssh -g quantumssh -m 0600 "$WORK/hostkey" "$ACCT_DIR/host_key"
    install -o root -g root -m 0644 "$WORK/ca.pub" "$ACCT_DIR/trusted_user_ca_keys"
    local name
    for name in alice deploy nologin; do
        ssh-keygen -t ed25519 -N "" -f "$WORK/acct_$name" -q
        install -o root -g root -m 0644 "$WORK/acct_$name.pub" "$ACCT_DIR/keys/qssh-$name"
    done
    {
        printf 'schema_version = 1\n\n[server]\nlisten = "127.0.0.1:%s"\n' "$ACCT_PORT"
        printf 'host_key = "%s/host_key"\n\n' "$ACCT_DIR"
        printf '[auth]\ntrusted_user_ca_keys = "%s/trusted_user_ca_keys"\n\n' "$ACCT_DIR"
        printf '[limits]\naccept_burst = 256\n'
        for name in alice deploy nologin; do
            printf '\n[[account]]\nname = "qssh-%s"\nauthorized_keys = "%s/keys/qssh-%s"\n' \
                "$name" "$ACCT_DIR" "$name"
        done
    } >"$ACCT_DIR/config.toml"
    chmod 0644 "$ACCT_DIR/config.toml"
    LOG=$ACCT_LOG
    "$ACCT_BIN" --config "$ACCT_DIR/config.toml" --log-format json --require-account-mode \
        >"$ACCT_LOG" 2>&1 &
    wait_for 10 port_open "$ACCT_PORT" || fail "the account-mode server never listened on port $ACCT_PORT"
}

# account_mode: an account case's first call. It skips the case where
# account mode cannot run (ADR-0068 §1) and returns 1; otherwise it sets
# the run's accounts up once, and points LOG at the account-mode server.
account_mode() {
    if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ] || [ "${INTEROP_ACCOUNT_MODE:-}" != 1 ]; then
        skip "account mode needs Linux, root and INTEROP_ACCOUNT_MODE=1"
        return 1
    fi
    if [ "$ACCT_READY" -eq 0 ]; then
        account_setup
        ACCT_READY=1
    fi
    LOG=$ACCT_LOG
}

# acct_ssh <key> [ssh arguments…]: the stock client against the
# account-mode server, with that test account's key.
acct_ssh() {
    local key=$1
    shift
    ssh -i "$WORK/acct_$key" -p "$ACCT_PORT" "${COMMON[@]}" "$@"
}

# shellcheck source=tests/interop/cases.sh
. "$HERE/cases.sh"

# ---------------------------------------------------------------------
# The catalogue: a Markdown table, `| case | checks | may skip |`. A row
# counts when its first cell is a case name; the header and the rule
# under it are not.
NAMES=()
MAY_SKIP=()
while IFS='|' read -r _ name _ may_skip _; do
    name="$(tr -d '[:space:]' <<<"$name")"
    [[ "$name" =~ ^[a-z0-9_]+$ ]] || continue
    may_skip="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$may_skip")"
    [ -n "$may_skip" ] || fail "catalogue: $name has no 'may skip' cell"
    NAMES+=("$name")
    MAY_SKIP+=("$may_skip")
done < <(grep '^|' "$CATALOGUE")
[ "${#NAMES[@]}" -gt 0 ] || fail "catalogue: $CATALOGUE lists no case"

listed=" ${NAMES[*]} "
dups="$(printf '%s\n' "${NAMES[@]}" | sort | uniq -d | tr '\n' ' ')"
[ -z "$dups" ] || fail "catalogue: listed more than once: $dups"
for name in "${NAMES[@]}"; do
    declare -F "case_$name" >/dev/null || fail "catalogue: $name has a line and no case"
done
while read -r _ _ fn; do
    case "$fn" in
        case_*) ;;
        *) continue ;;
    esac
    case "$listed" in
        *" ${fn#case_} "*) ;;
        *) fail "catalogue: ${fn#case_} is a case with no line" ;;
    esac
done < <(declare -F)
for name in ${INTEROP_ALLOW_SKIP:-}; do
    case "$listed" in
        *" $name "*) ;;
        *) fail "INTEROP_ALLOW_SKIP names $name, which is not a case" ;;
    esac
done

# ---------------------------------------------------------------------
start_server "$PORT" "$WORK/hostkey" "$WORK/server.log" --config "$WORK/config.toml"

passed=0
skipped=0
i=0
while [ "$i" -lt "${#NAMES[@]}" ]; do
    CASE="${NAMES[$i]}"
    CASE_SKIP=""
    CASE_DIR="$WORK/c/$CASE"
    mkdir -p "$CASE_DIR"
    # Called as a plain statement, so `set -e` holds inside the case.
    "case_$CASE"
    # An account case points LOG at its own server.
    LOG="$WORK/server.log"
    if [ -n "$CASE_SKIP" ]; then
        [ "${MAY_SKIP[$i]}" != never ] \
            || fail "skipped ($CASE_SKIP), and its catalogue line says never"
        case "$ALLOW_SKIP" in
            *" $CASE "*) ;;
            *) fail "skipped ($CASE_SKIP), and this leg does not allow it (INTEROP_ALLOW_SKIP)" ;;
        esac
        echo "skip: $CASE ($CASE_SKIP)"
        skipped=$((skipped + 1))
    else
        echo "ok: $CASE"
        passed=$((passed + 1))
    fi
    i=$((i + 1))
done
CASE=summary

[ $((passed + skipped)) -eq "${#NAMES[@]}" ] \
    || fail "$((passed + skipped)) cases reported, the catalogue lists ${#NAMES[@]}"

FINISHED=1
echo "INTEROP PASS: $passed cases passed, $skipped skipped, ${#NAMES[@]} in the catalogue"
