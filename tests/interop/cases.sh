# shellcheck shell=bash
# The cases of the OpenSSH conformance suite (ADR-0062). Sourced by
# run_openssh_client.sh, which supplies fail, skip, wait_for, port_open,
# log_has, with_tty, start_server and stop_server, the option arrays
# COMMON, SSH_OPTS and COPY_OPTS, and BIN, PORT, HOST, WORK, LOG and
# CASE_DIR; for the account cases, account_mode, acct_ssh and ACCT_PORT.
#
# One function per case, `case_<name>`, with a line in CASES.md that says
# which document the case checks. A case fails through fail(), or by any
# command failing under `set -e`.
#
# Two rules from ADR-0062 §4:
#   - a refusal case asserts the refusal, not only that the client failed;
#   - a case about which side acted reads it from the server's audit log.
#
# The single-quoted remote commands are meant to expand on the server.
# shellcheck disable=SC2016

# ---------------------------------------------------------------------
# Helpers shared by cases.

client_has_cipher() { ssh -Q cipher | grep -x "$1" >/dev/null; }
client_has_key_type() { ssh -Q key | grep -x "$1" >/dev/null; }
client_has_compression() { ssh -Q compression | grep -x "$1" >/dev/null; }

# refused_with <the client's message> <ssh options…>: a run with those
# options fails, and fails with that message.
refused_with() {
    local want=$1 out
    shift
    if out="$(ssh "${SSH_OPTS[@]}" "$@" "$HOST" true 2>&1)"; then
        fail "the client was NOT refused"
    fi
    grep -qF "$want" <<<"$out" || fail "refused for another reason: $out"
}

# log_count <event> <"field":value>: how many such records the audit log
# holds.
log_count() { grep -F "\"event\":\"$1\"" "$LOG" | grep -cF "$2" || true; }

# sign_cert <name> <ca> <principal> <validity>: writes
# $CASE_DIR/<name>-cert.pub for the certificate key.
sign_cert() {
    cp "$WORK/certkey.pub" "$CASE_DIR/$1.pub"
    ssh-keygen -q -s "$2" -I "tester@interop" -n "$3" -V "$4" "$CASE_DIR/$1.pub"
}

# forward_refused <the client's message> <local port> <ssh arguments…>:
# a connection to a local forward makes the client open a direct-tcpip
# channel, and the client reports that failure.
forward_refused() {
    local want=$1 lport=$2 err="$CASE_DIR/err" pid
    shift 2
    ssh "${SSH_OPTS[@]}" -L "127.0.0.1:$lport:127.0.0.1:9" "$@" >/dev/null 2>"$err" &
    pid=$!
    disown "$pid"
    # Each probe of the port is itself a connection to forward.
    wait_for 10 port_open "$lport" || { kill "$pid" 2>/dev/null; fail "the client never listened on port $lport"; }
    wait_for 10 grep -qF "$want" "$err" || { kill "$pid" 2>/dev/null; fail "no '$want' from the client: $(cat "$err")"; }
    kill "$pid" 2>/dev/null || true
}

sleeps_running() { [ "$(pgrep -fx "sleep $1" | wc -l | tr -d ' ')" -eq "$2" ]; }

# ---------------------------------------------------------------------
# Negotiation.

case_openssh_smoke() {
    local out
    out="$(ssh "${SSH_OPTS[@]}" "$HOST" 'echo hello')" || fail "ssh exited $?"
    [ "$out" = "hello" ] || fail "output '$out' != 'hello'"
}

case_openssh_verbose_kex() {
    local v
    v="$(ssh -v "${SSH_OPTS[@]}" "$HOST" true 2>&1)" || fail "ssh exited $?"
    grep -q "kex: algorithm: mlkem768x25519-sha256" <<<"$v" || fail "hybrid KEX not negotiated"
}

case_openssh_hostkey_composite() {
    local v
    v="$(ssh -v "${SSH_OPTS[@]}" "$HOST" true 2>&1)" || fail "ssh exited $?"
    grep -q "kex: host key algorithm: ssh-mldsa44-ed25519" <<<"$v" \
        || fail "ssh-mldsa44-ed25519 not negotiated"
}

# Stock OpenSSH prefers ChaCha20, so the server's second cipher is asked
# for explicitly. A client built without OpenSSL does not offer it.
case_openssh_aes_gcm() {
    local v
    if ! client_has_cipher aes256-gcm@openssh.com; then
        skip "this client offers no aes256-gcm@openssh.com"
        return 0
    fi
    v="$(ssh -v "${SSH_OPTS[@]}" -o Ciphers=aes256-gcm@openssh.com "$HOST" 'echo gcm-ok' 2>&1)" \
        || fail "ssh exited $?"
    grep -q "cipher: aes256-gcm@openssh.com" <<<"$v" || fail "aes256-gcm@openssh.com not negotiated"
    grep -qx "gcm-ok" <<<"$v" || fail "the command's output is missing"
}

# The eight name-lists of the server's KEXINIT, as `ssh -vv` prints them.
case_server_offer() {
    local v got want
    v="$(ssh -vv "${SSH_OPTS[@]}" "$HOST" true 2>&1)" || fail "ssh exited $?"
    got="$(awk '/peer server KEXINIT proposal/ { n = 8; next } n > 0 { print; n-- }' <<<"$v" \
        | tr -d '\r' | sed 's/^debug2: //')"
    want="KEX algorithms: mlkem768x25519-sha256,kex-strict-s-v00@openssh.com
host key algorithms: ssh-mldsa44-ed25519
ciphers ctos: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
ciphers stoc: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs ctos: hmac-sha2-512-etm@openssh.com
MACs stoc: hmac-sha2-512-etm@openssh.com
compression ctos: none
compression stoc: none"
    [ "$got" = "$want" ] || fail "the server's offer is not the profile: $got"
}

case_negative_no_hybrid() {
    refused_with "no matching key exchange method found. Their offer: mlkem768x25519-sha256,kex-strict-s-v00@openssh.com" \
        -o KexAlgorithms=curve25519-sha256
}

# Another post-quantum hybrid is refused like a classical exchange: the
# server offers one KEX.
case_negative_sntrup761() {
    refused_with "no matching key exchange method found. Their offer: mlkem768x25519-sha256,kex-strict-s-v00@openssh.com" \
        -o KexAlgorithms=sntrup761x25519-sha512
}

# A client limited to ssh-ed25519 host keys finds no common algorithm;
# nothing falls back.
case_negative_ed25519_hostkey() {
    refused_with "no matching host key type found. Their offer: ssh-mldsa44-ed25519" \
        -o HostKeyAlgorithms=ssh-ed25519
}

case_legacy_cipher_refused() {
    refused_with "no matching cipher found. Their offer: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" \
        -o Ciphers=aes256-ctr
}

# A client that asks for compression still lists `none`, and that is what
# both directions negotiate. A client built without zlib cannot ask.
case_compression_none() {
    local v
    if ! client_has_compression zlib@openssh.com; then
        skip "this client offers no zlib@openssh.com"
        return 0
    fi
    v="$(ssh -v "${SSH_OPTS[@]}" -o Compression=yes "$HOST" 'echo comp-ok' 2>&1)" \
        || fail "ssh exited $?"
    [ "$(grep -c "kex: .* compression: none" <<<"$v")" -eq 2 ] \
        || fail "compression was not 'none' in both directions"
    grep -qx "comp-ok" <<<"$v" || fail "the command's output is missing"
}

# ssh-keyscan negotiates no strict-kex, so the server disconnects it
# before it sends a host key. The reason is read from the audit log.
case_keyscan_refused() {
    local out
    out="$(ssh-keyscan -p "$PORT" -t mldsa44-ed25519 127.0.0.1 2>"$CASE_DIR/err")" || true
    if grep -v '^#' <<<"$out" | grep -q .; then
        fail "ssh-keyscan read a host key: $out"
    fi
    wait_for 5 log_has kex.failed '"reason":"no-strict-kex"' '"disconnect_code":3' \
        || fail "the server did not refuse it for strict-kex: $(cat "$CASE_DIR/err")"
}

# Trusting the host key before the first connection, as
# docs/deployment.md §3 says: a known_hosts line made from the .pub file.
# Strict checking then connects, and refuses a host whose key is another.
case_known_hosts_from_pub() {
    local kh="$CASE_DIR/known_hosts" out strict
    strict=(-F /dev/null -i "$WORK/clientkey" -p "$PORT"
        -o IdentitiesOnly=yes -o PasswordAuthentication=no -o ConnectTimeout=10
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$kh"
        -o GlobalKnownHostsFile=/dev/null)
    printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d' ' -f1-2 "$WORK/hostkey.pub")" >"$kh"
    out="$(ssh "${strict[@]}" "$HOST" 'echo known-ok' 2>&1)" \
        || fail "strict checking refused the published key: $out"
    [ "$out" = "known-ok" ] || fail "output '$out' != 'known-ok'"
    ssh-keygen -t mldsa44-ed25519 -N "" -f "$CASE_DIR/other" -q
    printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d' ' -f1-2 "$CASE_DIR/other.pub")" >"$kh"
    if out="$(ssh "${strict[@]}" "$HOST" true 2>&1)"; then
        fail "a host whose key is not the known one was accepted"
    fi
    grep -qF "REMOTE HOST IDENTIFICATION HAS CHANGED" <<<"$out" || fail "refused for another reason: $out"
}

# A low client RekeyLimit forces several client-initiated re-keys
# mid-transfer; the server must respond and the stream must survive.
case_openssh_rekey() {
    local n
    n=$(ssh "${SSH_OPTS[@]}" -o RekeyLimit=16K "$HOST" 'head -c 262144 /dev/zero' | wc -c | tr -d ' ')
    [ "$n" = "262144" ] || fail "got $n bytes across re-keys, want 262144"
}

# The server starts a re-key after 1 GiB (ADR-0026). Under ChaCha20 the
# client's own limit is also 1 GiB and it starts first, so this runs
# under AES-GCM, whose client limit is far higher, and reads who started
# it from the audit log.
case_rekey_server_initiated() {
    local before n
    if ! client_has_cipher aes256-gcm@openssh.com; then
        skip "this client offers no aes256-gcm@openssh.com"
        return 0
    fi
    before="$(log_count rekey.completed '"initiator":"server","trigger":"bytes"')"
    n=$(ssh "${SSH_OPTS[@]}" -o Ciphers=aes256-gcm@openssh.com "$HOST" \
        'head -c 1200000000 /dev/zero' | wc -c | tr -d ' ')
    [ "$n" = "1200000000" ] || fail "got $n bytes across the re-key, want 1200000000"
    [ "$(log_count rekey.completed '"initiator":"server","trigger":"bytes"')" -gt "$before" ] \
        || fail "no re-key that the server started on its byte limit was logged"
}

# ---------------------------------------------------------------------
# Authentication.

# The client is willing to use a password here; the server offers
# publickey alone.
case_password_auth_not_offered() {
    local out
    if out="$(ssh -F /dev/null -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password,keyboard-interactive \
        "$HOST" true 2>&1)"; then
        fail "a client with no key was let in"
    fi
    grep -qF "Permission denied (publickey)." <<<"$out" || fail "refused for another reason: $out"
}

case_unauthorized_key_refused() {
    local out
    ssh-keygen -t ed25519 -N "" -f "$CASE_DIR/stranger" -q
    if out="$(ssh -i "$CASE_DIR/stranger" -p "$PORT" "${COMMON[@]}" -o BatchMode=yes \
        "$HOST" true 2>&1)"; then
        fail "a key that authorized_keys does not list was let in"
    fi
    grep -qF "Permission denied (publickey)." <<<"$out" || fail "refused for another reason: $out"
}

# The server names ssh-ed25519 as the only signature algorithm it takes
# (server-sig-algs), so the client has nothing to offer from an RSA or an
# ECDSA key.
case_legacy_user_keys_refused() {
    local t out
    if ! client_has_key_type ssh-rsa || ! client_has_key_type ecdsa-sha2-nistp256; then
        skip "this client has no RSA or ECDSA keys"
        return 0
    fi
    for t in rsa ecdsa; do
        ssh-keygen -t "$t" -N "" -f "$CASE_DIR/$t" -q
        if out="$(ssh -v -i "$CASE_DIR/$t" -p "$PORT" "${COMMON[@]}" -o BatchMode=yes \
            "$HOST" true 2>&1)"; then
            fail "a client with only an $t key was let in"
        fi
        grep -qF "server-sig-algs=<ssh-ed25519>" <<<"$out" \
            || fail "$t: the server did not name ssh-ed25519 alone"
        grep -qF "Permission denied (publickey)." <<<"$out" \
            || fail "$t: refused for another reason"
    done
}

# Every request that does not authenticate spends one of 12 attempts, and
# the twelfth ends the connection with code 11. Three unauthorized keys
# stay within the budget; fourteen do not.
case_auth_attempt_budget() {
    local i out many=() few=()
    for i in $(seq 1 14); do
        ssh-keygen -t ed25519 -N "" -f "$CASE_DIR/k$i" -q
        many+=(-i "$CASE_DIR/k$i")
        [ "$i" -gt 3 ] || few+=(-i "$CASE_DIR/k$i")
    done
    out="$(ssh "${few[@]}" -i "$WORK/clientkey" -p "$PORT" "${COMMON[@]}" -o BatchMode=yes \
        "$HOST" 'echo within-budget' 2>/dev/null)" || fail "three failures spent the budget"
    [ "$out" = "within-budget" ] || fail "output '$out' != 'within-budget'"
    if out="$(ssh "${many[@]}" -i "$WORK/clientkey" -p "$PORT" "${COMMON[@]}" -o BatchMode=yes \
        "$HOST" true 2>&1)"; then
        fail "fourteen unauthorized keys did not spend the budget"
    fi
    grep -qF ":11: too-many-auth-attempts" <<<"$out" || fail "ended for another reason: $out"
}

# `ssh-keygen -s` signs for the `tester` principal with a validity window,
# and the exec round trip runs on the certificate alone: its key is not in
# authorized_keys.
case_openssh_cert() {
    local out
    sign_cert valid "$WORK/ca" tester -5m:+5m
    out="$(ssh -i "$WORK/certkey" -p "$PORT" "${COMMON[@]}" \
        -o CertificateFile="$CASE_DIR/valid-cert.pub" "$HOST" 'echo cert-ok')" \
        || fail "ssh exited $?"
    [ "$out" = "cert-ok" ] || fail "output '$out' != 'cert-ok'"
    wait_for 5 log_has auth.succeeded '"cert_key_id":"tester@interop"' \
        || fail "auth.succeeded lacks cert_key_id (ADR-0051)"
}

# A certificate for another principal, an expired one, and one from a CA
# the server does not trust are refused. Each run must show that the
# client offered the certificate and was denied, so a run that failed for
# any other reason does not pass.
case_openssh_cert_refusals() {
    local refused out
    ssh-keygen -t mldsa44-ed25519 -N "" -f "$CASE_DIR/untrusted_ca" -q
    sign_cert other "$WORK/ca" someone-else -5m:+5m
    sign_cert expired "$WORK/ca" tester 20200101:20200102
    sign_cert untrusted "$CASE_DIR/untrusted_ca" tester -5m:+5m
    for refused in other expired untrusted; do
        if out="$(ssh -v -i "$WORK/certkey" -p "$PORT" "${COMMON[@]}" \
            -o CertificateFile="$CASE_DIR/$refused-cert.pub" "$HOST" true 2>&1)"; then
            fail "the $refused certificate was NOT refused"
        fi
        grep -qF "Offering public key: $CASE_DIR/$refused-cert.pub ED25519-CERT" <<<"$out" \
            || fail "the client never offered the $refused certificate: $out"
        grep -qF "Permission denied (publickey)." <<<"$out" \
            || fail "the $refused certificate was refused for another reason: $out"
    done
}

# ---------------------------------------------------------------------
# The session channel.

case_exit_status_propagation() {
    local rc=0
    ssh "${SSH_OPTS[@]}" "$HOST" 'exit 3' || rc=$?
    [ "$rc" -eq 3 ] || fail "got $rc, want 3"
}

# A command killed by a signal reports exit-signal, which the client
# turns into 255.
case_exit_signal() {
    local rc=0 v
    v="$(ssh -v "${SSH_OPTS[@]}" "$HOST" 'kill -TERM $$' 2>&1)" || rc=$?
    [ "$rc" -eq 255 ] || fail "ssh exited $rc, want 255"
    grep -q "rtype exit-signal" <<<"$v" || fail "no exit-signal reached the client"
}

case_stdin_round_trip() {
    head -c 4194304 /dev/urandom >"$CASE_DIR/in"
    ssh "${SSH_OPTS[@]}" "$HOST" cat <"$CASE_DIR/in" >"$CASE_DIR/out" || fail "ssh exited $?"
    cmp -s "$CASE_DIR/in" "$CASE_DIR/out" || fail "4 MiB through cat came back different"
}

case_stderr_separate() {
    ssh "${SSH_OPTS[@]}" -o LogLevel=ERROR "$HOST" 'echo to-out; echo to-err >&2' \
        >"$CASE_DIR/out" 2>"$CASE_DIR/err" || fail "ssh exited $?"
    [ "$(cat "$CASE_DIR/out")" = "to-out" ] || fail "stdout is '$(cat "$CASE_DIR/out")'"
    [ "$(cat "$CASE_DIR/err")" = "to-err" ] || fail "stderr is '$(cat "$CASE_DIR/err")'"
}

# `shell` with no PTY: the commands arrive on stdin.
case_shell_without_pty() {
    local rc=0 out
    out="$(printf 'echo shell-ok\nexit 7\n' | ssh -T "${SSH_OPTS[@]}" "$HOST")" || rc=$?
    [ "$rc" -eq 7 ] || fail "the shell exited $rc, want 7"
    [ "$out" = "shell-ok" ] || fail "output '$out' != 'shell-ok'"
}

# `ssh -tt` allocates a pseudo-terminal; the command runs on it, with the
# slave as its controlling terminal.
case_openssh_pty() {
    local out
    out="$(ssh -tt "${SSH_OPTS[@]}" "$HOST" 'tty; : < /dev/tty && echo ctty-ok' </dev/null | tr -d '\r')" \
        || fail "ssh exited $?"
    case "$out" in
        /dev/*ctty-ok*) ;;
        *) fail "unexpected output '$out'" ;;
    esac
}

# `shell` on a PTY: an interactive shell reads the commands typed at it.
case_shell_on_pty() {
    local rc=0 out
    out="$(printf 'tty\nexit 4\n' | ssh -tt "${SSH_OPTS[@]}" -o LogLevel=ERROR "$HOST" | tr -d '\r')" \
        || rc=$?
    [ "$rc" -eq 4 ] || fail "the shell exited $rc, want 4"
    # The line may start with the shell's prompt.
    grep -Eq '/dev/(pts/[0-9]+|ttys[0-9]+)$' <<<"$out" || fail "the shell had no terminal: $out"
}

# The PTY takes the client's window size, and a resize follows it
# (window-change). The client gets a terminal of its own from script(1).
# The remote side prints its size, waits for it to change, and prints it
# again; the local side resizes once the first size has arrived.
# script(1) types a character into the terminal when its own input ends
# (BSD's an EOF, util-linux's a NUL), and the remote PTY echoes it in
# front of the first size, so only the sizes are compared.
case_pty_window_change() {
    local out="$CASE_DIR/out" err="$CASE_DIR/err" tty_script="$CASE_DIR/tty.sh" got
    local remote='stty size; i=0; while [ "$(stty size)" = "30 100" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done; stty size'
    {
        echo 'stty cols 100 rows 30'
        echo '('
        echo '    i=0'
        printf '    until grep -q "30 100" %q 2>/dev/null || [ $i -ge 100 ]; do sleep 0.1; i=$((i + 1)); done\n' "$out"
        echo '    stty cols 132 rows 43 </dev/tty'
        echo ') &'
        printf '%q ' ssh -tt "${SSH_OPTS[@]}" "$HOST" "$remote"
        printf '>%q 2>%q\n' "$out" "$err"
    } >"$tty_script"
    with_tty "bash $(printf '%q' "$tty_script")" >/dev/null 2>&1 \
        || fail "the client exited $? on its terminal: $(cat "$err" 2>/dev/null)"
    got="$(tr -d '\r' <"$out" | grep -oE '[0-9]+ [0-9]+$' | tr '\n' ' ')"
    [ "$got" = "30 100 43 132 " ] || fail "sizes '$got', want '30 100 43 132 '"
}

# `env` is refused: the client sends the variable, and the session runs
# without it.
case_env_refused() {
    local v
    v="$(ssh -v "${SSH_OPTS[@]}" -o SetEnv=QSSH_INTEROP=1 "$HOST" \
        'echo env=${QSSH_INTEROP:-unset}' 2>&1)" || fail "ssh exited $?"
    grep -q "setting env QSSH_INTEROP" <<<"$v" || fail "the client did not send the variable"
    grep -qx "env=unset" <<<"$v" || fail "the variable reached the session"
}

# Agent forwarding is refused: the client asks for it, and the session has
# no agent socket.
case_agent_forwarding_refused() {
    local v
    v="$(
        eval "$(ssh-agent -s)" >/dev/null
        trap 'ssh-agent -k >/dev/null 2>&1' EXIT
        ssh -v -A "${SSH_OPTS[@]}" "$HOST" 'echo sock=${SSH_AUTH_SOCK:-unset}' 2>&1
    )" || fail "ssh exited $?"
    grep -qi "requesting.*agent forwarding" <<<"$v" || fail "the client did not ask for agent forwarding"
    grep -qx "sock=unset" <<<"$v" || fail "an agent socket reached the session"
}

case_unknown_subsystem_refused() {
    local out
    if out="$(ssh "${SSH_OPTS[@]}" -s "$HOST" nosuch 2>&1 </dev/null)"; then
        fail "an unknown subsystem was started"
    fi
    grep -qF "subsystem request failed on channel 0" <<<"$out" || fail "refused for another reason: $out"
}

# ---------------------------------------------------------------------
# Channels and requests the server refuses.

# With no session open, a direct-tcpip channel is an unknown type.
case_direct_tcpip_refused() {
    forward_refused "open failed: unknown channel type" "$((10#$PORT + 2))" -N "$HOST"
}

# With a session open, the one-channel rule answers first (ADR-0023's
# erratum of 2026-11-21).
case_direct_tcpip_refused_during_session() {
    forward_refused "open failed: administratively prohibited: one channel only" \
        "$((10#$PORT + 3))" "$HOST" 'sleep 60'
}

# tcpip-forward is a global request, and the server answers every global
# request with a failure.
case_remote_forwarding_refused() {
    local rc=0 out
    out="$(ssh "${SSH_OPTS[@]}" -o ExitOnForwardFailure=yes -R 0:127.0.0.1:9 "$HOST" \
        'echo SHOULD-NOT-RUN' 2>&1)" || rc=$?
    [ "$rc" -eq 255 ] || fail "ssh exited $rc, want 255"
    grep -qF "remote port forwarding failed for listen port 0" <<<"$out" \
        || fail "failed for another reason: $out"
    if grep -qx "SHOULD-NOT-RUN" <<<"$out"; then fail "the command ran"; fi
}

# One session channel per connection: a second, through the first
# connection's control socket, is refused.
case_second_session_refused() {
    local sock="$WORK/mux" pid out
    ssh "${SSH_OPTS[@]}" -M -S "$sock" "$HOST" 'sleep 60' >/dev/null 2>&1 &
    pid=$!
    disown "$pid"
    wait_for 10 test -S "$sock" || { kill "$pid" 2>/dev/null; fail "the first connection never made its control socket"; }
    out="$(ssh "${SSH_OPTS[@]}" -S "$sock" "$HOST" true 2>&1)" || true
    kill "$pid" 2>/dev/null || true
    grep -qF "Session open refused by peer" <<<"$out" || fail "the second session was not refused: $out"
}

# The server answers the client's keepalive, a global request, so a client
# that would give up after two silent seconds stays for four.
case_client_keepalive() {
    local out
    out="$(ssh "${SSH_OPTS[@]}" -o ServerAliveInterval=1 -o ServerAliveCountMax=2 "$HOST" \
        'sleep 4; echo alive')" || fail "ssh exited $?"
    [ "$out" = "alive" ] || fail "output '$out' != 'alive'"
}

# When the client goes away, the command's whole process group is killed.
# The sleeps are seen running first, so their absence means something.
case_client_gone_reaps_command() {
    local n=$((70000 + RANDOM)) pid
    # shellcheck disable=SC2029 # $n is meant to expand here, on the client
    ssh "${SSH_OPTS[@]}" "$HOST" "sleep $n & sleep $n" >/dev/null 2>&1 &
    pid=$!
    disown "$pid"
    wait_for 10 sleeps_running "$n" 2 || { kill "$pid" 2>/dev/null; fail "the command never started"; }
    kill -KILL "$pid"
    wait_for 10 sleeps_running "$n" 0 || { pkill -fx "sleep $n" || true; fail "the command outlived its client"; }
}

# ---------------------------------------------------------------------
# SFTP. Remote paths are absolute: the helper starts in the account's
# $HOME.

# `sftp -b` against the server's own SFTP v3 helper, checked byte for
# byte.
case_openssh_sftp() {
    local d=$CASE_DIR
    head -c 300000 /dev/urandom >"$d/payload"
    cat >"$d/batch" <<EOF
mkdir "$d/remote"
put "$d/payload" "$d/remote/a"
rename "$d/remote/a" "$d/remote/b"
get "$d/remote/b" "$d/got"
ls -l "$d/remote"
rm "$d/remote/b"
rmdir "$d/remote"
EOF
    sftp -b "$d/batch" "${COPY_OPTS[@]}" "$HOST" >/dev/null || fail "batch exited $?"
    cmp -s "$d/payload" "$d/got" || fail "downloaded bytes differ"
    [ ! -e "$d/remote" ] || fail "rmdir left the directory"
}

# scp uses SFTP by default.
case_openssh_scp() {
    local d=$CASE_DIR
    head -c 300000 /dev/urandom >"$d/payload"
    scp "${COPY_OPTS[@]}" "$d/payload" "$HOST:$d/up" || fail "upload exited $?"
    cmp -s "$d/payload" "$d/up" || fail "uploaded bytes differ"
    scp "${COPY_OPTS[@]}" "$HOST:$d/up" "$d/down" || fail "download exited $?"
    cmp -s "$d/payload" "$d/down" || fail "downloaded bytes differ"
}

# SETSTAT, SYMLINK and READLINK, and a READ from an offset: `chmod`,
# `ln -s` and a resumed download.
case_sftp_attrs_links_resume() {
    local d=$CASE_DIR
    head -c 100000 /dev/urandom >"$d/payload"
    head -c 40000 "$d/payload" >"$d/partial"
    mkdir "$d/remote"
    cat >"$d/batch" <<EOF
put "$d/payload" "$d/remote/f"
chmod 600 "$d/remote/f"
ln -s "$d/remote/f" "$d/remote/link"
reget "$d/remote/f" "$d/partial"
EOF
    sftp -b "$d/batch" "${COPY_OPTS[@]}" "$HOST" >/dev/null || fail "batch exited $?"
    [ -n "$(find "$d/remote/f" -perm 600)" ] || fail "chmod 600 did not reach the file"
    [ "$(readlink "$d/remote/link")" = "$d/remote/f" ] || fail "the symlink does not point at the file"
    cmp -s "$d/payload" "$d/partial" || fail "the resumed download differs"
}

# The helper has four extensions (ADR-0041). The client says so for the
# three it asks for and does not find, and nothing is created.
case_sftp_unsupported_extensions() {
    local d=$CASE_DIR out ext
    head -c 1000 /dev/urandom >"$d/payload"
    mkdir "$d/remote"
    cat >"$d/batch" <<EOF
put "$d/payload" "$d/remote/f"
-df "$d/remote"
-ln "$d/remote/f" "$d/remote/hard"
-cp "$d/remote/f" "$d/remote/copy"
EOF
    out="$(sftp -b "$d/batch" "${COPY_OPTS[@]}" "$HOST" 2>&1)" || fail "batch exited $?"
    for ext in statvfs@openssh.com hardlink@openssh.com copy-data; do
        grep -qF "Server does not support $ext extension" <<<"$out" \
            || fail "the client did not report $ext as unsupported: $out"
    done
    [ ! -e "$d/remote/hard" ] && [ ! -e "$d/remote/copy" ] || fail "a refused request created a file"
}

# ---------------------------------------------------------------------
# quantumssh keygen (RFC-0018 §6, ADR-0058 §4).

# ssh-keygen reads the key that keygen wrote back to the same public key
# and fingerprint.
case_keygen_read_by_ssh_keygen() {
    local out fp
    out="$("$BIN" keygen "$CASE_DIR/hostkey")" || fail "keygen exited $?"
    [ "$(ssh-keygen -y -f "$CASE_DIR/hostkey")" = "$(cat "$CASE_DIR/hostkey.pub")" ] \
        || fail "ssh-keygen -y does not reproduce hostkey.pub"
    fp="$(tail -n 1 <<<"$out")"
    [ "$(ssh-keygen -lf "$CASE_DIR/hostkey.pub" | awk '{print $2}')" = "$fp" ] \
        || fail "ssh-keygen -lf disagrees with the fingerprint keygen printed"
}

# A server started with a key that keygen wrote serves the stock client.
# It is a second server on its own port, so a pass cannot come from the
# first.
case_keygen_host_key_serves() {
    local kg_port=$((10#$PORT + 1)) main_srv=$SRV main_log=$LOG out fp v
    out="$("$BIN" keygen "$CASE_DIR/hostkey")" || fail "keygen exited $?"
    fp="$(tail -n 1 <<<"$out")"
    start_server "$kg_port" "$CASE_DIR/hostkey" "$CASE_DIR/server.log"
    v="$(ssh -v -i "$WORK/clientkey" -p "$kg_port" "${COMMON[@]}" "$HOST" true 2>&1)" \
        || fail "ssh against the keygen host key exited $?"
    grep -qF "Server host key: ssh-mldsa44-ed25519 $fp" <<<"$v" \
        || fail "the server did not present the keygen host key"
    stop_server
    SRV=$main_srv
    LOG=$main_log
}

# ---------------------------------------------------------------------
# Account mode (ADR-0068). Each case starts with account_mode, which
# skips it where account mode cannot run. The listed accounts are
# qssh-alice, qssh-deploy and qssh-nologin, each with its own key;
# qssh-unlisted exists and is not listed.

# offered_and_denied <key path> <output of ssh -v>: the client offered
# that key and was refused, as a wrong key is.
offered_and_denied() {
    grep -qF "Offering public key: $1 ED25519" <<<"$2" || fail "the client never offered $1: $2"
    grep -qF "Permission denied (publickey)." <<<"$2" || fail "refused for another reason: $2"
}

case_account_session_identity() {
    account_mode || return 0
    local got want home team
    home="$(getent passwd qssh-alice | cut -d: -f6)"
    team="$(getent group qssh-team | cut -d: -f3)"
    got="$(acct_ssh alice qssh-alice@127.0.0.1 \
        'id -u; id -g; id -G | tr " " "\n" | sort -n | tr "\n" " "; echo; pwd -P; echo "$HOME $USER $LOGNAME $SHELL"; echo "$PATH"')" \
        || fail "ssh exited $?"
    want="$(id -u qssh-alice)
$(id -g qssh-alice)
$(id -G qssh-alice | tr ' ' '\n' | sort -n | tr '\n' ' ')
$home
$home qssh-alice qssh-alice /bin/bash
/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"
    [ "$got" = "$want" ] || fail "the session is not qssh-alice's: got '$got', want '$want'"
    grep -qw "$team" <<<"$(sed -n 3p <<<"$got")" || fail "qssh-team is not among the groups: $got"
}

case_account_login_shell() {
    account_mode || return 0
    local rc=0 out
    out="$(printf 'echo "zero=$0"\nexit 5\n' \
        | acct_ssh alice -tt -o LogLevel=ERROR qssh-alice@127.0.0.1 | tr -d '\r')" || rc=$?
    [ "$rc" -eq 5 ] || fail "the shell exited $rc, want 5"
    grep -qx 'zero=-bash' <<<"$out" || fail "not bash as a login shell: $out"
}

case_account_pty_owner() {
    account_mode || return 0
    local out
    out="$(acct_ssh alice -tt qssh-alice@127.0.0.1 'stat -c "%U %a" "$(tty)"' </dev/null | tr -d '\r')" \
        || fail "ssh exited $?"
    [ "$out" = "qssh-alice 600" ] || fail "the terminal is '$out', want 'qssh-alice 600'"
}

case_account_session_privileges() {
    account_mode || return 0
    local out field
    out="$(acct_ssh alice qssh-alice@127.0.0.1 'cat /proc/self/status' | tr '\t' ' ')" \
        || fail "ssh exited $?"
    grep -qx 'NoNewPrivs: 0' <<<"$out" || fail "NoNewPrivs is not 0: $(grep NoNewPrivs <<<"$out")"
    for field in CapInh CapPrm CapEff; do
        grep -qx "$field: 0000000000000000" <<<"$out" || fail "$field is not empty: $(grep "$field" <<<"$out")"
    done
}

case_account_audit_records() {
    account_mode || return 0
    local fp uid event marker="audit-$RANDOM"
    fp="$(ssh-keygen -lf "$WORK/acct_alice.pub" | awk '{print $2}')"
    uid="$(id -u qssh-alice)"
    # shellcheck disable=SC2029 # $marker is meant to expand here
    acct_ssh alice qssh-alice@127.0.0.1 "echo $marker" >/dev/null || fail "ssh exited $?"
    log_has server.started '"identity_mode":"account"' \
        || fail "server.started lacks identity_mode account"
    for event in exec.started exec.finished; do
        wait_for 5 log_has "$event" "\"command\":\"echo $marker\"" '"account":"qssh-alice"' \
            "\"authenticated_identity\":\"$fp\"" "\"executing_uid\":$uid," \
            || fail "no $event with the account, the key's fingerprint and UID $uid"
    done
}

case_account_exit_status() {
    account_mode || return 0
    local rc=0 v
    acct_ssh alice qssh-alice@127.0.0.1 'exit 3' || rc=$?
    [ "$rc" -eq 3 ] || fail "exit 3 reported $rc"
    rc=0
    v="$(acct_ssh alice -v qssh-alice@127.0.0.1 'kill -TERM $$' 2>&1)" || rc=$?
    [ "$rc" -eq 255 ] || fail "ssh exited $rc, want 255"
    grep -q "rtype exit-signal" <<<"$v" || fail "no exit-signal reached the client"
}

case_account_client_gone_kills() {
    account_mode || return 0
    local n=$((80000 + RANDOM)) pid
    # shellcheck disable=SC2029 # $n is meant to expand here, on the client
    acct_ssh alice qssh-alice@127.0.0.1 "sleep $n & sleep $n" >/dev/null 2>&1 &
    pid=$!
    disown "$pid"
    wait_for 10 sleeps_running "$n" 2 || { kill "$pid" 2>/dev/null; fail "the command never started"; }
    [ "$(pgrep -u qssh-alice -fx "sleep $n" | wc -l | tr -d ' ')" -eq 2 ] \
        || { kill "$pid" 2>/dev/null; fail "the command does not run as qssh-alice"; }
    kill -KILL "$pid"
    wait_for 10 sleeps_running "$n" 0 || { pkill -fx "sleep $n" || true; fail "the command outlived its client"; }
}

case_account_sftp_ownership() {
    account_mode || return 0
    local d=$CASE_DIR home
    home="$(getent passwd qssh-alice | cut -d: -f6)"
    head -c 100000 /dev/urandom >"$d/payload"
    printf 'put "%s" "%s/sftp-owned"\n' "$d/payload" "$home" >"$d/batch"
    sftp -b "$d/batch" -i "$WORK/acct_alice" -P "$ACCT_PORT" "${COMMON[@]}" qssh-alice@127.0.0.1 >/dev/null \
        || fail "batch exited $?"
    cmp -s "$d/payload" "$home/sftp-owned" || fail "uploaded bytes differ"
    [ "$(stat -c '%U %G' "$home/sftp-owned")" = "qssh-alice $(id -gn qssh-alice)" ] \
        || fail "the file belongs to $(stat -c '%U %G' "$home/sftp-owned")"
}

case_account_nologin() {
    account_mode || return 0
    local rc=0 out
    out="$(acct_ssh nologin qssh-nologin@127.0.0.1 'echo ran' 2>&1)" || rc=$?
    [ "$rc" -eq 1 ] || fail "exec exited $rc, want nologin's 1: $out"
    grep -qF "This account is currently not available." <<<"$out" || fail "nologin did not answer: $out"
    ! grep -qx ran <<<"$out" || fail "the command ran"
    printf 'ls /\n' >"$CASE_DIR/batch"
    sftp -b "$CASE_DIR/batch" -i "$WORK/acct_nologin" -P "$ACCT_PORT" "${COMMON[@]}" qssh-nologin@127.0.0.1 \
        >/dev/null || fail "the sftp batch exited $?"
}

case_account_unlisted_refused() {
    account_mode || return 0
    local user out
    ! getent passwd qssh-nobody >/dev/null || fail "qssh-nobody exists"
    for user in root qssh-unlisted qssh-nobody; do
        if out="$(acct_ssh alice -v "$user@127.0.0.1" true 2>&1)"; then
            fail "$user logged in"
        fi
        offered_and_denied "$WORK/acct_alice" "$out"
    done
}

case_account_key_bound_to_account() {
    account_mode || return 0
    local out
    [ "$(acct_ssh deploy qssh-deploy@127.0.0.1 'id -un')" = qssh-deploy ] \
        || fail "qssh-deploy's own key did not log in"
    if out="$(acct_ssh alice -v qssh-deploy@127.0.0.1 true 2>&1)"; then
        fail "qssh-alice's key logged in to qssh-deploy"
    fi
    offered_and_denied "$WORK/acct_alice" "$out"
}

case_account_certificate_principal() {
    account_mode || return 0
    local out
    sign_cert alice "$WORK/ca" qssh-alice -5m:+5m
    out="$(ssh -i "$WORK/certkey" -p "$ACCT_PORT" "${COMMON[@]}" \
        -o CertificateFile="$CASE_DIR/alice-cert.pub" qssh-alice@127.0.0.1 'id -un')" \
        || fail "ssh exited $?"
    [ "$out" = qssh-alice ] || fail "the session ran as '$out'"
    if out="$(ssh -v -i "$WORK/certkey" -p "$ACCT_PORT" "${COMMON[@]}" \
        -o CertificateFile="$CASE_DIR/alice-cert.pub" qssh-deploy@127.0.0.1 true 2>&1)"; then
        fail "a qssh-alice certificate logged in to qssh-deploy"
    fi
    grep -qF "Offering public key: $CASE_DIR/alice-cert.pub ED25519-CERT" <<<"$out" \
        || fail "the client never offered the certificate: $out"
    grep -qF "Permission denied (publickey)." <<<"$out" || fail "refused for another reason: $out"
}

# ADR-0074 §2, §4: each session joins a session keyring of its own. Where
# a session can use keyrings, a key that qssh-alice links into her @s is
# neither found nor read by a session of qssh-bob. Where keyctl is
# blocked as a whole, as by a container's default seccomp profile, the
# session runs on without one, and keyctl is blocked inside it too.
case_account_own_keyring() {
    account_mode || return 0
    local nrs probe=/etc/quantumssh-interop/keyring_probe.pl serial holder search read_bob n
    case "$(uname -m)" in
        x86_64) nrs="248 250" ;;
        aarch64) nrs="217 219" ;;
        *) fail "no keyring system call numbers for $(uname -m)" ;;
    esac
    install -m 0644 "$HERE/../systemd/keyring_probe.pl" "$probe"
    # shellcheck disable=SC2029 # the probe's arguments expand here
    # The probe's own errors come back on stdout, apart from the client's.
    acct_ssh alice qssh-alice@127.0.0.1 "perl $probe $nrs add 2>&1" \
        >"$CASE_DIR/alice" 2>"$CASE_DIR/alice.err" &
    holder=$!
    disown "$holder"
    wait_for 10 test -s "$CASE_DIR/alice" || { kill "$holder" 2>/dev/null; fail "the probe printed nothing"; }
    serial="$(head -1 "$CASE_DIR/alice")"
    # shellcheck disable=SC2029
    search="$(acct_ssh deploy qssh-deploy@127.0.0.1 "perl $probe $nrs search")"
    case "$serial" in
        'add_key: Operation not permitted')
            kill "$holder" 2>/dev/null || true
            [ "$search" = "errno 1" ] || fail "keyctl is blocked for one session but gave '$search' in another"
            ;;
        '' | *[!0-9]*)
            kill "$holder" 2>/dev/null || true
            fail "the probe could not add a key: $(cat "$CASE_DIR/alice")"
            ;;
        *)
            # shellcheck disable=SC2029
            read_bob="$(acct_ssh deploy qssh-deploy@127.0.0.1 "perl $probe $nrs read $serial")"
            kill "$holder" 2>/dev/null || true
            [ "$search" = "errno 126" ] || fail "another account's search found the key: '$search'"
            [ "$read_bob" = "errno 13" ] || fail "another account read the key: '$read_bob'"
            ;;
    esac
    n=0
    while kill -0 "$holder" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
}

