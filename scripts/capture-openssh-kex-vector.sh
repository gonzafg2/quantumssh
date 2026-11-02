#!/usr/bin/env bash
# Captures the mlkem768x25519-sha256 golden vector against an OpenSSH
# peer (#216; RFC-0003 §"Test vectors and KAT plan", threat model §5.2.4).
#
# Usage, from the repository root, with Docker:
#   scripts/capture-openssh-kex-vector.sh \
#       > crates/quantumssh-core/tests/vectors/mlkem768x25519-sha256-openssh.txt
#
# It runs in the interop gate's container. The image digest, the
# snapshot.debian.org timestamp, the openssh-client version and the
# `ssh -V` string come from .github/workflows/interop.yml, so an "OpenSSH
# version bump" (ADR-0048) moves the capture with the gate. Inside the
# container it builds the release binary from this tree and runs it under
# the fixed-RNG profile of scripts/fixed-getrandom.c. A stock ssh then
# completes one session through the relay of
# scripts/capture-openssh-kex-vector.py, which records the transcript.
# The vector goes to stdout and everything else to stderr.
set -euo pipefail

if [ "${1:-}" != "--in-container" ]; then
    cd "$(git rev-parse --show-toplevel)"
    workflow=.github/workflows/interop.yml
    pin() { sed -n "s/^ *$1: *'\{0,1\}\([^']*\)'\{0,1\}\$/\1/p" "$workflow"; }
    image="$(sed -n 's/^ *image: *\(debian@sha256:[0-9a-f]\{64\}\)$/\1/p' "$workflow")"
    for value in "$image" "$(pin SNAPSHOT)" "$(pin OPENSSH_CLIENT_VERSION)" "$(pin SSH_V_EXPECTED)"; do
        [ -n "$value" ] || { echo "capture: a pin is missing from $workflow" >&2; exit 1; }
    done
    exec docker run --rm \
        -e IMAGE="$image" \
        -e SNAPSHOT="$(pin SNAPSHOT)" \
        -e OPENSSH_CLIENT_VERSION="$(pin OPENSSH_CLIENT_VERSION)" \
        -e SSH_V_EXPECTED="$(pin SSH_V_EXPECTED)" \
        -e COMMIT="$(git describe --always --dirty --abbrev=40)" \
        -v "$PWD:/src:ro" \
        "$image" bash /src/scripts/capture-openssh-kex-vector.sh --in-container
fi

exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive

# The interop workflow's install step, with python3 for the relay.
grep -q "snapshot.debian.org/archive/debian/${SNAPSHOT}" /etc/apt/sources.list.d/debian.sources
cat > /etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: http://snapshot.debian.org/archive/debian/${SNAPSHOT}/
Suites: forky forky-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/
Suites: forky-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
EOF
printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "3";\n' > /etc/apt/apt.conf.d/99snapshot
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl gcc libc6-dev python3 "openssh-client=${OPENSSH_CLIENT_VERSION}" > /dev/null
[ "$(ssh -V 2>&1)" = "$SSH_V_EXPECTED" ] || { echo "capture: ssh -V is not the pinned client" >&2; exit 1; }

toolchain="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*$/\1/p' /src/rust-toolchain.toml)"
curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain "$toolchain"
. "$HOME/.cargo/env"
mkdir /work
tar --exclude=./target -C /src -cf - . | tar -C /work -xf -
cd /work
cargo build --release -q -p quantumssh
gcc -shared -fPIC -O2 -Wall -Werror -o /work/fixed-getrandom.so scripts/fixed-getrandom.c

# Under target/ for the StrictModes walk (ADR-0029), as in the gate.
mkdir -p target
chmod go-w target
WORK="$(mktemp -d "$PWD/target/capture.XXXXXX")"
ssh-keygen -t mldsa44-ed25519 -N "" -f "$WORK/hostkey" -q
ssh-keygen -t ed25519 -N "" -f "$WORK/clientkey" -q
cp "$WORK/clientkey.pub" "$WORK/authorized_keys"

FIXED_GETRANDOM_LOG="$WORK/draws.log" LD_PRELOAD=/work/fixed-getrandom.so \
    ./target/release/quantumssh \
        --listen 127.0.0.1:2222 \
        --host-key "$WORK/hostkey" \
        --authorized-keys "$WORK/authorized_keys" \
        --log-format human \
        > "$WORK/server.log" 2>&1 &
server=$!
for _ in $(seq 1 100); do
    (exec 4<>/dev/tcp/127.0.0.1/2222) 2>/dev/null && break
    sleep 0.1
done

status=0
ssh -v -i "$WORK/clientkey" \
    -o ProxyCommand="python3 /work/scripts/capture-openssh-kex-vector.py relay 127.0.0.1 2222 $WORK" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PasswordAuthentication=no \
    -o IdentitiesOnly=yes \
    tester@127.0.0.1 true 2> "$WORK/ssh.log" || status=$?
kill "$server"
if [ "$status" -ne 0 ] \
    || ! grep -q "kex: algorithm: mlkem768x25519-sha256" "$WORK/ssh.log" \
    || ! grep -q "kex: host key algorithm: ssh-mldsa44-ed25519" "$WORK/ssh.log"; then
    echo "capture: the session did not complete (ssh exited $status)" >&2
    cat "$WORK/ssh.log" "$WORK/server.log" >&2
    exit 1
fi

python3 scripts/capture-openssh-kex-vector.py extract "$WORK" "$COMMIT" "$(ssh -V 2>&1)" "$IMAGE" >&3
