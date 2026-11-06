#!/usr/bin/env bash
# Runs run_reference_unit.sh in a disposable container of the gate image
# (ADR-0043 §7, ADR-0059), with systemd as PID 1, from the repository
# root. CI's pull-request job and the release workflow both drive it from
# here, after tests/gate-image/verify.sh has checked the image.
#
# Usage: tests/systemd/run_in_docker.sh [<extracted release tarball directory>]
#
# With no argument the check installs the checkout's release build. Given
# the directory of an extracted release tarball, it installs that
# tarball's binary and unit instead (ADR-0055 §2).
set -euo pipefail

# The gate image's OCI index, pinned by digest; interop.yml pins the same
# one, and verify.sh fails unless the two match.
image=ghcr.io/gonzafg2/quantumssh-gate@sha256:88a4c0e68037c080d0430f88f63847b9fd7c5c1f369798a9c5233a0b6c903b1e

mounts=(-v "$PWD":/src:ro)
env=()
if [ "$#" -eq 1 ]; then
    artifact="$(cd "$1" && pwd)"
    mounts+=(-v "$artifact":/artifact:ro)
    env=(-e SRC=/artifact -e QUANTUMSSH_BIN=/artifact/quantumssh)
fi

docker run -d --name quantumssh-systemd --privileged --cgroupns=host \
    --stop-signal SIGRTMIN+3 -v /sys/fs/cgroup:/sys/fs/cgroup:rw "${mounts[@]}" \
    "$image" /sbin/init
for _ in $(seq 1 150); do
    state="$(docker exec quantumssh-systemd systemctl is-system-running 2>/dev/null || true)"
    case "$state" in running|degraded) break ;; esac
    sleep 0.2
done
docker exec "${env[@]}" quantumssh-systemd bash /src/tests/systemd/run_reference_unit.sh
