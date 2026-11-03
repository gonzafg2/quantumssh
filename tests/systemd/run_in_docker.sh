#!/usr/bin/env bash
# Runs run_reference_unit.sh in the disposable systemd container
# (ADR-0043 §7), from the repository root. CI's pull-request job and the
# release workflow both drive it from here.
#
# Usage: tests/systemd/run_in_docker.sh [<extracted release tarball directory>]
#
# With no argument the check installs the checkout's release build. Given
# the directory of an extracted release tarball, it installs that
# tarball's binary and unit instead (ADR-0055 §2).
set -euo pipefail

mounts=(-v "$PWD":/src:ro)
env=()
if [ "$#" -eq 1 ]; then
    artifact="$(cd "$1" && pwd)"
    mounts+=(-v "$artifact":/artifact:ro)
    env=(-e SRC=/artifact -e QUANTUMSSH_BIN=/artifact/quantumssh)
fi

docker build -t quantumssh-systemd tests/systemd
docker run -d --name quantumssh-systemd --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw "${mounts[@]}" quantumssh-systemd
for _ in $(seq 1 150); do
    state="$(docker exec quantumssh-systemd systemctl is-system-running 2>/dev/null || true)"
    case "$state" in running|degraded) break ;; esac
    sleep 0.2
done
docker exec "${env[@]}" quantumssh-systemd bash /src/tests/systemd/run_reference_unit.sh
