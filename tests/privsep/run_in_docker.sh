#!/usr/bin/env bash
# Runs the session-helper check (ADR-0065 §6) as root in a disposable
# container of the gate image (ADR-0059), from the repository root, with
# the Linux release binary at target/release/quantumssh.
#
# The image is the one the systemd gate pins, read from
# tests/systemd/run_in_docker.sh, so a gate-image bump has one place to
# change for both.
set -euo pipefail

image="$(sed -n 's/^image=//p' tests/systemd/run_in_docker.sh)"
[ -n "$image" ] || { echo "PRIVSEP FAIL: no image pin in tests/systemd/run_in_docker.sh" >&2; exit 1; }

docker run --rm -v "$PWD":/src:ro -e QUANTUMSSH_PRIVSEP_CONTAINER=1 \
    "$image" bash /src/tests/privsep/run_session_helper.sh
