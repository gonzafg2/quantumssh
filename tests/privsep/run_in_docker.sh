#!/usr/bin/env bash
# Runs the session-helper check (ADR-0065 §6) and the check of account
# mode's processes (ADR-0066) as root in disposable
# containers of the gate image (ADR-0059), from the repository root, with
# the Linux release binary at target/release/quantumssh.
#
# The image is the one the systemd gate pins, read from
# tests/systemd/run_in_docker.sh, so a gate-image bump has one place to
# change for both.
set -euo pipefail

image="$(sed -n 's/^image=//p' tests/systemd/run_in_docker.sh)"
[ -n "$image" ] || { echo "PRIVSEP FAIL: no image pin in tests/systemd/run_in_docker.sh" >&2; exit 1; }

# One disposable container per script: each creates its own accounts.
for script in run_session_helper.sh run_account_mode.sh; do
    docker run --rm -v "$PWD":/src:ro -e QUANTUMSSH_PRIVSEP_CONTAINER=1 \
        "$image" bash "/src/tests/privsep/$script"
done
