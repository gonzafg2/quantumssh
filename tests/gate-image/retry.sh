#!/usr/bin/env bash
# retry <command> [<arg>...]: runs the command up to eight times, two
# minutes apart, and fails if the last attempt fails. The gate image build
# bind-mounts it for its apt steps (tests/gate-image/Dockerfile): it is not
# part of either image. snapshot.debian.org can fail some files for minutes
# at a time, and apt keeps what it already verified, so each attempt fetches
# only what is still missing (ADR-0059). On #264, while the service was
# failing, the source fetch went from 134 failed fetches on its first
# attempt to 2 on its fifth, hence eight.
set -euo pipefail

for attempt in 1 2 3 4 5 6 7 8; do
    "$@" && exit 0
    if [ "$attempt" -eq 8 ]; then
        echo "retry: failed after $attempt attempts: $*" >&2
        exit 1
    fi
    echo "retry: attempt $attempt failed, retrying in 120 s: $*" >&2
    sleep 120
done
