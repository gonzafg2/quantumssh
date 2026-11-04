#!/usr/bin/env bash
# Static-link check of a release binary (ADR-0053 §3, RFC-0017 §2). It
# fails closed: a dynamically linked Linux binary, or a macOS binary that
# links anything outside /usr/lib, stops the release.
#
# Usage: check-binary.sh <binary> <target> [<expected version>]
#
# It prints the version the binary reports for `--version`. Given an
# expected version (a v* tag, without the `v`), it fails unless the two
# are equal; a rehearsal-* tag passes none.
#
# Linux needs readelf and Docker: the binary runs inside the Alpine image
# pinned below, mounted read-only and with no network.
set -euo pipefail

# alpine:3.24.3, an OCI index covering linux/amd64 and linux/arm64/v8
# (checked 2026-11-03).
ALPINE=alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

fail() { echo "STATIC CHECK FAIL: $1" >&2; exit 1; }
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || { echo "usage: $0 <binary> <target> [<expected version>]" >&2; exit 2; }
bin="$1" target="$2" expected="${3:-}"
[ -f "$bin" ] || fail "$bin: no such file"

case "$target" in
    *-unknown-linux-musl)
        needed="$(readelf -d "$bin" | grep -F '(NEEDED)' || true)"
        [ -z "$needed" ] || fail "$bin links shared libraries: $needed"
        if readelf -l "$bin" | grep -qw INTERP; then
            fail "$bin has a PT_INTERP program header"
        fi
        dir="$(cd "$(dirname "$bin")" && pwd)"
        out="$(docker run --rm --network none -v "$dir:/check:ro" "$ALPINE" \
            "/check/$(basename "$bin")" --version)" \
            || fail "$bin --version failed in Alpine"
        ;;
    *-apple-darwin)
        outside="$(otool -L "$bin" | tail -n +2 | awk '{print $1}' | grep -v '^/usr/lib/' || true)"
        [ -z "$outside" ] || fail "$bin links libraries outside /usr/lib: $outside"
        out="$("$bin" --version)" || fail "$bin --version failed"
        ;;
    *) fail "no static-link check for target $target" ;;
esac

version="${out#quantumssh }"
[ "$out" = "quantumssh $version" ] && [ -n "$version" ] || fail "unexpected --version output '$out'"
if [ -n "$expected" ] && [ "$version" != "$expected" ]; then
    fail "the binary reports $version, the tag names $expected"
fi
echo "$version"
