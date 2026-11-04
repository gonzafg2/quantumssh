#!/usr/bin/env bash
# The pinned signature check of ADR-0054 §7, for a signature by the
# current release key. It reads GnuPG status lines on stdin, from
# `gpg --status-fd 1 --verify` or `git verify-tag --raw … 2>&1`, and
# passes only when:
#   - a VALIDSIG line names the pin set's `current` fingerprint, and every
#     VALIDSIG line names it;
#   - no REVKEYSIG, KEYREVOKED, BADSIG, EXPKEYSIG or EXPSIG line appears.
# No VALIDSIG line at all fails, so empty input never passes. A bare
# `gpg --verify` exit status is not used: it is 0 for a good signature by
# a revoked or expired key.
#
# A retired key is refused here. Accepting one also takes the release
# window and asset-digest checks of ADR-0054 §7, which need the published
# release.
#
# Usage: pinned-signature-check.sh <release-keys.txt> < status-lines
set -euo pipefail

fail() { echo "SIGNATURE CHECK FAIL: $1" >&2; exit 1; }
[ "$#" -eq 1 ] || { echo "usage: $0 <release-keys.txt> < status-lines" >&2; exit 2; }
status="$(cat)"

current="$(awk '!/^#/ && NF && $2 == "current" { print $1 }' "$1")"
[ -n "$current" ] && [ "$(wc -l <<<"$current")" -eq 1 ] \
    || fail "the pin set $1 must name exactly one current key"

refused="$(grep -E '^\[GNUPG:\] (REVKEYSIG|KEYREVOKED|BADSIG|EXPKEYSIG|EXPSIG)( |$)' <<<"$status" || true)"
[ -z "$refused" ] || fail "$refused"

signers="$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 }' <<<"$status")"
[ -n "$signers" ] || fail "no VALIDSIG line"
while read -r fpr; do
    [ "$fpr" = "$current" ] || fail "signed by $fpr, not the current release key $current"
done <<<"$signers"
echo "good signature by the current release key $current"
