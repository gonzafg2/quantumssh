#!/usr/bin/env bash
# The pinned signature check of ADR-0054 §7. It reads GnuPG status lines
# on stdin, from `gpg --status-fd 1 --verify` or `git verify-tag --raw … 2>&1`,
# and classifies the one signer against the pin set <release-keys.txt>:
#   - a REVKEYSIG, KEYREVOKED or BADSIG line fails;
#   - no VALIDSIG line fails, so empty input never passes;
#   - VALIDSIG lines that name more than one fingerprint fail;
#   - otherwise the signer's role in the pin set decides:
#       current  passes (exit 0) unless an EXPKEYSIG or EXPSIG line appears;
#       retired  is valid only inside its window, which takes the published
#                release's record (ADR-0054 §7). The check prints
#                "retired <fingerprint> <first use> <end date>" and exits 3,
#                so a caller that wants exit 0 refuses it;
#       revoked, or absent from the pin set, fails.
# A bare `gpg --verify` exit status is not used: it is 0 for a good
# signature by a revoked or expired key.
#
# Usage: pinned-signature-check.sh <release-keys.txt> < status-lines
# Exit:  0 current key, 3 retired key (its window check is still due),
#        1 refused, 2 usage.
set -euo pipefail

fail() { echo "SIGNATURE CHECK FAIL: $1" >&2; exit 1; }
[ "$#" -eq 1 ] || { echo "usage: $0 <release-keys.txt> < status-lines" >&2; exit 2; }
status="$(cat)"

date_re='[0-9]{4}-[0-9]{2}-[0-9]{2}'
pins="$(grep -Ev '^#|^[[:space:]]*$' "$1" || true)"
malformed="$(grep -Ev "^[0-9A-F]{40} (current $date_re -|(retired|revoked) $date_re $date_re)\$" <<<"$pins" || true)"
[ -z "$malformed" ] || fail "malformed pin-set line in $1: $(head -1 <<<"$malformed")"
[ -z "$(cut -d' ' -f1 <<<"$pins" | sort | uniq -d)" ] || fail "the pin set $1 lists a fingerprint twice"
[ "$(grep -c ' current ' <<<"$pins")" -eq 1 ] || fail "the pin set $1 must name exactly one current key"

refused="$(grep -E '^\[GNUPG:\] (REVKEYSIG|KEYREVOKED|BADSIG)( |$)' <<<"$status" || true)"
[ -z "$refused" ] || fail "$refused"

signers="$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 }' <<<"$status" | sort -u)"
[ -n "$signers" ] || fail "no VALIDSIG line"
[ "$(wc -l <<<"$signers")" -eq 1 ] || fail "more than one signer: $(tr '\n' ' ' <<<"$signers")"

role="" first_use="" end_date=""
read -r _ role first_use end_date < <(awk -v f="$signers" '$1 == f' <<<"$pins") || true
case "$role" in
    current)
        expired="$(grep -E '^\[GNUPG:\] (EXPKEYSIG|EXPSIG)( |$)' <<<"$status" || true)"
        [ -z "$expired" ] || fail "$expired"
        echo "good signature by the current release key $signers" ;;
    retired)
        echo "retired $signers $first_use $end_date"
        echo "signed by the retired key $signers: valid only for a release published from $first_use to $end_date, on its recorded assets (ADR-0054 §7)" >&2
        exit 3 ;;
    revoked) fail "signed by the revoked key $signers" ;;
    *) fail "signed by $signers, which is not in the pin set $1" ;;
esac
