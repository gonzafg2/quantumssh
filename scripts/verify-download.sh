#!/usr/bin/env bash
# Checks the signature on a release's SHA256SUMS, as ADR-0054 §6 step 2
# and §7 require. Run it from a checkout of this repository's main, on the
# directory that holds the downloaded SHA256SUMS and SHA256SUMS.asc:
#
#   scripts/verify-download.sh vX.Y.Z [<dir>]
#
#   1. Every line of SHA256SUMS names an asset of version X.Y.Z.
#   2. Every key the pin set keys/release-keys.txt lists is imported into
#      a throwaway GnuPG home: keys/security.asc for the current key and
#      keys/retired/<fingerprint>.asc for each retired or revoked one. A
#      listed key missing after the import fails, and so does a revoked
#      key whose file does not revoke it: GnuPG must report REVKEYSIG,
#      never NO_PUBKEY.
#   3. scripts/release/pinned-signature-check.sh classifies
#      `gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS`.
#   4. A signature by a retired key also needs the release's immutable
#      record, read with gh:
#        - GitHub's timestamp in `gh release verify vX.Y.Z` falls inside
#          the key's window in the pin set;
#        - `gh release verify-asset` passes for SHA256SUMS and for
#          SHA256SUMS.asc, so they are the files the release recorded.
#
# Then `sha256sum --ignore-missing -c SHA256SUMS` checks the downloads
# (ADR-0054 §6 step 3). QUANTUMSSH_KEYS names another keys/ directory;
# the tests use one.
set -euo pipefail

REPO=gonzafg2/quantumssh
fail() { echo "VERIFY FAIL: $1" >&2; exit 1; }
{ [ "$#" -ge 1 ] && [ "$#" -le 2 ]; } || { echo "usage: $0 vX.Y.Z [<dir>]" >&2; exit 2; }
tag="$1" dir="${2:-.}"
[[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || fail "$tag is not a vX.Y.Z tag"
version="${BASH_REMATCH[1]}"
command -v gpg >/dev/null || fail "gpg (GnuPG) is not installed"

here="$(cd "$(dirname "$0")" && pwd)"
keys="${QUANTUMSSH_KEYS:-$here/../keys}"
pins="$keys/release-keys.txt"
[ -f "$pins" ] || fail "no pin set at $pins"
for f in SHA256SUMS SHA256SUMS.asc; do
    [ -f "$dir/$f" ] || fail "no $dir/$f"
done

# 1. The signed file must be this version's, so an older release's
#    SHA256SUMS cannot stand in for it.
[ -s "$dir/SHA256SUMS" ] || fail "$dir/SHA256SUMS is empty"
v="${version//./\\.}"
foreign="$(grep -Ev "^[0-9a-f]{64}  quantumssh-$v(-[a-z0-9_]+(-[a-z0-9_]+)*\.tar\.gz|\.cdx\.json)\$" "$dir/SHA256SUMS" || true)"
[ -z "$foreign" ] || fail "SHA256SUMS has a line that is not a $tag asset: $(head -1 <<<"$foreign")"

# 2. The whole pin set, so that every role reaches the check below.
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
listed="$(grep -Ev '^#|^[[:space:]]*$' "$pins" || true)"
[ -f "$keys/security.asc" ] || fail "no $keys/security.asc"
gpg --batch --quiet --import "$keys/security.asc" 2>/dev/null
while read -r fpr role _; do
    case "$role" in
        retired|revoked)
            file="$keys/retired/$fpr.asc"
            [ -f "$file" ] || fail "no $file for the $role key $fpr"
            gpg --batch --quiet --import "$file" 2>/dev/null ;;
    esac
done <<<"$listed"
keyring="$(gpg --batch --with-colons --fixed-list-mode --list-keys 2>/dev/null)"
while read -r fpr role _; do
    # A pub record's validity is its field 2 ("r" is revoked); the fpr
    # record right after it holds the primary fingerprint.
    validity="$(awk -F: -v f="$fpr" '
        $1 == "fpr" && prev == "pub" && $10 == f { print v }
        $1 == "pub" { v = $2 }
        { prev = $1 }' <<<"$keyring")"
    [ -n "$validity" ] || fail "the $role key $fpr is not in its key file"
    if [ "$role" = revoked ]; then
        [ "$validity" = r ] || fail "the revoked key $fpr's file does not carry its revocation"
    else
        [ "$validity" != r ] || fail "the $role key $fpr is revoked in its key file"
    fi
done <<<"$listed"
echo "current release key: $(awk '$2 == "current" { print $1 }' <<<"$listed")"

# 3. The pinned signature check.
status="$(gpg --batch --status-fd 1 --verify "$dir/SHA256SUMS.asc" "$dir/SHA256SUMS" 2>/dev/null || true)"
rc=0
verdict="$("$BASH" "$here/release/pinned-signature-check.sh" "$pins" <<<"$status")" || rc=$?
case "$rc" in
    0) echo "$verdict"; echo "$tag: SHA256SUMS is signed by the current release key"; exit 0 ;;
    3) ;;
    *) exit 1 ;;
esac

# 4. A retired key: the release's own record decides, never a date the
#    signer chose.
read -r _ fpr first_use end_date <<<"$verdict"
for tool in gh jq; do
    command -v "$tool" >/dev/null || fail "a signature by the retired key $fpr needs $tool, to read $tag's release record"
done
record="$(gh release verify "$tag" -R "$REPO" --format json)" \
    || fail "$tag has no verifiable immutable-release record"
jq -e --arg r "$REPO" --arg t "$tag" \
    '[if type == "array" then .[] else . end]
     | length > 0 and all(.verificationResult.statement.predicate | .repository == $r and .tag == $t)' \
    <<<"$record" >/dev/null || fail "the release record is not for $REPO $tag"
stamps="$(jq -r '[if type == "array" then .[] else . end][].verificationResult.verifiedTimestamps[]?.timestamp' <<<"$record")"
[ -n "$stamps" ] || fail "$tag's release record carries no verified timestamp"
while read -r stamp; do
    day="${stamp%%T*}"
    [[ "$day" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "unreadable release timestamp $stamp"
    { [[ ! "$day" < "$first_use" ]] && [[ ! "$day" > "$end_date" ]]; } \
        || fail "$tag was published on $day, outside the retired key $fpr's window, $first_use to $end_date"
done <<<"$stamps"
for f in SHA256SUMS SHA256SUMS.asc; do
    gh release verify-asset "$tag" "$dir/$f" -R "$REPO" >/dev/null \
        || fail "$f is not the asset $tag's release recorded"
done
echo "$tag: SHA256SUMS is signed by the retired key $fpr, inside its window, and both files are the release's recorded assets"
