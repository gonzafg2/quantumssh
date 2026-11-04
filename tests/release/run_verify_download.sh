#!/usr/bin/env bash
# Drives scripts/verify-download.sh and scripts/release/pinned-signature-check.sh
# (ADR-0054 §6–§7) through each role of the pin set, with GnuPG keys
# generated here and thrown away at the end. No private key is committed.
#
# The retired-key case reads the release record of this repository's
# v0.1.0, which was published before immutable releases and has none, so
# it needs gh, the network and a token (GH_TOKEN in CI). It checks that
# the window check fails closed; a passing retired-key case needs an
# immutable release signed by a retired key, which does not exist yet.
#
# Usage, from the repository root: tests/release/run_verify_download.sh
set -euo pipefail

root="$(pwd)"
verify="$root/scripts/verify-download.sh"
check="$root/scripts/release/pinned-signature-check.sh"
work="$(mktemp -d)"
export GNUPGHOME="$work/gen"
mkdir -m 0700 "$GNUPGHOME"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

failures=0
pass() { echo "ok: $1"; }
bad() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

gen() { # gen <name> [faked time] -> prints the primary fingerprint
    local name="$1" faked=() expiry=1y
    if [ "$#" -eq 2 ]; then faked=(--faked-system-time "$2"); expiry=1d; fi
    gpg --batch --quiet "${faked[@]}" --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "Test $name <$name@test.invalid>" ed25519 sign "$expiry" 2>/dev/null
    gpg --batch --with-colons --list-keys "$name@test.invalid" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }'
}

sign() { # sign <dir> [faked time] <fingerprint>...
    local dir="$1"; shift
    local faked=()
    case "${1:-}" in *T*!) faked=(--faked-system-time "$1"); shift ;; esac
    local users=()
    for f in "$@"; do users+=(-u "$f"); done
    gpg --batch --quiet "${faked[@]}" --pinentry-mode loopback --passphrase '' \
        "${users[@]}" --armor --detach-sign -o "$dir/SHA256SUMS.asc" "$dir/SHA256SUMS" 2>/dev/null
}

release_dir() { # release_dir <name> <version> -> a directory holding SHA256SUMS
    local dir="$work/$1"
    mkdir -p "$dir"
    for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin; do
        printf '%s\n' "$target" > "$dir/quantumssh-$2-$target.tar.gz"
    done
    printf '{}\n' > "$dir/quantumssh-$2.cdx.json"
    (cd "$dir" && shasum -a 256 -- *.tar.gz *.cdx.json | LC_ALL=C sort -k2) > "$dir/SHA256SUMS"
    echo "$dir"
}

keys_dir() { # keys_dir <name> <manifest lines> <current fpr> [<fpr> to retired/]... -> a keys/ directory
    local dir="$work/keys-$1"
    mkdir -p "$dir/retired"
    printf '%s\n' "$2" > "$dir/release-keys.txt"
    gpg --batch --armor --export "$3" > "$dir/security.asc"
    shift 3
    for f in "$@"; do gpg --batch --armor --export "$f" > "$dir/retired/$f.asc"; done
    echo "$dir"
}

expect() { # expect <case> <want exit> <want stderr substring> <keys> <tag> <dir>
    local name="$1" want="$2" needle="$3" rc=0
    QUANTUMSSH_KEYS="$4" bash "$verify" "$5" "$6" >"$work/out" 2>"$work/err" || rc=$?
    if [ "$rc" -ne "$want" ]; then
        bad "$name: exit $rc, wanted $want"; sed 's/^/    /' "$work/err" >&2; return
    fi
    if [ -n "$needle" ] && ! grep -qF -- "$needle" "$work/err"; then
        bad "$name: stderr lacks '$needle'"; sed 's/^/    /' "$work/err" >&2; return
    fi
    pass "$name"
}

# The retired-key case must fail on the missing record, not on gh itself.
command -v gh >/dev/null || { echo "gh is required" >&2; exit 1; }
gh release view v0.1.0 -R gonzafg2/quantumssh --json tagName >/dev/null \
    || { echo "gh cannot read gonzafg2/quantumssh's v0.1.0 (network or token)" >&2; exit 1; }

current="$(gen current)"
retired="$(gen retired)"
revoked="$(gen revoked)"
stranger="$(gen stranger)"
expired="$(gen expired '20200101T000000!')"

# The revoked key signs before its revocation is imported, as a key that
# signed releases and was later compromised would have.
d_revoked="$(release_dir revoked 0.1.0)"; sign "$d_revoked" "$revoked"
gpg --batch --armor --export "$revoked" > "$work/revoked-unrevoked.asc"
sed 's/^:-----/-----/' "$GNUPGHOME/openpgp-revocs.d/$revoked.rev" | gpg --batch --quiet --import 2>/dev/null

today="$(date -u +%Y-%m-%d)"
pins="$current current 2020-01-01 -
$retired retired 2020-01-01 $today
$revoked revoked 2020-01-01 $today"
k_all="$(keys_dir all "$pins" "$current" "$retired" "$revoked")"

d_good="$(release_dir good 0.1.0)"; sign "$d_good" "$current"
expect "current key, good signature" 0 "" "$k_all" v0.1.0 "$d_good"

d_tampered="$(release_dir tampered 0.1.0)"; sign "$d_tampered" "$current"
sed -i.orig '1s/^./0/' "$d_tampered/SHA256SUMS"
cmp -s "$d_tampered/SHA256SUMS" "$d_tampered/SHA256SUMS.orig" && sed -i.orig '1s/^./1/' "$d_tampered/SHA256SUMS"
expect "tampered SHA256SUMS" 1 "BADSIG" "$k_all" v0.1.0 "$d_tampered"

expect "SHA256SUMS of another version" 1 "is not a v0.2.0 asset" "$k_all" v0.2.0 "$d_good"

expect "revoked key" 1 "REVKEYSIG" "$k_all" v0.1.0 "$d_revoked"

d_retired="$(release_dir retired 0.1.0)"; sign "$d_retired" "$retired"
rc=0; bash "$check" "$k_all/release-keys.txt" \
    < <(gpg --batch --status-fd 1 --verify "$d_retired/SHA256SUMS.asc" "$d_retired/SHA256SUMS" 2>/dev/null) \
    >"$work/out" 2>/dev/null || rc=$?
if [ "$rc" -eq 3 ] && grep -qx "retired $retired 2020-01-01 $today" "$work/out"; then
    pass "pinned check: retired key exits 3 with its window"
else
    bad "pinned check: retired key gave exit $rc, '$(cat "$work/out")'"
fi
expect "retired key, release without an immutable record" 1 "has no verifiable immutable-release record" \
    "$k_all" v0.1.0 "$d_retired"

d_two="$(release_dir two 0.1.0)"; sign "$d_two" "$current" "$retired"
expect "two signers" 1 "more than one signer" "$k_all" v0.1.0 "$d_two"

# A stranger's key in security.asc reaches GnuPG but not the pin set.
k_stranger="$(keys_dir stranger "$pins" "$current" "$retired" "$revoked")"
gpg --batch --armor --export "$current" "$stranger" > "$k_stranger/security.asc"
d_stranger="$(release_dir stranger 0.1.0)"; sign "$d_stranger" "$stranger"
expect "signer outside the pin set" 1 "not in the pin set" "$k_stranger" v0.1.0 "$d_stranger"

d_unknown="$(release_dir unknown 0.1.0)"; sign "$d_unknown" "$stranger"
expect "signer missing from the keyring" 1 "no VALIDSIG line" "$k_all" v0.1.0 "$d_unknown"

k_expired="$(keys_dir expired "$expired current 2020-01-01 -" "$expired")"
d_expired="$(release_dir expired 0.1.0)"; sign "$d_expired" '20200101T000000!' "$expired"
expect "current key past its expiry" 1 "EXPKEYSIG" "$k_expired" v0.1.0 "$d_expired"

k_norev="$(keys_dir norev "$pins" "$current" "$retired")"
cp "$work/revoked-unrevoked.asc" "$k_norev/retired/$revoked.asc"
expect "revoked key file without its revocation" 1 "does not carry its revocation" "$k_norev" v0.1.0 "$d_good"

k_missing="$(keys_dir missing "$pins" "$current" "$retired")"
expect "retired key file missing" 1 "no $k_missing/retired/$revoked.asc" "$k_missing" v0.1.0 "$d_good"

k_twocurrent="$(keys_dir twocurrent "$current current 2020-01-01 -
$retired current 2020-01-01 -" "$current")"
gpg --batch --armor --export "$current" "$retired" > "$k_twocurrent/security.asc"
expect "two current keys in the pin set" 1 "exactly one current key" "$k_twocurrent" v0.1.0 "$d_good"

if [ "$failures" -ne 0 ]; then
    echo "$failures case(s) failed" >&2
    exit 1
fi
echo "all release signature cases pass"
