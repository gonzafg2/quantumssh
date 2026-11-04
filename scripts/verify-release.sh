#!/usr/bin/env bash
# The maintainer's check of a release draft before signing it, and again
# before publishing it (ADR-0054 §4). It stops at the first failure.
#
#   scripts/verify-release.sh vX.Y.Z <empty dir>
#     1. The tag is annotated, the pinned signature check passes on it
#        with the pin set of origin/main, and its commit is on origin/main.
#     2. The draft holds exactly five assets: the three tarballs, the SBOM
#        and the unsigned SHA256SUMS. They are downloaded into <dir>.
#     3. Each tarball and the SBOM passes `gh attestation verify` with the
#        repository, signer-workflow, source-ref and hosted-runner pins,
#        and its attested commit is the tag's.
#     4. SHA256SUMS recomputed from those files is byte-identical to the
#        draft's copy.
#     5. The four gate records of the tag's release run name exactly
#        those tarball digests.
#     6. It prints `ready to sign` and the commands that follow: sign
#        SHA256SUMS, run the pinned check on the new signature
#        (scripts/verify-download.sh), upload it, then the second form.
#
#   scripts/verify-release.sh --publish vX.Y.Z <dir>
#     Run once SHA256SUMS.asc is uploaded, immediately before publishing.
#     It repeats step 1, so a tag moved since the check fails. It checks
#     the local signature with scripts/verify-download.sh and the pin set
#     of origin/main. It then downloads the draft again,
#     requires exactly six assets, byte-identical to the verified files,
#     repeats the checksum and attestation checks on them, and requires
#     immutable releases to be on. Last, it prints the
#     publish command.
#
# A rehearsal-<name> tag (ADR-0053 §4) runs the first form with no tag
# signature to check. It ends with `rehearsal verified`, never
# `ready to sign`. Run from the repository root, with gh authenticated.
set -euo pipefail

REPO=gonzafg2/quantumssh
WORKFLOW=.github/workflows/release.yml
TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin"
KEY=9A8DFF06AFD25B24

fail() { echo "VERIFY-RELEASE FAIL: $1" >&2; exit 1; }
step() { echo "== $*"; }
usage() { echo "usage: $0 [--publish] <vX.Y.Z | rehearsal-name> <dir>" >&2; exit 2; }

publish=0
if [ "${1:-}" = --publish ]; then publish=1; shift; fi
[ "$#" -eq 2 ] || usage
tag="$1" dir="$2"
rehearsal=0
case "$tag" in
    v[0-9]*.[0-9]*.[0-9]*) [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "$tag is not vX.Y.Z" ;;
    rehearsal-*) rehearsal=1; [ "$publish" -eq 0 ] || fail "a rehearsal is never published" ;;
    *) usage ;;
esac
for tool in gh git gpg jq; do
    command -v "$tool" >/dev/null || fail "$tool is not installed"
done
if command -v sha256sum >/dev/null; then sha256() { sha256sum -- "$@"; }; else sha256() { shasum -a 256 -- "$@"; }; fi
here="$(cd "$(dirname "$0")" && pwd)"

git fetch --quiet origin main
git fetch --quiet --force origin "refs/tags/$tag:refs/tags/$tag"
commit="$(git rev-parse "refs/tags/$tag^{commit}")"
version="$(git show "$commit:crates/quantumssh/Cargo.toml" | sed -n 's/^version = "\([^"]*\)"$/\1/p' | head -1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "no version in crates/quantumssh/Cargo.toml at $commit"
[ "$rehearsal" -eq 1 ] || [ "v$version" = "$tag" ] || fail "$tag tags a commit whose version is $version"

expected="$(for t in $TARGETS; do echo "quantumssh-$version-$t.tar.gz"; done; echo "quantumssh-$version.cdx.json")"
assets() { # assets <extra name>... -> the sorted expected names
    { echo "$expected"; for n in "$@"; do echo "$n"; done; } | LC_ALL=C sort
}
download() { # download <empty dir> <expected names>: the draft's assets, exactly those
    [ ! -e "$1" ] || [ -z "$(ls -A "$1")" ] || fail "$1 is not empty"
    mkdir -p "$1"
    [ "$(gh release view "$tag" -R "$REPO" --json isDraft -q .isDraft)" = true ] || fail "$tag is not a draft release"
    have="$(gh release view "$tag" -R "$REPO" --json assets -q '.assets[].name' | LC_ALL=C sort)"
    [ "$have" = "$2" ] || fail "the draft's assets are not exactly the expected ones:
$(diff <(echo "$2") <(echo "$have") || true)"
    gh release download "$tag" -R "$REPO" -D "$1"
    # A second API call: an asset added in between would land here too.
    got="$(find "$1" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort)"
    [ "$got" = "$2" ] || fail "the downloaded files are not exactly the expected ones:
$(diff <(echo "$2") <(echo "$got") || true)"
}

# The pin set and keys of origin/main, never the local tree's.
keys="$(mktemp -d)"
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$keys" "$GNUPGHOME"' EXIT
git archive origin/main keys | tar -x -C "$keys"
pins="$keys/keys/release-keys.txt"

check_tag() { # step 1; --publish runs it again
    [ "$(git cat-file -t "refs/tags/$tag")" = tag ] || fail "$tag is not an annotated tag"
    if [ "$rehearsal" -eq 1 ]; then
        echo "rehearsal tag: no signature to check"
    else
        gpg --batch --quiet --import "$keys/keys/security.asc" 2>/dev/null
        status="$(git verify-tag --raw "$tag" 2>&1 || true)"
        "$BASH" "$here/release/pinned-signature-check.sh" "$pins" <<<"$status"
    fi
    git merge-base --is-ancestor "$commit" origin/main || fail "$tag ($commit) is not on origin/main"
    echo "$tag -> $commit, version $version, on origin/main"
}

check_attestations() { # check_attestations <dir>: step 3; --publish runs it again
    for f in $expected; do
        out="$(gh attestation verify "$1/$f" -R "$REPO" \
            --signer-workflow "$REPO/$WORKFLOW" --source-ref "refs/tags/$tag" \
            --deny-self-hosted-runners --format json)" || fail "$f: attestation verification failed"
        attested="$(jq -r '.[].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[]?.digest.gitCommit // empty' <<<"$out" | sort -u)"
        [ "$attested" = "$commit" ] || fail "$f: attested commit '$attested', not $commit"
        echo "ok: $f"
    done
}

check_sums() { # check_sums <dir>: step 4; --publish runs it again
    # shellcheck disable=SC2086 # $expected is a list of file names without spaces
    (cd "$1" && sha256 $expected | LC_ALL=C sort -k2) > "$keys/SHA256SUMS.recomputed"
    cmp -s "$keys/SHA256SUMS.recomputed" "$1/SHA256SUMS" || {
        diff "$keys/SHA256SUMS.recomputed" "$1/SHA256SUMS" >&2 || true
        fail "SHA256SUMS recomputed from $1 differs from the draft's"
    }
    echo "ok"
}

if [ "$publish" -eq 1 ]; then
    step "the tag, again: it must not have moved since the check"
    check_tag
    step "the local signature, with the pin set of origin/main"
    QUANTUMSSH_KEYS="$keys/keys" "$BASH" "$here/verify-download.sh" "$tag" "$dir"
    step "immutable releases"
    [ "$(gh api "repos/$REPO/immutable-releases" -q .enabled)" = true ] \
        || fail "immutable releases are off; turn them on before publishing (ADR-0054 §5)"
    step "the draft holds exactly six assets, byte-identical to the verified files"
    # Under $keys, so the EXIT trap removes it on any failure.
    again="$keys/before-publish"
    download "$again" "$(assets SHA256SUMS SHA256SUMS.asc)"
    for f in $(assets SHA256SUMS SHA256SUMS.asc); do
        cmp -s "$dir/$f" "$again/$f" || fail "$f on the draft differs from the verified $dir/$f"
    done
    step "the downloads, again: they must match the signed SHA256SUMS"
    check_sums "$again"
    step "the attestations, again: they must name the tag's commit now"
    check_attestations "$again"
    echo
    echo "ready to publish $tag:"
    echo "  gh release edit $tag -R $REPO --draft=false"
    exit 0
fi

step "1. the tag: annotated, signed by the current release key, on main"
check_tag

step "2. the draft holds exactly five assets"
download "$dir" "$(assets SHA256SUMS)"
ls -1 "$dir"

step "3. attestations"
check_attestations "$dir"

step "4. SHA256SUMS recomputed byte for byte"
check_sums "$dir"

step "5. the gates' digest records"
runs="$(gh run list -R "$REPO" --workflow release.yml --branch "$tag" --json databaseId,headSha,conclusion \
    -q "[.[] | select(.headSha == \"$commit\" and .conclusion == \"success\")] | .[].databaseId")"
if [ -z "$runs" ] || [ "$(wc -l <<<"$runs")" -ne 1 ]; then
    fail "expected one successful release run of $tag at $commit, found: ${runs:-none}"
fi
records="$keys/gates"
gh run download "$runs" -R "$REPO" -p 'gate-digests-*' -D "$records"
[ "$(find "$records" -type f -name gate-digests.txt | wc -l)" -eq 4 ] || fail "expected four gate records in run $runs"
find "$records" -type f -name gate-digests.txt -print0 | xargs -0 cat | LC_ALL=C sort -u > "$keys/gate-lines"
grep '\.tar\.gz$' "$dir/SHA256SUMS" | LC_ALL=C sort -u > "$keys/sum-lines"
cmp -s "$keys/gate-lines" "$keys/sum-lines" || {
    diff "$keys/sum-lines" "$keys/gate-lines" >&2 || true
    fail "the gates' records are not exactly SHA256SUMS's tarball lines"
}
echo "ok: run $runs, every tarball line equals a gate record"

echo
if [ "$rehearsal" -eq 1 ]; then
    echo "rehearsal verified: $tag"
    exit 0
fi
cat <<EOF
ready to sign $tag. Then, from the repository root:
  gpg --armor --detach-sign -u $KEY $dir/SHA256SUMS
  scripts/verify-download.sh $tag $dir
  gh release upload $tag -R $REPO $dir/SHA256SUMS.asc
  scripts/verify-release.sh --publish $tag $dir
EOF
