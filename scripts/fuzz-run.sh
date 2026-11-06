#!/usr/bin/env bash
# Fuzzes one target for a time budget (ADR-0060 §5, §7, §8), from its
# corpus, its seeds and its regressions. libFuzzer's output and the
# program's stderr go to a file, never to the job log. On a finding, the
# output and fuzz/artifacts/<target>/ are encrypted to the key that
# keys/release-keys.txt lists as current, the key SECURITY.md takes
# private reports on, after checking keys/security.asc against that pin.
#
# The target must already be built (scripts/fuzz-prepare.sh), so a build
# failure shows in the public log rather than in the encrypted report.
#
# Usage: scripts/fuzz-run.sh <target> <seconds> <corpus-dir> <report-dir>
#        (from the repository root)
# Exit:  0 no finding; 1 a finding, encrypted to
#        <report-dir>/fuzz-crash-<target>.tar.gz.gpg; 2 usage or setup error.
set -euo pipefail

usage() { echo "usage: $0 <target> <seconds> <corpus-dir> <report-dir>" >&2; exit 2; }
[ "$#" -eq 4 ] || usage
target=$1 seconds=$2 corpus=$3 report_dir=$4
[[ "$target" =~ ^[a-z_]+$ && "$seconds" =~ ^[0-9]+$ ]] || usage

mkdir -p "$corpus" "$report_dir"
dirs=("$corpus" "fuzz/seeds/$target")
if [ -d "fuzz/regressions/$target" ]; then
    dirs+=("fuzz/regressions/$target")
fi

output="$(mktemp)"
if cargo fuzz run --sanitizer none "$target" "${dirs[@]}" -- \
    -max_total_time="$seconds" -timeout=5 >"$output" 2>&1; then
    echo "$target: no finding in ${seconds}s"
    exit 0
fi

echo "$target: a finding; its report is encrypted to the current security key"
fingerprint="$(awk '$2 == "current" { print $1 }' keys/release-keys.txt)"
if ! [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]]; then
    echo "keys/release-keys.txt names no current key" >&2
    exit 2
fi
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
gpg --batch --quiet --import keys/security.asc
if ! gpg --batch --with-colons --fingerprint "$fingerprint" | grep -q "^fpr:::::::::$fingerprint:"; then
    echo "keys/security.asc is not the pinned current key $fingerprint" >&2
    exit 2
fi
mkdir -p "fuzz/artifacts/$target"
cp "$output" "fuzz/artifacts/$target.output"
tar -czf - -C fuzz/artifacts "$target" "$target.output" |
    gpg --batch --yes --trust-model always --recipient "$fingerprint" \
        --encrypt --output "$report_dir/fuzz-crash-$target.tar.gz.gpg"
exit 1
