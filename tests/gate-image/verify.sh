#!/usr/bin/env bash
# verify.sh: checks the gate image before anything runs it (ADR-0059 §4).
#
# 1. Every file that names the image pins one and the same index digest.
# 2. That digest has a provenance attestation made by gate-image.yml on
#    refs/heads/main, on a GitHub-hosted runner.
#
# Run it from the repository root on the runner host, never inside the
# image: steps inside a container could be made to lie by the image they
# would be checking. The attestation API is public for this repository, so a
# token with contents: read is enough (GH_TOKEN). Prints the verified
# reference.
set -euo pipefail

image=ghcr.io/gonzafg2/quantumssh-gate
files=(.github/workflows/interop.yml tests/systemd/run_in_docker.sh)

pinned="$(grep -ohE "$image@sha256:[0-9a-f]{64}" "${files[@]}" | LC_ALL=C sort -u)"
if [ -z "$pinned" ] || [ "$(wc -l <<<"$pinned")" -ne 1 ]; then
    echo "::error::expected one pinned $image digest across ${files[*]}, found:" >&2
    echo "${pinned:-none}" >&2
    exit 1
fi
for f in "${files[@]}"; do
    grep -qF "$pinned" "$f" || { echo "::error::$f does not pin $pinned" >&2; exit 1; }
done

gh attestation verify "oci://$pinned" -R gonzafg2/quantumssh \
    --signer-workflow gonzafg2/quantumssh/.github/workflows/gate-image.yml \
    --source-ref refs/heads/main --deny-self-hosted-runners > /dev/null
echo "verified: $pinned"
