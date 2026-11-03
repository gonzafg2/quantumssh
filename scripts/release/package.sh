#!/usr/bin/env bash
# Assembles a release tarball (RFC-0017 §3). quantumssh-<version>-<target>.tar.gz
# holds one directory of the same name with:
#   - the quantumssh binary;
#   - LICENSE, README.md and CHANGELOG.md;
#   - contrib/systemd/quantumssh.service;
#   - config.toml, the example of docs/deployment.md §4 with its
#     /etc/quantumssh paths.
#
# Usage, from the repository root: package.sh <binary> <version> <target> <out-dir>
# It prints the tarball's path.
set -euo pipefail

[ "$#" -eq 4 ] || { echo "usage: $0 <binary> <version> <target> <out-dir>" >&2; exit 2; }
bin="$1" version="$2" target="$3" out="$4"
name="quantumssh-$version-$target"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
root="$stage/$name"
install -d "$root/contrib/systemd"
install -m 0755 "$bin" "$root/quantumssh"
install -m 0644 LICENSE README.md CHANGELOG.md "$root/"
install -m 0644 contrib/systemd/quantumssh.service "$root/contrib/systemd/"

# The first TOML block of deployment.md §4 is the example configuration.
awk '/^## 4\./ { s = 1 } s && /^```toml$/ { c = 1; next } c && /^```$/ { exit } c' \
    docs/deployment.md > "$root/config.toml"
[ -s "$root/config.toml" ] || { echo "package: no TOML block in docs/deployment.md §4" >&2; exit 1; }
chmod 0644 "$root/config.toml"

mkdir -p "$out"
# COPYFILE_DISABLE: macOS tar would otherwise add AppleDouble (._*) entries.
COPYFILE_DISABLE=1 tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
echo "$out/$name.tar.gz"
