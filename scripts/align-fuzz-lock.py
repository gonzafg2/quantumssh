#!/usr/bin/env python3
"""Aligns fuzz/Cargo.lock to the root Cargo.lock (ADR-0060 §2).

fuzz/ is its own workspace with its own lockfile, so on its own it drifts
from the versions the binary ships with. Before every fuzz build, this
script moves each package the two lockfiles share to the root's version,
matching packages by name and semver-compatible version, with
`cargo update --precise`. It fails if a shared package still differs
afterwards. The committed fuzz/Cargo.lock then decides only the
fuzz-only packages.

Usage: python3 scripts/align-fuzz-lock.py   (from the repository root)
"""

import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
ROOT_LOCK = ROOT / "Cargo.lock"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
FUZZ_LOCK = ROOT / "fuzz/Cargo.lock"


def registry_versions(lock):
    """{name: [version, ...]} for the registry packages of a lockfile."""
    versions = {}
    for package in tomllib.loads(lock.read_text())["package"]:
        if "source" in package:
            versions.setdefault(package["name"], []).append(package["version"])
    return versions


def compatible(a, b):
    """Cargo's caret compatibility: same major, or same 0.minor."""
    a, b = a.split("."), b.split(".")
    return a[0] == b[0] and (a[0] != "0" or a[1] == b[1])


def drift():
    """(name, fuzz version, root version) for every shared package whose
    fuzz version is not the root's."""
    root, fuzz = registry_versions(ROOT_LOCK), registry_versions(FUZZ_LOCK)
    pairs = []
    for name in sorted(root.keys() & fuzz.keys()):
        for fuzz_version in fuzz[name]:
            for root_version in root[name]:
                if compatible(fuzz_version, root_version) and fuzz_version != root_version:
                    pairs.append((name, fuzz_version, root_version))
    return pairs


def main():
    for name, fuzz_version, root_version in drift():
        print(f"align {name} {fuzz_version} -> {root_version}")
        subprocess.run(
            [
                "cargo",
                "update",
                "--quiet",
                "--manifest-path",
                str(FUZZ_MANIFEST),
                "--package",
                f"{name}@{fuzz_version}",
                "--precise",
                root_version,
            ],
            check=True,
        )
    remaining = drift()
    for name, fuzz_version, root_version in remaining:
        print(
            f"error: {name} is {fuzz_version} in fuzz/Cargo.lock "
            f"and {root_version} in Cargo.lock",
            file=sys.stderr,
        )
    return 1 if remaining else 0


if __name__ == "__main__":
    sys.exit(main())
