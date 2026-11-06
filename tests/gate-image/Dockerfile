# The image the OpenSSH interop gate and the systemd reference-unit test
# run in (ADR-0059). It is built once per pin by
# .github/workflows/gate-image.yml, never by a gate. The pin is ADR-0048's:
# the dated forky base by digest, its build snapshot, the exact
# openssh-client version and its `ssh -V`. To bump, follow ADR-0034's
# procedure in this file (new digest -> its timestamp into SNAPSHOT -> the
# package version that snapshot resolves -> the `ssh -V` it prints); the
# gates move to the new image in a second PR (ADR-0059 §5).

# debian:forky-20261027-slim
FROM debian@sha256:04db4720574d184e24353e77e46dbbe4377edad01c9ba50a67aa1473cef9b9d4 AS snapshot

ARG SNAPSHOT=20261027T000000Z

# The stages built FROM this one inherit the shell.
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# ADR-0034: the base image's own debian.sources names, commented out, the
# snapshot it was built from, and apt must read that one. http, because the
# slim image has no CA bundle; apt checks the Release signatures
# (Signed-By). Check-Valid-Until off, because the archived Release files of
# forky-updates and forky-security are past their validity window.
RUN grep -q "snapshot.debian.org/archive/debian/${SNAPSHOT}" /etc/apt/sources.list.d/debian.sources \
        || { echo "SNAPSHOT=${SNAPSHOT} is not the snapshot this image was built from" >&2; exit 1; }; \
    printf '%s\n' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
        'Suites: forky forky-updates' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
        '' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/" \
        'Suites: forky-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
        > /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' 'Acquire::Check-Valid-Until "false";' 'Acquire::Retries "3";' \
        > /etc/apt/apt.conf.d/99snapshot

FROM snapshot AS gate

ARG SNAPSHOT=20261027T000000Z
ARG OPENSSH_CLIENT_VERSION=1:10.6p1-1
# OpenSSL is part of the string, so it pins the library build as well.
ARG SSH_V_EXPECTED="OpenSSH_10.6p1 Debian-1, OpenSSL 3.6.5 29 Sep 2026"

# The interop gate's packages, then the systemd test's; only the client is
# named by version, the snapshot freezes the rest. The interop gate builds
# the workspace inside this image on pull requests: ca-certificates and curl
# are what dtolnay/rust-toolchain needs to install rustup, and gcc and
# libc6-dev are the linker and C runtime cargo links with. The systemd test
# needs systemd as PID 1 and procps. apt-get update fails on any missing
# index (by default it warns and goes on), and both it and the download are
# retried (retry.sh); the install then runs from the verified cache. A
# client that does not match the pin fails the build, so no such image is
# pushed. The image then records, readable without running it, its `ssh -V`
# and the Debian source package of everything installed (ADR-0059 §2).
# hadolint ignore=DL3008,SC3054
RUN --mount=type=bind,source=retry.sh,target=/usr/local/sbin/retry \
    pkgs=(ca-certificates curl gcc libc6-dev "openssh-client=${OPENSSH_CLIENT_VERSION}" \
        systemd systemd-sysv procps); \
    retry apt-get update --error-on=any; \
    retry apt-get install -y --no-install-recommends --download-only "${pkgs[@]}"; \
    apt-get install -y --no-install-recommends "${pkgs[@]}"; \
    rm -rf /var/lib/apt/lists/*; \
    ssh_v="$(ssh -V 2>&1)"; \
    [ "$ssh_v" = "$SSH_V_EXPECTED" ] \
        || { echo "ssh -V is '$ssh_v', expected '$SSH_V_EXPECTED'" >&2; exit 1; }; \
    ssh -Q kex | grep -qx mlkem768x25519-sha256 \
        || { echo "mlkem768x25519-sha256 not offered by this client" >&2; exit 1; }; \
    ssh -Q key | grep -qx ssh-mldsa44-ed25519 \
        || { echo "ssh-mldsa44-ed25519 not offered by this client" >&2; exit 1; }; \
    mkdir -p /usr/share/quantumssh-gate; \
    printf '%s\n' "$ssh_v" > /usr/share/quantumssh-gate/ssh-version; \
    dpkg-query -W -f '${source:Package}=${source:Version}\n' | LC_ALL=C sort -u \
        > /usr/share/quantumssh-gate/sources.txt

LABEL org.opencontainers.image.source="https://github.com/gonzafg2/quantumssh" \
      org.opencontainers.image.description="The QuantumSSH OpenSSH and systemd gates' image (ADR-0059): Debian forky at snapshot.debian.org ${SNAPSHOT}, openssh-client ${OPENSSH_CLIENT_VERSION}. The Debian sources of every package in it are in ghcr.io/gonzafg2/quantumssh-gate-sources, tagged sha256-<hex of this image's index digest>."

# The systemd test runs the image with systemd as PID 1 (ADR-0043 §7).
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

# The Debian source packages the gate image's sources.txt lists, from the
# same snapshot. The workflow passes the union of both platforms' lists as
# the build context `list`. apt checks each file it fetches against the
# signed Sources index. There are a few hundred files; the index and the
# files are retried as in the gate stage, and apt-get source keeps the files
# it already verified.
FROM snapshot AS fetch-sources

WORKDIR /sources

RUN --mount=type=bind,from=list,target=/list \
    --mount=type=bind,source=retry.sh,target=/usr/local/sbin/retry \
    sed -i 's/^Types: deb$/Types: deb-src/' /etc/apt/sources.list.d/debian.sources; \
    retry apt-get update --error-on=any; \
    chown _apt /sources; \
    retry xargs -a /list/sources.txt apt-get source --download-only; \
    cp /list/sources.txt /sources/SOURCES.txt

FROM scratch AS sources
LABEL org.opencontainers.image.source="https://github.com/gonzafg2/quantumssh" \
      org.opencontainers.image.description="Debian source packages of ghcr.io/gonzafg2/quantumssh-gate (ADR-0059 §2). The tag names the gate image's index digest; SOURCES.txt lists every source package and version."
COPY --from=fetch-sources /sources /sources
