# Disposable systemd host for the reference-unit check (ADR-0043 §7):
# the interop gate's pinned Debian image and snapshot (ADR-0034,
# .github/workflows/interop.yml), with systemd as PID 1 and the same
# pinned OpenSSH 10 client. Bump the digest, SNAPSHOT and client version
# together with the interop gate.
FROM debian@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2

ARG SNAPSHOT=20260623T000000Z
ARG OPENSSH_CLIENT_VERSION=1:10.0p1-7+deb13u4

RUN set -eu; \
    grep -q "snapshot.debian.org/archive/debian/${SNAPSHOT}" /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
        'Suites: trixie trixie-updates' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
        '' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/" \
        'Suites: trixie-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
        > /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' 'Acquire::Check-Valid-Until "false";' 'Acquire::Retries "3";' \
        > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv procps "openssh-client=${OPENSSH_CLIENT_VERSION}"; \
    rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
