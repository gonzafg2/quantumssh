# Disposable systemd host for the reference-unit check (ADR-0043 §7):
# the interop gate's pinned Debian image and snapshot (ADR-0034 and
# ADR-0048, .github/workflows/interop.yml), with systemd as PID 1 and the
# same pinned OpenSSH 10.6 client, whose ssh-keygen makes the composite
# host key. Bump the digest, SNAPSHOT and client version together with
# the interop gate.
# debian:forky-20261027-slim
FROM debian@sha256:04db4720574d184e24353e77e46dbbe4377edad01c9ba50a67aa1473cef9b9d4

ARG SNAPSHOT=20261027T000000Z
ARG OPENSSH_CLIENT_VERSION=1:10.6p1-1

# The apt steps are retried as in the interop gate (#262): apt-get update
# fails on any missing index, and the download is retried before the
# install runs from the verified cache.
# ponytail: a copy of interop.yml's retry loop; both go away when the gates
# move to the image of ADR-0059 (§5 step 2).
RUN set -eu; \
    grep -q "snapshot.debian.org/archive/debian/${SNAPSHOT}" /etc/apt/sources.list.d/debian.sources; \
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
        > /etc/apt/apt.conf.d/99snapshot; \
    retry() { \
        attempt=1; \
        until "$@"; do \
            [ "$attempt" -lt 8 ] || { echo "failed after $attempt attempts: $*" >&2; return 1; }; \
            echo "attempt $attempt failed, retrying in 120 s: $*" >&2; \
            attempt=$((attempt + 1)); \
            sleep 120; \
        done; \
    }; \
    retry apt-get update --error-on=any; \
    retry apt-get install -y --no-install-recommends --download-only \
        systemd systemd-sysv procps "openssh-client=${OPENSSH_CLIENT_VERSION}"; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv procps "openssh-client=${OPENSSH_CLIENT_VERSION}"; \
    rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
