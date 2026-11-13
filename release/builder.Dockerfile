# Release builder: the C core, the link and every Go binary of a release are
# built in this image, so the runner bytes do not depend on the build host.
# The Rust NTS library keeps its own pinned image
# (trusted-time/toolchain/toolchain.Dockerfile), and nitro-cli its own
# (platform-aws/deploy/nitro-cli/Dockerfile).
#
# Every input is pinned:
#   - the base image by its index digest (the same digest as the nitro-cli
#     runtime stage),
#   - the Debian packages (gcc, glibc, binutils, the aarch64 cross
#     toolchain) by a snapshot.debian.org date: apt sees the archive as it
#     was at SNAPSHOT and nothing newer. apt checks the Release files with
#     the keyring of the base image,
#   - Go by version and the sha256 that go.dev/dl publishes.
#
# No git: the build needs no VCS data (-buildvcs=false), and git pulls in
# libcurl and krb5. snapshot.debian.org answered 503 ("No healthy
# backends") for a random part of the .deb files on 2026-11-09, so the
# download step loops: each try keeps what it fetched, and apt checks every
# file against the signed Release. A failed fetch fails the build, never
# changes the bytes.
#
# Bump one pin at a time and record the runner sha256 before and after in
# the PR: a new gcc, glibc or Go changes the runner, so the measurements.
#
#   docker buildx build -f release/builder.Dockerfile -t signer-release-builder:<tag> release
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ARG SNAPSHOT=20261101T000000Z
ARG GO_VERSION=1.26.10
ARG GO_SHA256=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5

RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm main" \
    "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm-updates main" \
    "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT} bookworm-security main" \
    >/etc/apt/sources.list \
 && apt-get -o Acquire::Retries=5 update \
 && pkgs="gcc libc6-dev binutils gcc-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu file ca-certificates python3 jq" \
 && ok=0 && for i in $(seq 1 30); do \
      apt-get -o Acquire::Retries=3 -qq install -d -y --no-install-recommends $pkgs && { ok=1; break; }; \
      echo "apt download try $i failed, retrying"; sleep 5; \
    done && [ "$ok" = 1 ] \
 && apt-get install -y --no-install-recommends --no-download $pkgs \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb \
 && dpkg-query -W -f '${Package} ${Version} ${Architecture}\n' | LC_ALL=C sort >/builder-packages.txt

ADD --checksum=sha256:${GO_SHA256} https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz /tmp/go.tgz
RUN tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz \
 && echo "go ${GO_VERSION} ${GO_SHA256}" >>/builder-packages.txt

ENV PATH=/usr/local/go/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GOTOOLCHAIN=local \
    GOWORK=off \
    CGO_ENABLED=1 \
    LC_ALL=C.UTF-8 \
    TZ=UTC
