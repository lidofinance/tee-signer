# Builds nitro-cli from the pinned aws-nitro-enclaves-cli source and packs it
# with the kernel/init blobs from the same source tree. Only `build-enclave`
# and `describe-eif` are useful here: there is no Nitro device on the build
# host. Build context: third_party/aws-nitro-enclaves-cli (see
# scripts/nitro-eif.sh). Base images are pinned by digest.
#
# Second build input: the named context "patches" is platform-aws/deploy/nitro-cli
# (scripts/nitro-cli-image.sh passes it), for target-arch.patch.
#
# Building an EIF for the other arch (arm64 on x86_64): nitro-cli 1.5.2 takes
# the kernel blob name from the arch it runs on. target-arch.patch lets
# NITRO_CLI_TARGET_ARCH set it instead. The blobs baked in below are the host
# arch's. For another target scripts/nitro-eif.sh mounts that arch's blob set
# from the pinned source over them and sets NITRO_CLI_TARGET_ARCH. The blob
# set has its own linuxkit binary, which then runs through qemu-user (binfmt_misc
# with the F flag, package qemu-user-static on the docker host).
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin nitro-cli
# The patch comes after the unpatched build on purpose. The build above and
# its cargo registry stay as they were, so docker keeps reusing their cached
# layer, and the second build recompiles nitro-cli alone, offline. The grep
# fails the build if the patched code is not in the binary.
COPY --from=patches target-arch.patch /tmp/target-arch.patch
RUN git apply /tmp/target-arch.patch \
 && cargo build --release --locked --offline --bin nitro-cli \
 && grep -qa NITRO_CLI_TARGET_ARCH target/release/nitro-cli

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG BLOBS_ARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/nitro-cli /usr/bin/nitro-cli
COPY blobs/${BLOBS_ARCH}/ /usr/share/nitro_enclaves/blobs/
# World-writable log dir: the build script runs nitro-cli as the calling user.
RUN mkdir -p /var/log/nitro_enclaves /out && chmod 1777 /var/log/nitro_enclaves
ENV NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs \
    NITRO_CLI_ARTIFACTS=/tmp/nitro-artifacts
ENTRYPOINT ["/usr/bin/nitro-cli"]
