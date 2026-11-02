# Rust toolchain for the NTS static library (trusted-time/rust, scripts/build-nts.sh).
#
# The base is the rust:1.94.1-slim-bookworm image, pinned by its index digest.
# Its rustup install uses the minimal profile (rustc, cargo, rust-std), and
# Debian slim adds only gcc and libc6-dev, which the crates' build scripts and
# the x86_64 test binaries link with. The only addition is the aarch64 standard
# library: rustup downloads rust-std for aarch64-unknown-linux-gnu from
# static.rust-lang.org over HTTPS and checks it against the sha256 in the
# release manifest of 1.94.1, which comes from the same server. The build
# (scripts/nts-container.sh) then checks the installed files of each target
# against NTS_STD_SHA256_<arch> in scripts/common.sh. A Rust staticlib needs no linker, so there is no
# aarch64 gcc here. The Go runner build does the final link with the host's
# aarch64-linux-gnu-gcc.
#
#   docker build --pull=false -f trusted-time/toolchain/toolchain.Dockerfile -t signer-nts-toolchain:1.94.1-slim trusted-time/toolchain
FROM rust:1.94.1-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2
RUN rustup target add aarch64-unknown-linux-gnu \
 && rustc -Vv \
 && rustup target list --installed
