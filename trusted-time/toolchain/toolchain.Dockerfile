# Rust toolchain for the NTS static library (nts/, scripts/build-nts.sh).
#
# The base is the rust:1.94.1-bookworm image, pinned by the digest of the
# image in the local Docker store. The only addition is the aarch64 standard
# library: rustup downloads rust-std for aarch64-unknown-linux-gnu from
# static.rust-lang.org over HTTPS and checks it against the sha256 in the
# release manifest of 1.94.1. A Rust staticlib needs no linker, so there is no
# aarch64 gcc here. The Go runner build does the final link with the host's
# aarch64-linux-gnu-gcc.
#
#   docker build --pull=false -f rust/toolchain.Dockerfile -t signer-nts-toolchain:1.94.1 rust/
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55
RUN rustup target add aarch64-unknown-linux-gnu \
 && rustc -Vv \
 && rustup target list --installed
