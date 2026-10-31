#!/usr/bin/env bash
# Runs inside the toolchain image. scripts/build-nts.sh starts it, one run per
# architecture, as an unprivileged user, with no network. Not for the host.
#
# In: NTS_TARGET (Rust target), NTS_CROOT (where the sources are mounted),
# NTS_RUSTC_COMMIT (the compiler this build is pinned to), NTS_STD_SHA256 (the
# standard library of NTS_TARGET this build is pinned to), NTS_TEST (1: run the
# tests of signer-nts and signer-nts-core first, on x86_64 only).
# Out, in /out: libsigner_nts.a, and the no_std checks of the core:
# core-features.txt (cargo tree -e features) and libsigner_nts_nostd_check.a.
set -euo pipefail
umask 022
: "${NTS_TARGET:?}" "${NTS_CROOT:?}" "${NTS_RUSTC_COMMIT:?}" "${NTS_STD_SHA256:?}" "${CARGO_HOME:?}" "${CARGO_TARGET_DIR:?}"

mkdir -p "$HOME" "$CARGO_HOME"

# The crates: build-nts.sh mounts the download cache read-only at /crates.
# Only the lock's .crate archives are copied out of it, and the copies are
# checked against the sha256 in Cargo.lock. Each checked archive is unpacked
# into $VENDOR, a directory source whose .cargo-checksum.json names the same
# sha256 (cargo compares it with the lock). cargo builds from $VENDOR alone:
# no registry index, no extracted source and no other file of the host cache
# is read, so dependency features come from the crates' own Cargo.toml.
VENDOR=/tmp/vendor
bash /nts-verify-crates.sh "$NTS_CROOT/nts/Cargo.lock" /crates "$CARGO_HOME"
mkdir -p "$VENDOR"
for archive in "$CARGO_HOME"/registry/cache/*/*.crate; do
  crate="$(basename "$archive" .crate)"
  [ ! -e "$VENDOR/$crate" ] || continue
  tar -xzf "$archive" -C "$VENDOR" --no-same-owner
  [ -f "$VENDOR/$crate/Cargo.toml" ] || { echo "$archive does not unpack to $crate/" >&2; exit 1; }
  printf '{"files":{},"package":"%s"}\n' "$(sha256sum "$archive" | cut -d' ' -f1)" >"$VENDOR/$crate/.cargo-checksum.json"
done
rm -rf "$CARGO_HOME/registry"

got="$(rustc -vV | sed -n 's/^commit-hash: //p')"
[ "$got" = "$NTS_RUSTC_COMMIT" ] || { echo "rustc is $got, this build is pinned to $NTS_RUSTC_COMMIT" >&2; exit 1; }
installed="$(rustup target list --installed)"
grep -qx "$NTS_TARGET" <<<"$installed" || { echo "the standard library for $NTS_TARGET is not installed" >&2; exit 1; }
# rustup checked the aarch64 rust-std only against the release manifest it
# downloaded from the same server; this checks the installed files against
# the pin.
nts_std_sum() {
  (cd "$(rustc --print sysroot)/lib/rustlib/$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}
got="$(nts_std_sum "$NTS_TARGET")"
[ "$got" = "$NTS_STD_SHA256" ] || { echo "the standard library for $NTS_TARGET sums to $got, this build is pinned to $NTS_STD_SHA256" >&2; exit 1; }

# Every absolute path the compiler or cargo could write into the archive is
# mapped to a fixed one: the mount point of the sources, the crates, the cargo
# and rustup folders, the target folder. The standard library has /rustc/<commit>/ paths
# of its own, the same on every build with this compiler.
export RUSTFLAGS="--remap-path-prefix=$NTS_CROOT=/build --remap-path-prefix=$VENDOR=/vendor --remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup --remap-path-prefix=$CARGO_TARGET_DIR=/target"

cd "$NTS_CROOT/nts"
# --locked: Cargo.lock must be current. --offline: no index, no download.
# --frozen: both. The source replacement points crates.io at $VENDOR.
cargo_flags=(--locked --offline --frozen
  --config 'source.crates-io.replace-with="checked-crates"'
  --config "source.checked-crates.directory=\"$VENDOR\"")

if [ "${NTS_TEST:-0}" = 1 ]; then
  cargo test "${cargo_flags[@]}" --target x86_64-unknown-linux-gnu -p signer-nts -p signer-nts-core
fi

# The core must build without the standard library (it goes into an OP-TEE
# trusted app later), so no crate in its graph may turn on a "std" feature.
cargo tree "${cargo_flags[@]}" --target "$NTS_TARGET" -p signer-nts-core -e features >/out/core-features.txt
if grep -n 'feature "std"' /out/core-features.txt >&2; then
  echo "a dependency of signer-nts-core turns on a std feature (lines above)" >&2
  exit 1
fi

cargo build --release "${cargo_flags[@]}" --target "$NTS_TARGET"
install -m 0644 "$CARGO_TARGET_DIR/$NTS_TARGET/release/libsigner_nts.a" /out/libsigner_nts.a
# Redistribution notices for the exact standard library linked into this archive.
install -m 0644 "$(rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html" /out/RUST_STANDARD_LIBRARY.html

# The core in a no_std static library with its own panic handler: the build
# fails if anything in the graph links std (nostd-check/src/lib.rs).
cargo build --release "${cargo_flags[@]}" --target "$NTS_TARGET" -p signer-nts-nostd-check
install -m 0644 "$CARGO_TARGET_DIR/$NTS_TARGET/release/libsigner_nts_nostd_check.a" /out/libsigner_nts_nostd_check.a
