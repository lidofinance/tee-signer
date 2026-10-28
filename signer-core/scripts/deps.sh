#!/usr/bin/env bash
# Installs the Ubuntu 22.04/24.04 packages signer-core needs. Idempotent.
# On x86_64 it also installs an aarch64 cross toolchain and qemu-user so the
# test binaries can be cross-built and run under emulation.
# On aarch64 (Lima on Apple Silicon) the native build already covers aarch64.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

pkgs=(build-essential make git curl ca-certificates python3 tar gzip binutils file)
if [ "$HOST_ARCH" = x86_64 ]; then
  pkgs+=(gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user)
fi

missing=()
for p in "${pkgs[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
done

if [ "${#missing[@]}" -eq 0 ]; then
  log "deps already installed"
  exit 0
fi

log "installing: ${missing[*]}"
$SUDO apt-get -o DPkg::Lock::Timeout=900 update -qq
# --no-install-recommends keeps qemu-user from pulling in binfmt registration.
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 \
  install -y -qq --no-install-recommends "${missing[@]}"
