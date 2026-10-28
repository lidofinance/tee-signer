#!/usr/bin/env bash
# Installs build and test dependencies on Ubuntu 22.04 / 24.04 (x86_64 or
# arm64). Idempotent. Go (>= 1.26) and Docker are checked, not installed.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

pkgs=(build-essential git curl file openssl python3 gettext-base jq clang cloc)
case "$HOST_ARCH" in
  # qemu-user runs the arm64 test binaries. qemu-user-static registers the
  # binfmt_misc entry with the F flag, so arm64 programs also run inside
  # docker containers: nitro-eif.sh needs that for an arm64 EIF.
  x86_64) pkgs+=(gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user qemu-user-static) ;;
  aarch64) pkgs+=(gcc-x86-64-linux-gnu libc6-dev-amd64-cross) ;;
esac
missing=()
for p in "${pkgs[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
done
if [ ${#missing[@]} -gt 0 ]; then
  log "installing: ${missing[*]}"
  sudo apt-get -o DPkg::Lock::Timeout=900 update -qq
  sudo apt-get -o DPkg::Lock::Timeout=900 install -y -qq "${missing[@]}"
else
  log "apt packages already installed"
fi

if ! command -v go >/dev/null; then
  echo "Go not found. Install Go >= 1.26 from https://go.dev/dl/ and put it on PATH." >&2
  exit 1
fi
gov="$(go env GOVERSION | sed 's/^go//')"
if [ "$(printf '%s\n1.26\n' "$gov" | sort -V | head -1)" != "1.26" ]; then
  echo "Go $gov is too old; need >= 1.26 (runner/go.mod)." >&2
  exit 1
fi
log "go $gov"
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  log "docker $(docker version --format '{{.Server.Version}}') (needed for scripts/nitro-eif.sh only)"
else
  log "docker not usable: scripts/nitro-eif.sh will not run"
fi
