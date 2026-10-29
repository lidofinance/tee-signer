# Shared settings for the gateway scripts. Source it, do not run it.
# shellcheck shell=bash
# shellcheck disable=SC2034 # variables are used by the scripts that source this file

GW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$GW_DIR/.." && pwd)"
GW_BIN="$GW_DIR/bin"

# Web3Signer spec the request format and test vectors come from.
WEB3SIGNER_REPO="https://github.com/Consensys/web3signer.git"
WEB3SIGNER_TAG="26.9.0"

for d in /usr/local/go/bin "$HOME/go/bin"; do
  case ":$PATH:" in *":$d:"*) ;; *) [ -d "$d" ] && PATH="$d:$PATH" ;; esac
done
export PATH
# Each module builds with its own go.mod and replace lines, never a workspace.
export GOWORK=off

log() { printf '[gateway] %s\n' "$*" >&2; }
die() { printf '[gateway] ERROR: %s\n' "$*" >&2; exit 1; }
