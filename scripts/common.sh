# shellcheck shell=bash disable=SC2034
# Shared settings for the scripts in this folder. Source it, do not run it.
# Every pinned third-party version lives here.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY="$ROOT/signer-core/third_party"
BUILD="$ROOT/build"
LOGS="$ROOT/logs"

# The C signer core is the signer-core module of this repo.
# scripts/build-core.sh builds it into build/<arch>/lib for cgo.
SIGNER_CORE="$ROOT/signer-core"
# The Go modules of this repo, in dependency order (each has its own go.mod).
GO_MODULES=(devkit trusted-time signer-protocol markformat governance signer-core platform slashing-log
  platform-aws platform-azure platform-gcp attestation-verify tee-signer signer-admin web3signer-api tests)
[ ! -f "$ROOT/gateway/go.mod" ] || GO_MODULES+=(gateway)
# Go uses the go.mod of each module and its replace lines, never a workspace.
export GOWORK=off

# supranational/blst, vendored in signer-core/third_party/blst at this pin
# (signer-core/third_party/blst.sha256 lists its files).
BLST_REPO="https://github.com/supranational/blst.git"
BLST_TAG="v0.3.16"
BLST_COMMIT="e7f90de551e8df682f3cc99067d204d8b90d27ad"
BLST_DIR="$THIRD_PARTY/blst"

# aws/aws-nitro-enclaves-cli, pinned tag.
NITRO_CLI_REPO="https://github.com/aws/aws-nitro-enclaves-cli.git"
NITRO_CLI_TAG="v1.5.2"
NITRO_CLI_COMMIT="1c496ed730d2dc41ec5bff6df89b4f3185e18840"
# Fetched at its pin by scripts/fetch.sh --nitro, into build/ (not vendored).
NITRO_CLI_DIR="$BUILD/third_party/aws-nitro-enclaves-cli"

# NTS time client (nts/): a Rust static library, linked into the runner by the
# build tag nts. The Rust toolchain is a Docker image (trusted-time/toolchain/toolchain.Dockerfile:
# rust:1.94.1-slim-bookworm pinned by digest, plus the aarch64 standard library).
# The crates are those of trusted-time/rust/Cargo.lock, fetched from crates.io
# into NTS_CARGO_HOME by scripts/fetch-nts.sh. The output goes to build/nts/, not to
# build/<arch>/, so that no file an image build uses is overwritten.
NTS_DIR="$ROOT/trusted-time/rust"
NTS_CARGO_HOME="$BUILD/nts/cargo-home"
NTS_IMAGE="signer-nts-toolchain:1.94.1-slim"
NTS_RUSTC_COMMIT="e408947bfd200af42db322daf0fadfe7e26d3bd1"
NTS_OUT="$BUILD/nts"

# nts_toolchain_image: builds the toolchain image if this Docker has none.
nts_toolchain_image() {
  if ! docker image inspect "$NTS_IMAGE" >/dev/null 2>&1; then
    log "building $NTS_IMAGE (rustup downloads rust-std for aarch64 from static.rust-lang.org)"
    docker build --pull=false -q -f "$ROOT/trusted-time/toolchain/toolchain.Dockerfile" -t "$NTS_IMAGE" "$ROOT/trusted-time/toolchain" >/dev/null
  fi
}

# tool_for <arch> <tool>: the binutils tool that reads files of <arch> on this host.
tool_for() {
  if [ "$1" = "$HOST_ARCH" ]; then echo "$2"; else echo "$1-linux-gnu-$2"; fi
}

# Terraform image for scripts/tf-validate.sh (validate only, never apply).
TERRAFORM_IMAGE="hashicorp/terraform:1.16.3"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_ARCH=x86_64 ;;
  aarch64|arm64) HOST_ARCH=aarch64 ;;
  *) echo "unsupported architecture: $HOST_ARCH" >&2; exit 1 ;;
esac

# goarch_of <x86_64|aarch64>
goarch_of() { case "$1" in x86_64) echo amd64 ;; aarch64) echo arm64 ;; esac; }

# cc_for <arch>: the C compiler that targets <arch> from this host.
cc_for() {
  if [ "$1" = "$HOST_ARCH" ]; then echo gcc; else echo "$1-linux-gnu-gcc"; fi
}

# The runner is built once per cloud (tee-signer/platforms.go): a binary holds
# the platforms of its build tags and nothing else. scripts/build-runner.sh
# builds these, check-deps.sh checks them, test.sh tests them.
#   runner-azure, runner-aws, runner-gcp   release builds, one per image
#   runner-dev                             release build with the dev platform only
#   runner-dev-debugimport                 dev platform and plaintext import (local stack, Dirk fork tests)
#   runner-azure-debugimport, runner-aws-debugimport, runner-gcp-debugimport
#                                          test builds with the fake SNP report, NSM and
#                                          Google endpoints; the AWS one has the dev
#                                          platform too (vsock tests)
RUNNER_RELEASE_BINS=(runner-azure runner-aws runner-gcp)
RUNNER_BINS=(runner-azure runner-aws runner-gcp runner-dev runner-dev-debugimport runner-azure-debugimport runner-aws-debugimport runner-gcp-debugimport)

# IMAGE_FLAVOR is the build flavour of the runners and images
# (signer-protocol/buildflavor): default, or testnet, the same code built with
# -tags testnet, whose governance times run in minutes (a 2-minute default
# time lock, a 7-minute images minimum) and which starts on devnets, Hoodi,
# Sepolia and Chiado only. With testnet the runner lists above hold the
# release builds of that flavour instead (no debug builds):
#   runner-azure-testnet, runner-aws-testnet, runner-gcp-testnet, runner-dev-testnet
# and the image scripts put FLAVOR_SUFFIX (-testnet) into build folders,
# local image names, registry tags and fingerprint files, so testnet and
# default images never overwrite each other.
IMAGE_FLAVOR="${IMAGE_FLAVOR:-default}"
case "$IMAGE_FLAVOR" in
  default) FLAVOR_SUFFIX="" ;;
  testnet) FLAVOR_SUFFIX="-testnet" ;;
  *) echo "IMAGE_FLAVOR=$IMAGE_FLAVOR: want default or testnet" >&2; exit 1 ;;
esac
if [ "$IMAGE_FLAVOR" = testnet ]; then
  RUNNER_RELEASE_BINS=(runner-azure-testnet runner-aws-testnet runner-gcp-testnet)
  RUNNER_BINS=("${RUNNER_RELEASE_BINS[@]}" runner-dev-testnet)
fi

# image_suffix: the suffix of an image's runner, folder, names and record:
# the flavour (-testnet, or nothing).
image_suffix() { echo "$FLAVOR_SUFFIX"; }

# runner_tags <binary name>: its platform tags, then debugimport for a debug
# build, then nts for a cloud build, then testnet for that flavour, then
# verifierselect and runnerbuild. verifierselect: a runner links the
# attestation verifier of its own platform only (attestation-verify, the
# handover checks the other image with it), where the tools and the tests
# link every verifier. runnerbuild marks a runner build as such: a cloud
# platform tag with runnerbuild and without verifierselect does not
# compile (tee-signer/verifier_guard.go), so no runner build links the dev
# verifier by mistake, while the module tests, which carry no runnerbuild,
# still build with the platform tags alone. The cloud runners (azure, aws,
# gcp and their debug builds) link the Rust NTS library (trusted-time,
# build/nts/<arch>/lib) and their images run the NTS clock (-nts-clock).
# The dev builds stay without it.
runner_tags() { echo "$(runner_base_tags "$1"),verifierselect,runnerbuild"; }
runner_base_tags() {
  case "$1" in
    runner-*-testnet) echo "$(runner_base_tags "${1%-testnet}"),testnet" ;;
    runner-azure) echo platform_azure,nts ;;
    runner-aws) echo platform_aws,nts ;;
    runner-gcp) echo platform_gcp,nts ;;
    runner-dev) echo platform_dev ;;
    runner-dev-debugimport) echo platform_dev,debugimport ;;
    runner-azure-debugimport) echo platform_azure,debugimport,nts ;;
    runner-aws-debugimport) echo platform_aws,platform_dev,debugimport,nts ;;
    runner-gcp-debugimport) echo platform_gcp,debugimport,nts ;;
    *) echo "runner_tags: unknown runner build $1" >&2; return 1 ;;
  esac
}

log() { printf '[cloud] %s\n' "$*" >&2; }

# ---- chains -----------------------------------------------------------------
# The images are generic: the chain config is in each signer's setup
# (research/setup-phase.md in the threshold-signer-poc repo). The deploy steps name
# the chain in CHAIN and refuse a setup of another chain (check_setup below,
# with the chain config governance/chains/chain.sh verifies). write_build_chain
# and check_build_chain are the record of the per-chain images before the
# setup; no image build writes it now.
#   hoodi    the public testnet, governance/chains/hoodi.json (pinned to the chain's
#            published config)
#   devnet   the local Kurtosis devnet. Its genesis changes with every devnet,
#            so CHAIN_JSON must name the file (platform-azure/deploy/chain-from-devnet.sh)
#   testnet  governance/chains/chain.testnet.json, a test chain that no network runs
CHAINS="hoodi devnet testnet"
CHAIN_TOOL="$ROOT/governance/chains/chain.sh"

# chain_suffix NAME: the suffix of the build folders and local image tags.
# Empty for devnet and testnet, the folders used before chains had names.
chain_suffix() {
  case "$1" in
    devnet | testnet) echo "" ;;
    *) echo "-$1" ;;
  esac
}

# check_chain_name NAME: one of $CHAINS.
check_chain_name() {
  case " $CHAINS " in
    *" ${1:-} "*) ;;
    *) echo "CHAIN must be one of: $CHAINS (got '${1:-}')" >&2; return 1 ;;
  esac
}

# chain_select: CHAIN must be set. Sets CHAIN_JSON to governance/chains/$CHAIN.json
# (governance/chains/chain.testnet.json for testnet) when it is unset, and checks that the
# file is a chain config of $CHAIN.
chain_select() {
  [ -n "${CHAIN:-}" ] || { echo "set CHAIN to the chain of the image: $CHAINS" >&2; return 1; }
  check_chain_name "$CHAIN" || return 1
  if [ -z "${CHAIN_JSON:-}" ]; then
    case "$CHAIN" in
      testnet) CHAIN_JSON="$ROOT/governance/chains/chain.testnet.json" ;;
      devnet) echo "CHAIN=devnet needs CHAIN_JSON (platform-azure/deploy/chain-from-devnet.sh writes it)" >&2; return 1 ;;
      *) CHAIN_JSON="$ROOT/governance/chains/$CHAIN.json" ;;
    esac
  fi
  [ -f "$CHAIN_JSON" ] || { echo "$CHAIN_JSON: no such file" >&2; return 1; }
  bash "$CHAIN_TOOL" verify "$CHAIN" "$CHAIN_JSON" || return 1
  export CHAIN CHAIN_JSON
}

# write_build_chain RECORD CHAIN_FILE: the record of the chain a build used,
# read back by check_build_chain before a deploy step.
write_build_chain() {
  printf 'chain %s\nchain.json %s\n' "$CHAIN" "$(sha256sum <"$2" | cut -d' ' -f1)" >"$1"
}

# check_build_chain RECORD CHAIN_FILE: the build that wrote RECORD used chain
# $CHAIN, and CHAIN_FILE (the chain.json of that build) is still that file.
check_build_chain() {
  local record="$1" file="$2" name sum
  [ -n "${CHAIN:-}" ] || { echo "set CHAIN to the chain you deploy ($CHAINS)" >&2; return 1; }
  check_chain_name "$CHAIN" || return 1
  [ -s "$record" ] || { echo "no $record: build again with CHAIN=$CHAIN" >&2; return 1; }
  name="$(sed -n 's/^chain \(.*\)$/\1/p' "$record")"
  sum="$(sed -n 's/^chain\.json \([0-9a-f]\{64\}\)$/\1/p' "$record")"
  [ "$name" = "$CHAIN" ] || { echo "the build in $(dirname "$record") is for chain '$name', not CHAIN=$CHAIN: refused" >&2; return 1; }
  [ -f "$file" ] || { echo "no $file (the chain.json of the build)" >&2; return 1; }
  [ "$(sha256sum <"$file" | cut -d' ' -f1)" = "$sum" ] ||
    { echo "$file changed since the build (sha256 differs from $record): build again" >&2; return 1; }
  bash "$CHAIN_TOOL" verify "$CHAIN" "$file" || return 1
}

# ---- setups -----------------------------------------------------------------
# setup_tool ARGS...: signer-admin/cmd/setup-tool (encode, check, show,
# chain-lines). scripts/build-runner.sh builds it; a missing one is built
# here for this machine, without cgo.
setup_tool() {
  local bin="$BUILD/$HOST_ARCH/bin/setup-tool"
  if [ ! -x "$bin" ]; then
    mkdir -p "$(dirname "$bin")"
    (cd "$ROOT/signer-admin" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$bin" ./cmd/setup-tool) || return 1
  fi
  "$bin" "$@"
}

# check_setup FILE PLATFORM: FILE is a binary setup that the runner of
# PLATFORM accepts, and its chain is chain $CHAIN (chain_select). Prints
# setup-tool's lines: setup_sha256, platform, signer.
check_setup() {
  local file="$1" platform="$2"
  [ -s "$file" ] || { echo "$file: no such setup file (signer-admin/cmd/setup-tool encode makes one)" >&2; return 1; }
  chain_select || return 1
  setup_tool check -platform "$platform" -chain "$CHAIN_JSON" "$file"
}

# setup_value FILE KEY: the first value of KEY in the human form of a setup.
setup_value() {
  setup_tool show "$1" | sed -n "s/^$2 = //p" | head -n 1
}

# Go comes from the login shell PATH. Fall back to /usr/local/go.
if ! command -v go >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then
  PATH="/usr/local/go/bin:$PATH"
fi

# git_checkout_pinned <url> <dir> <tag> <commit>
# Clones or updates <dir> so that HEAD is exactly <commit>.
git_checkout_pinned() {
  local url="$1" dir="$2" tag="$3" commit="$4"
  if [ ! -d "$dir/.git" ]; then
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    git clone --quiet "$url" "$dir"
  fi
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$commit" ]; then
    git -C "$dir" fetch --quiet --tags origin
    git -C "$dir" -c advice.detachedHead=false checkout --quiet --force "$commit"
  fi
  if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
    git -C "$dir" reset --quiet --hard "$commit"
  fi
  local got
  got="$(git -C "$dir" rev-parse HEAD)"
  if [ "$got" != "$commit" ]; then
    echo "$dir: expected $commit ($tag), got $got" >&2
    return 1
  fi
  log "$(basename "$dir") at $tag ($commit)"
}

# has_nts <binary name>: the build links the NTS library (tag nts).
has_nts() { case ",$(runner_tags "$1")," in *,nts,*) return 0 ;; *) return 1 ;; esac; }

# The handover release gate (signer-protocol/docs/protocol.md, "Handover"). No image goes
# out that cannot hand its shares to the next one. scripts/handover-gate.sh
# runs tests/e2e TestE2EHandoverGate (image N hands over to N+1, then N+1
# to N+2) and, when it passed, writes HANDOVER_GATE_STAMP with the source id
# of the tree it tested. The image builds call require_handover_gate.
HANDOVER_GATE_STAMP="$BUILD/handover-gate.stamp"

# handover_source_id: one id for the Go sources an image is built from:
# HEAD, the uncommitted changes and the untracked files of backend, runner,
# attest and admin.
handover_source_id() {
  {
    git -C "$ROOT" rev-parse HEAD
    git -C "$ROOT" diff HEAD -- "${GO_MODULES[@]}"
    (cd "$ROOT" && git ls-files -z --others --exclude-standard -- "${GO_MODULES[@]}" | xargs -0 -r sha256sum)
    devnet_hook source_id
  } | sha256sum | cut -c1-64
}

# require_handover_gate <runner binary name>: the handover gate passed on
# exactly these sources. There is no override.
require_handover_gate() {
  local want got
  want="$(handover_source_id)"
  got="$(cat "$HANDOVER_GATE_STAMP" 2>/dev/null || true)"
  if [ "$got" != "$want" ]; then
    echo "the handover release gate has not passed on these sources (stamp ${got:-missing}, sources $want): run scripts/handover-gate.sh" >&2
    return 1
  fi
}

# The build overlay. SIGNER_BUILD_OVERLAY_DIR names a folder outside this
# repo whose hooks.sh adds parts to a build: runner files (go build
# -overlay), its own programs, image and deploy parts. Testnet builds only: build-runner.sh and the release gate
# (release-gate.sh) refuse a default build while it is set. Unset, this
# tree builds nothing of it.
OVERLAY_DIR="${SIGNER_BUILD_OVERLAY_DIR:-}"
if [ -n "$OVERLAY_DIR" ]; then
  [ -r "$OVERLAY_DIR/hooks.sh" ] || { echo "SIGNER_BUILD_OVERLAY_DIR=$OVERLAY_DIR has no hooks.sh" >&2; exit 1; }
  # shellcheck source=/dev/null
  . "$OVERLAY_DIR/hooks.sh"
fi

# devnet_has NAME: the overlay defines devnet_NAME.
devnet_has() { declare -F "devnet_$1" >/dev/null; }
# devnet_hook NAME ARGS...: runs devnet_NAME when the overlay defines it.
devnet_hook() {
  local f="devnet_$1"
  shift
  if declare -F "$f" >/dev/null; then "$f" "$@"; fi
}

# go_overlay_flags: the go build flags that add the overlay's runner files
# (go build -overlay), none without the overlay.
go_overlay_flags() {
  if devnet_has go_overlay; then
    printf -- '-overlay=%s\n' "$(devnet_go_overlay "$ROOT" "$BUILD")"
  fi
}
