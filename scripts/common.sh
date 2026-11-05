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
# The tools under tooling/ are one module each, named by their folder.
GO_MODULES=(devkit trusted-time signer-protocol markformat governance signer-core platform slashing-log
  platform-aws platform-azure platform-gcp attestation-verify tee-signer signer-admin web3signer-api
  tooling/health-exporter tests)
[ ! -f "$ROOT/gateway/go.mod" ] || GO_MODULES+=(gateway)
# Go uses the go.mod of each module and its replace lines, never a workspace.
export GOWORK=off

# FUZZ_MODULES names the Go modules scripts/fuzz.sh fuzzes, separated by
# spaces: unset or ALL for all of them, none for no module. On a pull
# request CI sets it from scripts/ci-scope.sh, which gives ALL for any
# change to the C code or a shared input. fuzz_everything: FUZZ_MODULES is
# unset or ALL, so every Go module and the C fuzz targets (signer-core,
# markformat) run.
fuzz_everything() { [ -z "${FUZZ_MODULES+x}" ] || [ "$FUZZ_MODULES" = ALL ]; }

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
# rust:1.94.1-slim-bookworm pinned by digest, plus the aarch64 standard library,
# pinned by NTS_STD_SHA256_aarch64).
# The crates are those of trusted-time/rust/Cargo.lock, fetched from crates.io
# into NTS_CARGO_HOME by scripts/fetch-nts.sh. The output goes to build/nts/, not to
# build/<arch>/, so that no file an image build uses is overwritten.
NTS_DIR="$ROOT/trusted-time/rust"
NTS_CARGO_HOME="$BUILD/nts/cargo-home"
NTS_IMAGE="signer-nts-toolchain:1.94.1-slim"
# The toolchain always runs as linux/amd64, also on an arm64 host (under
# emulation there). A native arm64 rustc gives a different aarch64 library,
# so the Nitro PCRs would depend on the build host.
NTS_PLATFORM="linux/amd64"
NTS_RUSTC_COMMIT="e408947bfd200af42db322daf0fadfe7e26d3bd1"
# The standard library of each target in the image: sha256 of the sorted
# "sha256  path" list of every file under lib/rustlib/<target> of the
# sysroot (nts_std_sum in nts-container.sh). The x86_64 one comes with the
# base image; the aarch64 one is what rustup downloaded at image build, and
# this pin is the only check of its bytes beyond rustup's own manifest.
NTS_STD_SHA256_x86_64="bf5ce11b2dc442f3261fb3197d8412a26ed4114b196299d4284f4fbf8c919320"
NTS_STD_SHA256_aarch64="9ebddcc2f45dafdc7e150626f7ed9bd981c7d4da85c33df46b46e7e2d7db8b88"
NTS_OUT="$BUILD/nts"

# nts_toolchain_image: builds the toolchain image if this Docker has none for
# $NTS_PLATFORM. An image of another platform under the same tag is rebuilt.
nts_toolchain_image() {
  local plat
  plat="$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$NTS_IMAGE" 2>/dev/null || true)"
  if [ "$plat" != "$NTS_PLATFORM" ]; then
    log "building $NTS_IMAGE for $NTS_PLATFORM (rustup downloads rust-std for aarch64 from static.rust-lang.org)"
    docker build --pull=false -q --platform "$NTS_PLATFORM" -f "$ROOT/trusted-time/toolchain/toolchain.Dockerfile" -t "$NTS_IMAGE" "$ROOT/trusted-time/toolchain" >/dev/null
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
#   runner-dev-debugimport                 dev platform and plaintext import (local stack, signing client tests)
#   runner-azure-debugimport, runner-aws-debugimport, runner-gcp-debugimport
#                                          test builds with the fake SNP report, NSM and
#                                          Google endpoints; the AWS one has the dev
#                                          platform too (vsock tests)
RUNNER_RELEASE_BINS=(runner-azure runner-aws runner-gcp)
RUNNER_BINS=(runner-azure runner-aws runner-gcp runner-dev runner-dev-debugimport runner-azure-debugimport runner-aws-debugimport runner-gcp-debugimport)

# ---- chains -----------------------------------------------------------------
# CHAIN is the one build switch: the chain the runners and images are built
# for, and the chain the deploy steps take setups of. Unset is mainnet.
#   mainnet  Ethereum mainnet, governance/chains/mainnet.json (pinned to the
#            chain's published config). The prod build: the design's
#            governance waits (a 2-day default time lock, a 7-day images
#            minimum), the build for real keys.
#   hoodi    the public testnet, governance/chains/hoodi.json (pinned to the
#            chain's published config)
#   devnet   a local Kurtosis devnet. Its genesis changes with every devnet,
#            so CHAIN_JSON must name the file (platform-azure/deploy/chain-from-devnet.sh)
#   ci-test  governance/chains/chain.ci-test.json, a test chain that no
#            network runs, for tests and CI only
# hoodi, devnet and ci-test are non-prod builds: the same code built with
# -tags nonprod,chain_<name> (signer-protocol/buildchain), whose governance
# times run in minutes (a 2-minute default time lock, a 7-minute images
# minimum), and which start on their own chain only. Their runners carry
# the chain in their names (runner-azure-hoodi, runner-dev-ci-test, no
# debug builds), and the image scripts put "-<chain>" (image_suffix) into
# build folders, local image names, registry tags and fingerprint files, so
# images of two chains never overwrite each other. The mainnet names have
# no suffix: they are the names of the builds before the switch.
#
# PROD_CHAINS are the prod chains; the chain table of the Go code
# (governance/setupwire chains.go) has the same rows, and a test there
# compares the two.
CHAINS="mainnet hoodi devnet ci-test"
PROD_CHAINS="mainnet"
CHAIN_TOOL="$ROOT/governance/chains/chain.sh"

# check_chain_name NAME: exactly one of $CHAINS.
check_chain_name() {
  local c
  for c in $CHAINS; do [ "${1:-}" = "$c" ] && return 0; done
  echo "CHAIN must be one of: $CHAINS (got '${1:-}')" >&2
  return 1
}

# chain_is_prod NAME: NAME is exactly one of $PROD_CHAINS.
chain_is_prod() {
  local c
  for c in $PROD_CHAINS; do [ "${1:-}" = "$c" ] && return 0; done
  return 1
}

# chain_tags NAME: the Go build tags of the chain's build: none for a prod
# chain, nonprod and chain_<name> ("-" as "_") otherwise.
chain_tags() {
  if chain_is_prod "$1"; then echo ""; else echo "nonprod,chain_${1//-/_}"; fi
}

CHAIN="${CHAIN:-mainnet}"
check_chain_name "$CHAIN" || exit 1
export CHAIN
# CHAIN_PROD: 1 when CHAIN is a prod chain, else 0. Computed here once, from
# this file's chain_is_prod, before the build overlay's hooks.sh (below)
# runs any code: the refusal of the overlay on a prod chain reads it.
if chain_is_prod "$CHAIN"; then CHAIN_PROD=1; else CHAIN_PROD=0; fi

if ! chain_is_prod "$CHAIN"; then
  RUNNER_RELEASE_BINS=(runner-azure-"$CHAIN" runner-aws-"$CHAIN" runner-gcp-"$CHAIN")
  RUNNER_BINS=("${RUNNER_RELEASE_BINS[@]}" runner-dev-"$CHAIN")
fi

# image_suffix: the suffix of an image's runner, folder, names and record:
# "-<chain>" for a non-prod chain, nothing for mainnet.
image_suffix() { if chain_is_prod "$CHAIN"; then echo ""; else echo "-$CHAIN"; fi; }

# runner_tags <binary name>: its platform tags, then debugimport for a debug
# build, then nts for a cloud build, then the chain tags of a non-prod
# build. No runner links an attestation verifier (scripts/check-deps.sh).
# The cloud runners (azure, aws, gcp and their debug builds) link the Rust
# NTS library (trusted-time, build/nts/<arch>/lib) and their images run the
# NTS clock (-nts-clock). The dev builds stay without it.
runner_tags() { runner_base_tags "$1"; }
runner_base_tags() {
  local c
  for c in $CHAINS; do
    chain_is_prod "$c" && continue
    case "$1" in runner-*-"$c") echo "$(runner_base_tags "${1%-"$c"}"),$(chain_tags "$c")"; return ;; esac
  done
  case "$1" in
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

# ---- chain configs ----------------------------------------------------------
# The images hold no chain config: it is in each signer's setup. The build
# checks CHAIN_JSON (chain_select), and the deploy steps refuse a setup of
# another chain than CHAIN (check_setup below, with the chain config
# governance/chains/chain.sh verifies). write_build_chain and
# check_build_chain are the record of the per-chain images before the
# setup; no image build writes it now.

# chain_suffix NAME: the suffix of the deploy folders and local file names.
# Empty for devnet and ci-test, the folders used before chains had names.
chain_suffix() {
  case "$1" in
    devnet | ci-test) echo "" ;;
    *) echo "-$1" ;;
  esac
}

# chain_select: sets CHAIN_JSON to governance/chains/$CHAIN.json
# (governance/chains/chain.ci-test.json for ci-test) when it is unset, and checks that the
# file is a chain config of $CHAIN.
chain_select() {
  check_chain_name "$CHAIN" || return 1
  if [ -z "${CHAIN_JSON:-}" ]; then
    case "$CHAIN" in
      ci-test) CHAIN_JSON="$ROOT/governance/chains/chain.ci-test.json" ;;
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

# The build overlay. SIGNER_BUILD_OVERLAY_DIR names a folder outside this
# repo whose hooks.sh adds parts to a build: runner files (go build
# -overlay), its own programs, image and deploy parts. Non-prod builds only:
# on a prod chain the overlay is refused here, before hooks.sh is sourced,
# so its code never runs in a mainnet build (it could redefine
# chain_is_prod), and the release gate (release-gate.sh) refuses it again on
# every mainnet binary. Unset, this tree builds nothing of it.
OVERLAY_DIR="${SIGNER_BUILD_OVERLAY_DIR:-}"
if [ -n "$OVERLAY_DIR" ]; then
  if [ "$CHAIN_PROD" = 1 ]; then
    echo "SIGNER_BUILD_OVERLAY_DIR is set: the build overlay goes into non-prod builds only (CHAIN=hoodi, devnet or ci-test), unset it for CHAIN=$CHAIN" >&2
    exit 1
  fi
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
