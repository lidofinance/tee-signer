#!/usr/bin/env bash
# Builds the static runner binaries, one per cloud, and the Nitro parent
# tools. The platforms are build-time plugins (tee-signer/platforms.go): a binary
# holds the platforms of its build tags and nothing else, so an Azure image
# carries no AWS SDK. Per architecture, in build/<arch>/bin/:
#
#   runner-azure             release: platform azure; the Azure image
#   runner-aws               release: platform nitro (tag platform_aws); the Nitro EIF
#   runner-gcp               release: platform gcp; the GCP image
#   runner-dev               release: platform dev only, no cloud code; local tests
#   runner-dev-debugimport   platform dev and -tags debugimport: plaintext
#                            IMPORT_SHARE and -allow-import. The local stack and
#                            the Dirk fork tests run this one.
#   runner-debugimport       a copy of runner-dev-debugimport under its old name,
#                            which stack/ and dirk-fork/scripts of threshold-signer-poc use
#   runner-azure-debugimport test build: the Azure runner with the fake SNP report
#                            and metadata service (attestation-verify/runnerclient tests)
#   runner-aws-debugimport   test build: the Nitro runner with the fake NSM, and
#                            the dev platform too, so the vsock tests run on it
#   runner-gcp-debugimport   test build: the GCP runner with STS, IAM and KMS at a
#                            test URL (tests/e2e mark log tests)
#   with IMAGE_FLAVOR=testnet, instead of the runners above (common.sh):
#   runner-<cloud>-testnet, runner-dev-testnet
#                            release builds with -tags testnet: governance
#                            times in minutes, devnets and test networks only
#                            (signer-protocol/buildflavor)
#   hostagent                pure Go (Nitro parent side, tag platform_aws for vsock)
#   forwarder                pure Go (Nitro parent side): TCP to vsock, no TLS
#   udprelay                 pure Go (Nitro parent side): the NTS clock's NTP datagrams
#                            between vsock and UDP, allowlist and rate limits
#
# The cloud runners (azure, aws, gcp and their debug builds) have the build
# tag nts: they carry the NTS clock (trusted-time/nts) and their images turn
# it on (-nts-clock). runner-dev and runner-dev-debugimport stay without it.
#
# Only the three release binaries named after a cloud go into images; the
# debug builds never do. The script checks that every binary is static and of
# the arch asked for, that every default-flavour binary passes the release
# gate (scripts/release-gate.sh: no testnet role, legacy or
# debug code, no test-only package in a release build), that no
# default-flavour binary has the image check
# override -allow-unlisted-image and every testnet one has it, that no
# release binary has the -allow-import flag or a
# test option (test_nsm_url, test_snp_hostdata, test_imds_url, test_google_url) and that the
# debug builds have them, that a build without a platform tag refuses to
# start, and, through scripts/check-deps.sh, that no binary links the code of
# a cloud it does not run on. hostagent and forwarder need no C compiler, so
# the aarch64 ones (the parent side of a Graviton instance) build on any host.
#
# Usage: build-runner.sh [x86_64|aarch64 ...]   default: same arch list as build-core.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# check_bin <file> <arch>: statically linked ELF of that arch.
check_bin() {
  local info
  info="$(file -b "$1")"
  case "$info" in
    *"statically linked"*) ;;
    *) echo "$1 is not static: $info" >&2; exit 1 ;;
  esac
  case "$2:$info" in
    x86_64:*"x86-64"*|aarch64:*"ARM aarch64"*) ;;
    *) echo "$1 is not an $2 binary: $info" >&2; exit 1 ;;
  esac
}

# has_string <file> <string> <yes|no> <why>: the binary holds the string, or not.
# The flag and option names are strings only the code behind them holds.
has_string() {
  if grep -qa -- "$2" "$1"; then
    [ "$3" = yes ] || { echo "$1 contains $2 ($4)" >&2; exit 1; }
  else
    [ "$3" = no ] || { echo "$1 has no $2 ($4)" >&2; exit 1; }
  fi
}

# The build overlay is for testnet builds only (release gate).
if [ -n "$OVERLAY_DIR" ] && [ "$IMAGE_FLAVOR" != testnet ]; then
  echo "SIGNER_BUILD_OVERLAY_DIR is set: the build overlay goes into testnet builds only, unset it for IMAGE_FLAVOR=$IMAGE_FLAVOR" >&2
  exit 1
fi
mapfile -t OVERLAY_FLAGS < <(go_overlay_flags)

bash "$ROOT/scripts/check-deps.sh"
bash "$ROOT/scripts/build-core.sh" "$@"

archs=("$@")
if [ ${#archs[@]} -eq 0 ]; then
  archs=("$HOST_ARCH")
  for a in x86_64 aarch64; do
    [ "$a" = "$HOST_ARCH" ] && continue
    command -v "$(cc_for "$a")" >/dev/null 2>&1 && archs+=("$a")
  done
fi
# -trimpath and an empty build id keep the binary byte-identical across
# rebuilds with the same toolchain, which keeps enclave measurements stable.
LDFLAGS="-s -w -buildid= -linkmode external -extldflags -static"
for arch in "${archs[@]}"; do
  out="$BUILD/$arch/bin"
  mkdir -p "$out"
  for name in "${RUNNER_BINS[@]}"; do
    (cd "$ROOT/tee-signer" && \
      CGO_ENABLED=1 GOOS=linux GOARCH="$(goarch_of "$arch")" CC="$(cc_for "$arch")" \
      go build -trimpath -buildvcs=false ${OVERLAY_FLAGS[@]+"${OVERLAY_FLAGS[@]}"} -tags "netgo,osusergo,$(runner_tags "$name")" -ldflags "$LDFLAGS" -o "$out/$name" .)
    check_bin "$out/$name" "$arch"
    log "$arch $name: $(stat -c %s "$out/$name") bytes, sha256 $(sha256sum "$out/$name" | cut -c1-16)..., $(file -b "$out/$name")"
    case "$name" in
      *-debugimport)
        has_string "$out/$name" allow-import yes "a debug build has the plaintext import flag"
        # The gate forbids file names; a debug build shows they are in the binary.
        has_string "$out/$name" tee-signer/debugimport.go yes "a debug build holds its debug file's name (release-gate.sh)" ;;
      *)
        has_string "$out/$name" allow-import no "a release build has no plaintext import flag" ;;
    esac
    # The release gate's forbid lists (scripts/release-gate.sh): every
    # default-flavour build, and the release list for the builds that are
    # not debug builds, with their dependencies.
    if [ "$IMAGE_FLAVOR" = default ]; then
      case "$name" in
        *-debugimport) bash "$ROOT/scripts/release-gate.sh" binary "$out/$name" debug ;;
        *)
          bash "$ROOT/scripts/release-gate.sh" binary "$out/$name" release
          GOOS=linux GOARCH="$(goarch_of "$arch")" CGO_ENABLED=1             bash "$ROOT/scripts/release-gate.sh" deps "$ROOT/tee-signer" "netgo,osusergo,$(runner_tags "$name")" . ;;
      esac
    fi
    # The flavour shows in HEALTH's version and the TLS certificate's name.
    case "$name" in
      *-testnet)
        if [ -n "$OVERLAY_DIR" ]; then
          has_string "$out/$name" signer-build-overlay yes "a testnet build with SIGNER_BUILD_OVERLAY_DIR has the overlay"
        else
          has_string "$out/$name" signer-build-overlay no "a testnet build without SIGNER_BUILD_OVERLAY_DIR has no overlay"
        fi
        has_string "$out/$name" "signer-runner testnet" yes "a testnet build names its flavour in its certificate"
        has_string "$out/$name" "0.1.0+testnet" yes "a testnet build names its flavour in its version"
        has_string "$out/$name" allow-unlisted-image yes "a testnet build has the image check override" ;;
      *)
        has_string "$out/$name" "signer-runner testnet" no "a default build is not a testnet build"
        has_string "$out/$name" "0.1.0+testnet" no "a default build is not a testnet build"
        has_string "$out/$name" allow-unlisted-image no "a default build always holds the image check (signer-protocol/docs/protocol.md, Image check)" ;;
    esac
    # Every release build has both handover sides; the debug builds have
    # neither (tee-signer/server, tag debugimport).
    case "$name" in
      *-debugimport)
        has_string "$out/$name" signer-handover-order-record-v1 no "a debug build cannot hand over, so no image takes it" ;;
      *)
        has_string "$out/$name" signer-handover-order-record-v1 yes "a release build has the handover source side" ;;
    esac
    for opt in test_nsm_url test_snp_hostdata test_imds_url test_google_url; do
      case "$name:$opt" in
        runner-aws-debugimport:test_nsm_url|runner-azure-debugimport:test_snp_hostdata|runner-azure-debugimport:test_imds_url|runner-gcp-debugimport:test_google_url)
          has_string "$out/$name" "$opt" yes "this debug build has the test option" ;;
        *)
          has_string "$out/$name" "$opt" no "this build has no such test option" ;;
      esac
    done
    # The NTS library and the -nts-clock flag in the cloud builds only; the
    # test servers' variable in their debug builds only.
    if has_nts "$name"; then
      has_string "$out/$name" "github.com/lidofinance/tee-signer/trusted-time/nts" yes "a cloud build has the NTS clock"
      has_string "$out/$name" "nts-coarse-urls" yes "a cloud build has the NTS clock flags"
    else
      has_string "$out/$name" "github.com/lidofinance/tee-signer/trusted-time/nts" no "a dev build has no NTS clock"
      has_string "$out/$name" "nts-coarse-urls" no "a dev build has no NTS clock flags"
    fi
    case "$name" in
      runner-azure-debugimport|runner-aws-debugimport|runner-gcp-debugimport)
        has_string "$out/$name" RUNNER_NTS_TEST_SERVERS yes "this debug build can name NTS test servers" ;;
      *)
        has_string "$out/$name" RUNNER_NTS_TEST_SERVERS no "this build uses the public NTS operators only" ;;
    esac
  done
  # The old file name of the dev debug runner, as a copy that replaces the
  # old file in one step (a process that runs the old one keeps it). A
  # testnet run builds no debug runner.
  if [ "$IMAGE_FLAVOR" = default ]; then
    cp "$out/runner-dev-debugimport" "$out/.runner-debugimport.$$"
    mv -f "$out/.runner-debugimport.$$" "$out/runner-debugimport"
  fi
  # The one runner that held every platform is gone: do not leave a stale one
  # that an image build could pick up.
  if [ -e "$out/runner" ]; then
    rm -f "$out/runner"
    log "$arch: removed the old all-platform runner (use runner-azure, runner-aws, runner-gcp or runner-dev)"
  fi
  (cd "$ROOT/platform-aws" && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$(goarch_of "$arch")" \
    go build -trimpath -buildvcs=false -tags platform_aws -ldflags "-s -w -buildid=" -o "$out/hostagent" ./cmd/hostagent)
  (cd "$ROOT/platform-aws" && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$(goarch_of "$arch")" \
    go build -trimpath -buildvcs=false -tags platform_aws -ldflags "-s -w -buildid=" -o "$out/forwarder" ./cmd/forwarder)
  (cd "$ROOT/platform-aws" && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$(goarch_of "$arch")" \
    go build -trimpath -buildvcs=false -tags platform_aws -ldflags "-s -w -buildid=" -o "$out/udprelay" ./cmd/udprelay)
  # setup-tool: makes and checks the signers' setups (the deploy scripts).
  (cd "$ROOT/signer-admin" && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$(goarch_of "$arch")" \
    go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o "$out/setup-tool" ./cmd/setup-tool)
  # The overlay's own programs, into the same folder.
  if [ -n "$OVERLAY_DIR" ]; then
    devnet_hook build_tools "$arch" "$out"
  fi
  for tool in hostagent forwarder udprelay setup-tool; do
    check_bin "$out/$tool" "$arch"
    log "$arch $tool: $(stat -c %s "$out/$tool") bytes, sha256 $(sha256sum "$out/$tool" | cut -c1-16)..., $(file -b "$out/$tool")"
  done
  # Keep redistribution notices beside every binary, including the legacy alias.
  license_bins=()
  for name in "${RUNNER_BINS[@]}" "${RUNNER_DKG_BINS[@]}" hostagent forwarder udprelay setup-tool; do
    license_bins+=("$out/$name")
  done
  [ "$IMAGE_FLAVOR" != default ] || license_bins+=("$out/runner-debugimport")
  python3 "$ROOT/scripts/bundle-licenses.py" "${license_bins[@]}"
done

# A runner built without a platform tag must refuse to start, whatever the flags.
notag="$(mktemp)"
trap 'rm -f "$notag"' EXIT
(cd "$ROOT/tee-signer" && CGO_ENABLED=1 CC="$(cc_for "$HOST_ARCH")" go build -trimpath -buildvcs=false -o "$notag" .)
if msg="$("$notag" -platform dev 2>&1)"; then
  echo "a runner built without a platform tag started" >&2
  exit 1
fi
case "$msg" in
  *"no platform built in"*) log "a runner built without a platform tag refuses to start: ${msg%%$'\n'*}" ;;
  *) echo "a runner built without a platform tag stopped with an unclear message: $msg" >&2; exit 1 ;;
esac

# The tags and linked modules of the binaries just built.
bash "$ROOT/scripts/check-deps.sh" "${archs[@]}"
