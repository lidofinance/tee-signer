#!/usr/bin/env bash
# Tests of the release tools on made-up inputs in a temporary folder. No
# Docker and no network: where a script calls docker or az, a stub on PATH
# answers.
#
#   release/release-test.sh [SECTION...]   (default: every section)
#
# Sections:
#   measurements  release/measurements.py and release/image-variant.py
#   lane          release/build.sh fetch, and the checks at the start of
#                 release/release-build.sh
#   compare       release/compare.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }
# expect NAME 0|1 CMD...: CMD exits zero (0) or non-zero (1).
expect() {
  local name="$1" want="$2" rc=0
  shift 2
  "$@" >"$TMP/out" 2>&1 || rc=$?
  if { [ "$want" = 0 ] && [ "$rc" = 0 ]; } || { [ "$want" = 1 ] && [ "$rc" != 0 ]; }; then
    ok "$name"
  else
    bad "$name (exit $rc): $(tail -n 3 "$TMP/out")"
  fi
}
# hex N SEED: N made-up hex digits.
hex() { local s="" i=0; while [ ${#s} -lt "$1" ]; do s="$s$(printf '%s-%s' "$2" "$i" | sha256sum | cut -c1-64)"; i=$((i + 1)); done; echo "${s:0:$1}"; }

COMMIT="$(hex 40 commit)"

# fingerprints FILE [NAME VALUE]...: a made-up fingerprints file of a prod
# mainnet lane; each NAME VALUE pair replaces that line, VALUE - drops it.
fingerprints() {
  local f="$1" name
  shift
  {
    echo "# generic images, built 2026-01-01T00:00:00Z from ${COMMIT:0:8}"
    echo "variant prod"
    echo "commit $COMMIT"
    echo "chain mainnet"
    for name in PCR0 PCR1 PCR2; do echo "nitro.$name $(hex 96 "$name")"; done
    for name in nitro.runner parent.hostagent parent.forwarder parent.udprelay azure.runner gcp.runner; do echo "$name $(hex 64 "$name")"; done
    echo "azure.image sha256:$(hex 64 azure.image)"
    echo "azure.cce_policy ${CCE:-$(hex 64 cce)}"
    echo "gcp.image ${GCP_DIGEST:-sha256:$(hex 64 gcp.image)}"
  } >"$f"
  while [ $# -ge 2 ]; do
    sed -i "/^$1 /d" "$f"
    [ "$2" = - ] || echo "$1 $2" >>"$f"
    shift 2
  done
}

# oci_tar FILE LOG_REDIRECT: a made-up OCI archive with one manifest whose
# config has that label; prints the manifest digest.
oci_tar() {
  python3 -I - "$1" "$2" <<'EOF'
import hashlib, io, json, sys, tarfile
out, redirect = sys.argv[1], sys.argv[2]
blobs = {}
def add(obj):
    data = json.dumps(obj).encode()
    d = hashlib.sha256(data).hexdigest()
    blobs[d] = data
    return "sha256:" + d
cfg = add({"config": {"Labels": {"tee.launch_policy.log_redirect": redirect}}})
man = add({"schemaVersion": 2, "config": {"digest": cfg}, "layers": []})
index = json.dumps({"schemaVersion": 2, "manifests": [{"digest": man}]}).encode()
with tarfile.open(out, "w") as t:
    for name, data in [("index.json", index)] + [("blobs/sha256/" + d, b) for d, b in blobs.items()]:
        i = tarfile.TarInfo(name)
        i.size = len(data)
        t.addfile(i, io.BytesIO(data))
print(man)
EOF
}

t_measurements() {
  local d="$TMP/m" m="$HERE/measurements.py" iv="$HERE/image-variant.py"
  mkdir -p "$d"
  local args=(--tag v0.1.0 --commit "$COMMIT" --chain mainnet --variant prod)
  fingerprints "$d/good.txt"
  expect "measurements: a prod file with matching arguments" 0 python3 -I "$m" "${args[@]}" "$d/good.txt"
  grep -q '"variant": "prod"' "$TMP/out" || bad "measurements: output names the variant"
  fingerprints "$d/old.txt" variant - commit - chain -
  expect "measurements: refuses a file without variant, commit and chain lines" 1 python3 -I "$m" "${args[@]}" "$d/old.txt"
  fingerprints "$d/test.txt" variant test
  expect "measurements: refuses --variant prod for a test lane" 1 python3 -I "$m" "${args[@]}" "$d/test.txt"
  fingerprints "$d/commit.txt" commit "$(hex 40 other)"
  expect "measurements: refuses a --commit the lane was not built from" 1 python3 -I "$m" "${args[@]}" "$d/commit.txt"
  fingerprints "$d/chain.txt" chain hoodi
  expect "measurements: refuses a --chain the lane was not built for" 1 python3 -I "$m" "${args[@]}" "$d/chain.txt"
  fingerprints "$d/runner.txt" nitro.runner not-a-hash
  expect "measurements: refuses a runner value that is not 64 hex" 1 python3 -I "$m" "${args[@]}" "$d/runner.txt"

  # The built images against the variant.
  local never always stdio_off stdio_on
  never="$(oci_tar "$d/never.tar" never)"
  always="$(oci_tar "$d/always.tar" always)"
  stdio_off="$d/off.rego" stdio_on="$d/on.rego"
  printf 'containers := [{"allow_elevated":false,"allow_stdio_access":false},{"allow_stdio_access":false}]\n' >"$stdio_off"
  printf 'containers := [{"allow_elevated":false,"allow_stdio_access":true},{"allow_stdio_access":true}]\n' >"$stdio_on"
  local off_h on_h
  off_h="$(sha256sum <"$stdio_off" | cut -c1-64)" on_h="$(sha256sum <"$stdio_on" | cut -c1-64)"
  CCE="$off_h" GCP_DIGEST="$never" fingerprints "$d/prod.txt"
  expect "image-variant: prod images pass as prod" 0 python3 -I "$iv" prod "$d/prod.txt" "$d/never.tar" "$stdio_off" "$stdio_off"
  CCE="$off_h" GCP_DIGEST="$always" fingerprints "$d/prod-gcp-always.txt"
  expect "image-variant: refuses a GCP image with log_redirect always as prod" 1 python3 -I "$iv" prod "$d/prod-gcp-always.txt" "$d/always.tar" "$stdio_off"
  CCE="$on_h" GCP_DIGEST="$never" fingerprints "$d/prod-stdio-on.txt"
  expect "image-variant: refuses an Azure policy with stdio on as prod" 1 python3 -I "$iv" prod "$d/prod-stdio-on.txt" "$d/never.tar" "$stdio_on"
  CCE="$on_h" GCP_DIGEST="$always" fingerprints "$d/test-images.txt" variant test
  expect "image-variant: test images pass as test" 0 python3 -I "$iv" test "$d/test-images.txt" "$d/always.tar" "$stdio_on"
  expect "image-variant: refuses test images as prod" 1 python3 -I "$iv" prod "$d/test-images.txt" "$d/always.tar" "$stdio_on"
  expect "image-variant: refuses a policy file that is not the measured one" 1 python3 -I "$iv" prod "$d/prod.txt" "$d/never.tar" "$stdio_on"
  expect "image-variant: refuses an archive without the measured manifest" 1 python3 -I "$iv" prod "$d/prod.txt" "$d/always.tar" "$stdio_off"
  expect "image-variant: refuses a call without an Azure policy" 1 python3 -I "$iv" prod "$d/prod.txt" "$d/never.tar"
}

# The start of release-build.sh in a made-up repo (scripts/common.sh and
# release/ of this tree), with stubs for docker and az. The docker stub
# logs each call, answers image inspect with FAKE_ID and fails docker run
# (exit 97), so a lane that gets past its checks stops at its first run.
t_lane() {
  local d="$TMP/lane" stub="$TMP/lane-bin" id other
  id="sha256:$(hex 64 builder)" other="sha256:$(hex 64 other)"
  mkdir -p "$stub"
  cat >"$stub/docker" <<'EOF'
#!/bin/sh
echo "$*" >>"$DOCKER_LOG"
case "$1 $2" in
  "image inspect") echo "$FAKE_ID" ;;
  "buildx build") ;;
  *) exit 97 ;;
esac
EOF
  printf '#!/bin/sh\necho 2.3.0\n' >"$stub/az"
  # A go stub for release/build.sh: logs the module folder and the arguments.
  # shellcheck disable=SC2016 # expanded by the stub, not here
  printf '#!/bin/sh\necho "${PWD##*/} $*" >>"$GO_LOG"\n' >"$stub/go"
  chmod +x "$stub"/*

  # release/build.sh fetch verifies every module it fetches.
  mkdir -p "$d/fetch/scripts" "$d/fetch/release" "$d/fetch/tee-signer" "$d/fetch/platform-aws" "$d/fetch/signer-admin"
  cp "$HERE/../scripts/common.sh" "$d/fetch/scripts/"
  cp "$HERE/build.sh" "$d/fetch/release/"
  : >"$TMP/go.log"
  (cd "$d/fetch" && GO_LOG="$TMP/go.log" PATH="$stub:$PATH" bash release/build.sh fetch) >/dev/null 2>&1 || bad "build.sh fetch with the go stub"
  local m
  for m in tee-signer platform-aws signer-admin; do
    if grep -qx "$m mod verify" "$TMP/go.log"; then ok "build.sh fetch: go mod verify in $m"; else bad "build.sh fetch: no go mod verify in $m"; fi
  done

  # repo: a fresh made-up checkout.
  repo() {
    rm -rf "$d/repo"
    mkdir -p "$d/repo/scripts" "$d/repo/release"
    cp "$HERE/../scripts/common.sh" "$d/repo/scripts/"
    cp "$HERE"/*.sh "$HERE"/*.py "$HERE/builder.Dockerfile" "$d/repo/release/"
    cp "$HERE/../.gitignore" "$d/repo/"
    git -C "$d/repo" init -q
    git -C "$d/repo" add -A
    git -C "$d/repo" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m t
  }
  # lane NAME WANT [VAR=VALUE...]: runs the lane with those variables. WANT
  # run: it gets to its first docker run; stop: it fails before any docker
  # run (it may build or inspect the builder image).
  lane() {
    local name="$1" want="$2" rc=0 ran=no
    shift 2
    : >"$TMP/docker.log"
    (cd "$d/repo" && env DOCKER_LOG="$TMP/docker.log" FAKE_ID="$id" PATH="$stub:$PATH" "$@" \
      bash release/release-build.sh "$d/dist") >"$TMP/out" 2>&1 || rc=$?
    ! grep -q '^run ' "$TMP/docker.log" || ran=yes
    if { [ "$want" = run ] && [ "$rc" = 97 ] && [ "$ran" = yes ]; } ||
      { [ "$want" = stop ] && [ "$rc" != 0 ] && [ "$ran" = no ]; }; then
      ok "$name"
    else
      bad "$name (exit $rc, docker run: $ran): $(tail -n 2 "$TMP/out")"
    fi
  }

  repo
  mkdir -p "$d/repo/build/aarch64/lib" && : >"$d/repo/build/aarch64/lib/libblst.a"
  lane "release-build: refuses a tree with a build/ folder" stop
  [ ! -s "$TMP/docker.log" ] || bad "release-build: called docker before the tree check"
  repo
  mkdir -p "$d/repo/signer-core/build" && : >"$d/repo/signer-core/build/x.o"
  lane "release-build: refuses a tree with other ignored files" stop
  repo
  mkdir -p "$d/repo/logs" && : >"$d/repo/logs/old.log"
  lane "release-build: a fresh tree with only logs/ gets to the build" run
  repo
  lane "release-build: refuses RELEASE_BUILDER_IMAGE without RELEASE_BUILDER_ID" stop RELEASE_BUILDER_IMAGE=builder:local
  lane "release-build: refuses a RELEASE_BUILDER_IMAGE of another id" stop RELEASE_BUILDER_IMAGE=builder:local RELEASE_BUILDER_ID="$other"
  lane "release-build: takes a RELEASE_BUILDER_IMAGE of the pinned id" run RELEASE_BUILDER_IMAGE=builder:local RELEASE_BUILDER_ID="$id"
  if grep -q "$id" "$TMP/out"; then ok "release-build: prints the builder image id"; else bad "release-build: prints the builder image id"; fi
  lane "release-build: refuses a Dockerfile build of another id than RELEASE_BUILDER_ID" stop RELEASE_BUILDER_ID="$other"
}

# release/compare.sh on made-up lane folders.
t_compare() {
  local d="$TMP/cmp" c="$HERE/compare.sh"
  # lane_dir DIR [PCR0]: a made-up lane folder with its SHA256SUMS.
  lane_dir() {
    rm -rf "$1"
    mkdir -p "$1"
    fingerprints "$1/fingerprints-mainnet.txt"
    echo runner >"$1/runner-gcp-mainnet-linux-amd64"
    echo eif "$1" >"$1/runner-aws-mainnet-aarch64.eif"
    echo "kernel x image sha256:$(hex 64 "$1")" >"$1/runner-aws-mainnet-aarch64.inputs.txt"
    printf '{"Measurements":{"PCR0":"%s","PCR1":"%s","PCR2":"%s"}}\n' "${2:-$(hex 96 p0)}" "$(hex 96 p1)" "$(hex 96 p2)" \
      >"$1/runner-aws-mainnet-aarch64.build-enclave.json"
    sums "$1"
  }
  sums() { (cd "$1" && rm -f SHA256SUMS && sha256sum -- * |LC_ALL=C sort -k2 >../.sums && mv ../.sums SHA256SUMS); }

  lane_dir "$d/a"
  lane_dir "$d/b"
  expect "compare: two equal lanes are identical" 0 bash "$c" "$d/a" "$d/b"
  echo changed >"$d/b/runner-gcp-mainnet-linux-amd64"
  expect "compare: refuses a file changed after SHA256SUMS" 1 bash "$c" "$d/a" "$d/b"
  lane_dir "$d/b"
  echo extra >"$d/b/extra.txt"
  expect "compare: refuses a file that SHA256SUMS does not list" 1 bash "$c" "$d/a" "$d/b"
  lane_dir "$d/a" null
  lane_dir "$d/b" null
  expect "compare: refuses a PCR that is not 96 hex" 1 bash "$c" "$d/a" "$d/b"
  lane_dir "$d/a"
  lane_dir "$d/b"
  echo '{}' >"$d/a/runner-aws-mainnet-aarch64.build-enclave.json"
  echo '{}' >"$d/b/runner-aws-mainnet-aarch64.build-enclave.json"
  sums "$d/a"
  sums "$d/b"
  expect "compare: refuses a build-enclave.json without PCRs" 1 bash "$c" "$d/a" "$d/b"
  rm -rf "$d/a" "$d/b"
  mkdir -p "$d/a" "$d/b"
  expect "compare: refuses two empty folders" 1 bash "$c" "$d/a" "$d/b"
  if grep -q '^same' "$TMP/out"; then bad "compare: printed same for an empty folder"; fi
}

sections=("$@")
[ ${#sections[@]} -gt 0 ] || sections=(measurements lane compare)
for s in "${sections[@]}"; do
  case "$s" in
    measurements) t_measurements ;;
    lane) t_lane ;;
    compare) t_compare ;;
    *) echo "release-test: unknown section $s" >&2; exit 2 ;;
  esac
done
[ "$fails" = 0 ] || { echo "release-test: $fails failed" >&2; exit 1; }
echo "release-test: all passed"
