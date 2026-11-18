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
# refuses NAME PATTERN CMD...: CMD exits non-zero and its output matches
# the extended regex PATTERN, so it refused for the reason NAME gives.
refuses() {
  local name="$1" pat="$2" rc=0
  shift 2
  "$@" >"$TMP/out" 2>&1 || rc=$?
  if [ "$rc" != 0 ] && grep -qE -- "$pat" "$TMP/out"; then
    ok "$name"
  else
    bad "$name (exit $rc, want /$pat/): $(tail -n 3 "$TMP/out")"
  fi
}
# says NAME PATTERN: the last command's output matches PATTERN.
says() { if grep -qE -- "$2" "$TMP/out"; then ok "$1"; else bad "$1 (want /$2/): $(tail -n 2 "$TMP/out")"; fi; }
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
  refuses "measurements: refuses a file without variant, commit and chain lines" "no (variant|commit|chain) line" python3 -I "$m" "${args[@]}" "$d/old.txt"
  fingerprints "$d/test.txt" variant test
  refuses "measurements: refuses --variant prod for a test lane" "--variant is 'prod', the lane was built with 'test'" python3 -I "$m" "${args[@]}" "$d/test.txt"
  fingerprints "$d/commit.txt" commit "$(hex 40 other)"
  refuses "measurements: refuses a --commit the lane was not built from" "--commit is " python3 -I "$m" "${args[@]}" "$d/commit.txt"
  fingerprints "$d/chain.txt" chain hoodi
  refuses "measurements: refuses a --chain the lane was not built for" "--chain is 'mainnet', the lane was built with 'hoodi'" python3 -I "$m" "${args[@]}" "$d/chain.txt"
  fingerprints "$d/runner.txt" nitro.runner not-a-hash
  refuses "measurements: refuses a runner value that is not 64 hex" "nitro.runner is missing or not 64 hex" python3 -I "$m" "${args[@]}" "$d/runner.txt"

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
  refuses "image-variant: refuses a GCP image with log_redirect always as prod" "GCP image has log_redirect 'always'" python3 -I "$iv" prod "$d/prod-gcp-always.txt" "$d/always.tar" "$stdio_off"
  CCE="$on_h" GCP_DIGEST="$never" fingerprints "$d/prod-stdio-on.txt"
  refuses "image-variant: refuses an Azure policy with stdio on as prod" "has allow_stdio_access" python3 -I "$iv" prod "$d/prod-stdio-on.txt" "$d/never.tar" "$stdio_on"
  CCE="$on_h" GCP_DIGEST="$always" fingerprints "$d/test-images.txt" variant test
  expect "image-variant: test images pass as test" 0 python3 -I "$iv" test "$d/test-images.txt" "$d/always.tar" "$stdio_on"
  refuses "image-variant: refuses test images as prod" "GCP image has log_redirect 'always'" python3 -I "$iv" prod "$d/test-images.txt" "$d/always.tar" "$stdio_on"
  refuses "image-variant: refuses a policy file that is not the measured one" "is not the measured CCE policy" python3 -I "$iv" prod "$d/prod.txt" "$d/never.tar" "$stdio_on"
  refuses "image-variant: refuses an archive without the measured manifest" "has no manifest" python3 -I "$iv" prod "$d/prod.txt" "$d/always.tar" "$stdio_off"
  refuses "image-variant: refuses a call without an Azure policy" "usage: image-variant.py" python3 -I "$iv" prod "$d/prod.txt" "$d/never.tar"
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
  "buildx version") echo "github.com/docker/buildx v0.30.0" ;;
  "info "*) echo "$FAKE_DRIVER_STATUS" ;;
  "run "*)
    [ -n "$FAKE_RUN_OK" ] || exit 97
    case "$*" in
      *"cat /builder-packages.txt"*) echo "gcc 12.2.0-14 amd64" ;;
      *sbom.py*)
        # -v DIST:/dist, and the SBOM's base name after "_". Docker reads a
        # -v source that is not an absolute path as a volume name, so then
        # nothing reaches the folder.
        dist="" prev="" base="" next=""
        for a in "$@"; do
          [ "$prev" != -v ] || case "$a" in *:/dist) dist="${a%:/dist}" ;; esac
          [ "$next" != 1 ] || { base="$a"; next=2; }
          [ "$a" != _ ] || [ -n "$next" ] || next=1
          prev="$a"
        done
        case "$dist" in
          /*) if [ -n "$FAKE_SBOM_EMPTY" ]; then : >"$dist/$base.spdx.json"; else echo '{}' >"$dist/$base.spdx.json"; fi ;;
        esac ;;
    esac ;;
  *) exit 97 ;;
esac
EOF
  printf '#!/bin/sh\necho 2.3.0\n' >"$stub/az"
  # A go stub for release/build.sh: logs the module folder and the arguments.
  # shellcheck disable=SC2016 # expanded by the stub, not here
  printf '#!/bin/sh\necho "${PWD##*/} $*" >>"$GO_LOG"\n' >"$stub/go"
  chmod +x "$stub"/*

  # The host programs the lane checks for, as stubs, so the tests do not
  # depend on what this host has installed. unshare fails as on a stock
  # Ubuntu 24.04 when FAKE_UNSHARE_FAIL is set.
  # The lane runs as on an x86_64 host whatever this host is, so the
  # cross nm is always the aarch64 one.
  local hstub="$TMP/lane-host" cross_nm=aarch64-linux-gnu-nm p
  mkdir -p "$hstub"
  for p in nm aarch64-linux-gnu-nm x86_64-linux-gnu-nm readelf file cc jq ip; do
    printf '#!/bin/sh\nexit 0\n' >"$hstub/$p"
  done
  cat >"$hstub/uname" <<'EOF'
#!/bin/sh
if [ "$1" = -m ] && [ -n "$FAKE_UNAME" ]; then echo "$FAKE_UNAME"; exit 0; fi
for u in /usr/bin/uname /bin/uname; do [ -x "$u" ] && exec "$u" "$@"; done
exit 1
EOF
  cat >"$hstub/unshare" <<'EOF'
#!/bin/sh
[ -z "$FAKE_UNSHARE_FAIL" ] || { echo "unshare: write failed /proc/self/uid_map: Operation not permitted" >&2; exit 1; }
exit 0
EOF
  chmod +x "$hstub"/*
  # hostbin: links to every program on PATH (the first of a name wins) and
  # to the stubs, in one folder that is the lanes' whole PATH. A test hides
  # a program by moving its link out (lane's hide).
  local hostbin="$TMP/hostbin" dir dirs i hide="" cwd="" dist=""
  mkdir -p "$hostbin" "$TMP/hidden"
  IFS=: read -ra dirs <<<"$PATH"
  for ((i = ${#dirs[@]} - 1; i >= 0; i--)); do
    dir="${dirs[$i]}"
    case "$dir" in /mnt/* | "") continue ;; esac
    [ -d "$dir" ] || continue
    find "$dir" -maxdepth 1 \( -type f -o -type l \) -exec ln -sf -t "$hostbin" {} +
  done
  ln -sf -t "$hostbin" "$hstub"/* "$stub"/*

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

  # repo [full]: a fresh made-up checkout. full adds stubs for the steps
  # after the checks (fetch, images, image-variant.py), which make up the
  # outputs the lane copies, so the lane runs to its end.
  repo() {
    rm -rf "$d/repo"
    mkdir -p "$d/repo/scripts" "$d/repo/release"
    cp "$HERE/../scripts/common.sh" "$d/repo/scripts/"
    cp "$HERE"/*.sh "$HERE"/*.py "$HERE/builder.Dockerfile" "$d/repo/release/"
    cp "$HERE/../.gitignore" "$d/repo/"
    if [ "${1:-}" = full ]; then
      mkdir -p "$d/repo/platform-azure/deploy" "$d/repo/sub"
      : >"$d/repo/sub/.keep"
      printf '#!/bin/sh\nexit 0\n' >"$d/repo/scripts/nitro-cli-image.sh"
      printf 'import sys\nsys.exit(0)\n' >"$d/repo/release/image-variant.py"
      # shellcheck disable=SC2016 # expanded when the lane sources it
      printf 'OUT="$1/build/azure"\n' >"$d/repo/platform-azure/deploy/common.sh"
      cat >"$d/repo/scripts/generic-images.sh" <<'EOF'
#!/usr/bin/env bash
# Stub of "generic-images.sh build OUT": made-up outputs.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
. "$ROOT/scripts/common.sh"
s="$(image_suffix)"
mkdir -p "$2" "$BUILD/nitro$s" "$BUILD/gcp$s" "$BUILD/azure/signer-x"
echo "nitro.PCR0 00" >"$2/fingerprints.txt"
for spec in "aarch64:runner-aws$s" "x86_64:runner-azure$s" "x86_64:runner-gcp$s" \
  aarch64:hostagent aarch64:forwarder aarch64:udprelay x86_64:setup-tool aarch64:setup-tool; do
  a="${spec%%:*}" n="${spec#*:}"
  mkdir -p "$BUILD/$a/bin/$n.licenses"
  echo "$a $n" >"$BUILD/$a/bin/$n"
  echo licence >"$BUILD/$a/bin/$n.licenses/LICENSE"
done
for f in runner-aarch64.eif build-enclave-aarch64.json inputs-aarch64.txt; do echo "$f" >"$BUILD/nitro$s/$f"; done
for f in runner.oci.tar runner.inputs; do echo "gcp $f" >"$BUILD/gcp$s/$f"; echo "azure $f" >"$BUILD/azure/$f"; done
echo policy >"$BUILD/azure/signer-x/policy.rego"
EOF
    fi
    git -C "$d/repo" init -q
    git -C "$d/repo" add -A
    git -C "$d/repo" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m t
  }
  # lane NAME WANT [VAR=VALUE...]: runs the lane with those variables. WANT
  # run: it gets to its first docker run; stop: it fails before any docker
  # run (it may build or inspect the builder image); end: it ends with exit
  # 0 (a repo full with FAKE_RUN_OK=1); late: it fails with exit 1 after a
  # docker run. The programs named in hide are not on its PATH. The lane
  # runs in the folder cwd (default the repo) with the DIST argument dist
  # (default $d/dist, removed before each run).
  lane() {
    local name="$1" want="$2" rc=0 ran=no p
    shift 2
    : >"$TMP/docker.log"
    rm -rf "$d/dist"
    for p in $hide; do mv "$hostbin/$p" "$TMP/hidden/"; done
    (cd "${cwd:-$d/repo}" && env -u SIGNER_BUILDER_IMAGE DOCKER_LOG="$TMP/docker.log" FAKE_ID="$id" \
      FAKE_DRIVER_STATUS='[["driver-type","io.containerd.snapshotter.v1"]]' FAKE_UNSHARE_FAIL= FAKE_UNAME=x86_64 \
      FAKE_RUN_OK= FAKE_SBOM_EMPTY= PATH="$hostbin" "$@" \
      bash "$d/repo/release/release-build.sh" "${dist:-$d/dist}") >"$TMP/out" 2>&1 || rc=$?
    for p in $hide; do mv "$TMP/hidden/$p" "$hostbin/"; done
    hide="" cwd="" dist=""
    ! grep -q '^run ' "$TMP/docker.log" || ran=yes
    if { [ "$want" = run ] && [ "$rc" = 97 ] && [ "$ran" = yes ]; } ||
      { [ "$want" = stop ] && [ "$rc" != 0 ] && [ "$ran" = no ]; } ||
      { [ "$want" = end ] && [ "$rc" = 0 ]; } ||
      { [ "$want" = late ] && [ "$rc" = 1 ] && [ "$ran" = yes ]; }; then
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

  # A build/ left by an earlier lane holds the read-only Go module cache.
  repo
  mkdir -p "$d/repo/build/gomod" && : >"$d/repo/build/gomod/x"
  lane "release-build: refuses a build/ left by an earlier lane" stop
  if grep -qF 'chmod -R u+w build && rm -rf build' "$TMP/out"; then ok "release-build: says how to remove build/"; else bad "release-build: says how to remove build/: $(tail -n 1 "$TMP/out")"; fi
  # The host checks, before any long step.
  repo
  hide="$cross_nm"
  lane "release-build: refuses a host without $cross_nm" stop
  if grep -q "$cross_nm.*binutils-" "$TMP/out"; then ok "release-build: names the package of $cross_nm"; else bad "release-build: names the package of $cross_nm: $(tail -n 1 "$TMP/out")"; fi
  repo
  lane "release-build: refuses a host where unshare -rn fails" stop FAKE_UNSHARE_FAIL=1
  if grep -q 'kernel.apparmor_restrict_unprivileged_userns' "$TMP/out"; then ok "release-build: names the userns sysctl"; else bad "release-build: names the userns sysctl: $(tail -n 1 "$TMP/out")"; fi
  repo
  lane "release-build: refuses a docker without the containerd image store" stop FAKE_DRIVER_STATUS='[["Backing Filesystem","extfs"]]'
  if grep -q 'containerd image store' "$TMP/out"; then ok "release-build: names the containerd image store"; else bad "release-build: names the containerd image store: $(tail -n 1 "$TMP/out")"; fi
  repo
  lane "release-build: refuses a mainnet test lane" stop CHAIN=mainnet IMAGE_VARIANT=test
  says "release-build: says mainnet builds are prod only" "mainnet builds are prod only"
  repo
  lane "release-build: takes a hoodi test lane" run CHAIN=hoodi IMAGE_VARIANT=test
  lane "release-build: refuses a host that is not x86_64" stop FAKE_UNAME=aarch64
  says "release-build: says the lane needs an x86_64 host" "build host must be x86_64 \(arm64 images are cross-built\)"

  # The tree check must see every change to a tracked file.
  local bit
  for bit in skip-worktree assume-unchanged; do
    repo
    git -C "$d/repo" update-index "--$bit" release/compare.sh
    echo "# changed" >>"$d/repo/release/compare.sh"
    lane "release-build: refuses a changed file with the $bit bit" stop
    says "release-build: names the $bit bit" "skip-worktree or assume-unchanged"
  done
  repo
  echo broken >"$d/repo/.git/index"
  lane "release-build: refuses a tree where git status fails" stop
  says "release-build: says git status failed" "git status failed"

  # DIST: never removes an earlier output, and is taken relative to the
  # caller's folder.
  repo
  mkdir -p "$d/old-dist" && echo old >"$d/old-dist/SHA256SUMS"
  dist="$d/old-dist"
  lane "release-build: refuses a DIST that is not empty" stop
  says "release-build: says to give a new or empty DIST" "not empty"
  [ -s "$d/old-dist/SHA256SUMS" ] || bad "release-build: removed the earlier output in DIST"
  repo full
  lane "release-build: a full lane with stubs gets to its end" end FAKE_RUN_OK=1
  if [ "$(grep -c '\.spdx\.json$' "$d/dist/SHA256SUMS" 2>/dev/null)" = 8 ]; then ok "release-build: DIST lists 8 SBOMs"; else bad "release-build: DIST lists 8 SBOMs: $(tail -n 2 "$TMP/out")"; fi
  repo full
  rm -rf "$d/empty-dist" && mkdir -p "$d/empty-dist"
  dist="$d/empty-dist"
  lane "release-build: takes an empty existing DIST" end FAKE_RUN_OK=1
  repo full
  cwd="$d/repo/sub" dist=out
  lane "release-build: a relative DIST is relative to the caller's folder" end FAKE_RUN_OK=1
  if [ "$(grep -c '\.spdx\.json$' "$d/repo/sub/out/SHA256SUMS" 2>/dev/null)" = 8 ]; then ok "release-build: the SBOMs of a relative DIST are in it"; else bad "release-build: the SBOMs of a relative DIST are in it: no SHA256SUMS with 8 SBOMs in $d/repo/sub/out"; fi
  repo full
  lane "release-build: refuses an empty SBOM" late FAKE_RUN_OK=1 FAKE_SBOM_EMPTY=1
  says "release-build: names the missing SBOM" "SBOM .*\.spdx\.json"

  # nitro-eif.sh shows why the runner build failed: a made-up repo whose
  # scripts/build-runner.sh fails the way a missing host program does.
  local n="$d/nitro"
  rm -rf "$n"
  mkdir -p "$n/scripts"
  cp "$HERE/../scripts/common.sh" "$HERE/../scripts/nitro-eif.sh" "$n/scripts/"
  printf '#!/bin/sh\nexit 0\n' >"$n/scripts/fetch.sh"
  printf '#!/bin/sh\necho "build-core.sh: line 118: aarch64-linux-gnu-nm: command not found" >&2\nexit 127\n' >"$n/scripts/build-runner.sh"
  expect "nitro-eif: fails when the runner build fails" 1 env -u SIGNER_BUILDER_IMAGE DOCKER_LOG="$TMP/docker.log" FAKE_ID="$id" \
    PATH="$hostbin" NITRO_CLI_REUSE=1 bash "$n/scripts/nitro-eif.sh" aarch64
  if grep -q 'aarch64-linux-gnu-nm: command not found' "$TMP/out"; then ok "nitro-eif: prints the end of the runner build's log"; else bad "nitro-eif: prints the end of the runner build's log: $(tail -n 2 "$TMP/out")"; fi
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
  refuses "compare: refuses a file changed after SHA256SUMS" "does not match its SHA256SUMS" bash "$c" "$d/a" "$d/b"
  lane_dir "$d/b"
  echo extra >"$d/b/extra.txt"
  refuses "compare: refuses a file that SHA256SUMS does not list" "are not the ones its SHA256SUMS lists" bash "$c" "$d/a" "$d/b"
  lane_dir "$d/b"
  echo other >"$d/b/runner-gcp-mainnet-linux-amd64"
  sums "$d/b"
  refuses "compare: refuses two self-consistent lanes with another runner" "the two lanes differ" bash "$c" "$d/a" "$d/b"
  says "compare: names the runner that differs" "^DIFF  runner-gcp-mainnet-linux-amd64 "
  lane_dir "$d/b" "$(hex 96 other)"
  refuses "compare: refuses two self-consistent lanes with another PCR0" "the two lanes differ" bash "$c" "$d/a" "$d/b"
  says "compare: names the PCR that differs" "^DIFF  runner-aws-mainnet-aarch64.build-enclave.json PCR0"
  lane_dir "$d/a" null
  lane_dir "$d/b" null
  refuses "compare: refuses a PCR that is not 96 hex" "PCR0 is not 96 hex digits" bash "$c" "$d/a" "$d/b"
  lane_dir "$d/a"
  lane_dir "$d/b"
  echo '{}' >"$d/a/runner-aws-mainnet-aarch64.build-enclave.json"
  echo '{}' >"$d/b/runner-aws-mainnet-aarch64.build-enclave.json"
  sums "$d/a"
  sums "$d/b"
  refuses "compare: refuses a build-enclave.json without PCRs" "PCR0 is not 96 hex digits: 'null'" bash "$c" "$d/a" "$d/b"
  rm -rf "$d/a" "$d/b"
  mkdir -p "$d/a" "$d/b"
  refuses "compare: refuses two empty folders" "no .*/SHA256SUMS" bash "$c" "$d/a" "$d/b"
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
