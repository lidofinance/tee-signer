#!/usr/bin/env bash
# Checks of the two build variants (DVT in scripts/common.sh): the default
# build holds no dv_share code, the dvt build does, and a dvt runner never
# links against a default core.
#
#   scripts/dvt-test.sh [SECTION...]   (default: every section)
#
# Sections:
#   names   common.sh: runner names, tags and image suffix per variant and
#           chain; DVT other than 0 or 1 is refused
#   core    scripts/build-core.sh with DVT=0 and DVT=1 for this machine:
#           only libsigner_core_dvt.a defines sc_signer_add_validator_group,
#           and build-core.sh's check (check_core_variant) refuses each
#           archive as the other variant
#   runner  a runner-dev of each variant: the default one holds none of the
#           dvt code (the file tee-signer/server/dvshare.go, the functions
#           core.(*Signer).AddValidatorGroup and server.(*Server).dvShare),
#           the dvt one holds all of it
#   link    a dvt runner linked against a default core: the link fails on
#           sc_signer_add_validator_group; a default runner linked against
#           a DVT core: the link fails on sc_core_dvt_marker, defined twice
#   admin   signer-admin of each variant (scripts/build-admin.sh): the
#           default one has none of the dv_share exit commands (dv-indices,
#           dv-exit, dv-exit-post) and refuses them as unknown, the dvt one
#           has all of them
#   go      go vet and the Go tests of the dvt-tagged packages with the tag
#           dvt: signer-core/core, tee-signer and tee-signer/server (with
#           the tags of runner-dev-dvt), under the race detector (RACE=
#           turns it off); then signer-admin's vet and all its tests with
#           the tag dvt, those that drive a dvt dev runner included
#           (SIGNER_ADMIN_DVT_RUNNER; the ones that need a default dev
#           runner skip)
#   ctest   the C suites of the DVT core build (signer-core/scripts/test.sh
#           with DVT=1, no fuzzing: the nightly run fuzzes)
# runner, link, admin and go need the libraries of core; ctest needs the vectors
# (signer-core/scripts/fetch.sh). Without a section: names core runner link.
# make test-dvt runs every section; CI's dvt job runs that.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }
# same NAME GOT WANT
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got '$2', want '$3'"; fi; }
LIB="$BUILD/$HOST_ARCH/lib"

# names_of VAR=VALUE...: what common.sh gives with those variables.
names_of() {
  # shellcheck disable=SC2016 # expanded by the inner bash
  env -u DVT -u CHAIN "$@" bash -c '. "$1"
    printf "release=%s bins=%s suffix=%s variant=%s" "${RUNNER_RELEASE_BINS[*]}" "${RUNNER_BINS[*]}" "$(image_suffix)" "$(variant)"
    for n in "${RUNNER_BINS[@]}"; do printf " %s=%s" "$n" "$(runner_tags "$n")"; done' _ "$ROOT/scripts/common.sh"
}

t_names() {
  same "names: default mainnet" "$(names_of)" \
    "release=runner-azure runner-aws runner-gcp bins=runner-azure runner-aws runner-gcp runner-dev runner-dev-debugimport runner-azure-debugimport runner-aws-debugimport runner-gcp-debugimport suffix= variant=default runner-azure=platform_azure,nts runner-aws=platform_aws,nts runner-gcp=platform_gcp,nts runner-dev=platform_dev runner-dev-debugimport=platform_dev,debugimport runner-azure-debugimport=platform_azure,debugimport,nts runner-aws-debugimport=platform_aws,platform_dev,debugimport,nts runner-gcp-debugimport=platform_gcp,debugimport,nts"
  same "names: DVT=0 is the default" "$(names_of DVT=0)" "$(names_of)"
  same "names: dvt mainnet" "$(names_of DVT=1)" \
    "release=runner-azure-dvt runner-aws-dvt runner-gcp-dvt bins=runner-azure-dvt runner-aws-dvt runner-gcp-dvt runner-dev-dvt suffix=-dvt variant=dvt runner-azure-dvt=platform_azure,nts,dvt runner-aws-dvt=platform_aws,nts,dvt runner-gcp-dvt=platform_gcp,nts,dvt runner-dev-dvt=platform_dev,dvt"
  same "names: dvt hoodi" "$(names_of DVT=1 CHAIN=hoodi)" \
    "release=runner-azure-hoodi-dvt runner-aws-hoodi-dvt runner-gcp-hoodi-dvt bins=runner-azure-hoodi-dvt runner-aws-hoodi-dvt runner-gcp-hoodi-dvt runner-dev-hoodi-dvt suffix=-hoodi-dvt variant=dvt runner-azure-hoodi-dvt=platform_azure,nts,nonprod,chain_hoodi,dvt runner-aws-hoodi-dvt=platform_aws,nts,nonprod,chain_hoodi,dvt runner-gcp-hoodi-dvt=platform_gcp,nts,nonprod,chain_hoodi,dvt runner-dev-hoodi-dvt=platform_dev,nonprod,chain_hoodi,dvt"
  same "names: default hoodi" "$(names_of CHAIN=hoodi)" \
    "release=runner-azure-hoodi runner-aws-hoodi runner-gcp-hoodi bins=runner-azure-hoodi runner-aws-hoodi runner-gcp-hoodi runner-dev-hoodi suffix=-hoodi variant=default runner-azure-hoodi=platform_azure,nts,nonprod,chain_hoodi runner-aws-hoodi=platform_aws,nts,nonprod,chain_hoodi runner-gcp-hoodi=platform_gcp,nts,nonprod,chain_hoodi runner-dev-hoodi=platform_dev,nonprod,chain_hoodi"
  local out rc=0
  out="$(names_of DVT=yes 2>&1)" || rc=$?
  if [ "$rc" != 0 ] && [[ "$out" == *"DVT must be 0 or 1"* ]]; then ok "names: refuses DVT=yes"; else bad "names: refuses DVT=yes (exit $rc): $out"; fi
}

# defines LIB SYMBOL: LIB defines SYMBOL as a function.
defines() { nm --defined-only "$1" | awk '$2 == "T" { print $3 }' | grep -qx "$2"; }

t_core() {
  DVT=0 bash "$ROOT/scripts/build-core.sh" "$HOST_ARCH"
  DVT=1 bash "$ROOT/scripts/build-core.sh" "$HOST_ARCH"
  local f
  for f in libsigner_core.a libsigner_core_dvt.a; do
    [ -f "$LIB/$f" ] || { bad "core: no $LIB/$f"; return; }
  done
  if defines "$LIB/libsigner_core.a" sc_signer_add_validator_group; then
    bad "core: the default core defines sc_signer_add_validator_group"
  else
    ok "core: the default core has no sc_signer_add_validator_group"
  fi
  if defines "$LIB/libsigner_core_dvt.a" sc_signer_add_validator_group; then
    ok "core: the dvt core defines sc_signer_add_validator_group"
  else
    bad "core: the dvt core has no sc_signer_add_validator_group"
  fi
  for f in libsigner_core.a libsigner_core_dvt.a; do
    if defines "$LIB/$f" sc_signer_add_validator; then ok "core: $f defines sc_signer_add_validator"; else bad "core: $f has no sc_signer_add_validator"; fi
  done
  # build-core.sh's own check (common.sh check_core_variant) takes each
  # archive as its variant and refuses it as the other.
  local v out
  for v in default:libsigner_core.a dvt:libsigner_core_dvt.a; do
    if out="$(check_core_variant "$LIB/${v#*:}" "${v%%:*}" nm 2>&1)"; then ok "core: check_core_variant takes ${v#*:} as ${v%%:*}"; else bad "core: check_core_variant refuses ${v#*:} as ${v%%:*}: $out"; fi
  done
  for v in dvt:libsigner_core.a default:libsigner_core_dvt.a; do
    if out="$(check_core_variant "$LIB/${v#*:}" "${v%%:*}" nm 2>&1)"; then bad "core: check_core_variant takes ${v#*:} as ${v%%:*}"; else ok "core: check_core_variant refuses ${v#*:} as ${v%%:*} ($out)"; fi
  done
}

# runner OUT TAGS [VAR=VALUE...]: a runner-dev built with TAGS into OUT.
runner() {
  local out="$1" tags="$2"
  shift 2
  (cd "$ROOT/tee-signer" && env CGO_ENABLED=1 CC="$(cc_for "$HOST_ARCH")" "$@" \
    go build -trimpath -buildvcs=false -tags "$tags" -o "$out" .)
}

t_runner() {
  local out
  runner "$TMP/runner-dev" platform_dev || { bad "runner: the default runner-dev does not build"; return; }
  runner "$TMP/runner-dev-dvt" platform_dev,dvt || { bad "runner: the dvt runner-dev does not build"; return; }
  # dvt_marks (common.sh), the check build-runner.sh runs on every runner.
  if out="$(dvt_marks "$TMP/runner-dev" no 2>&1)"; then ok "runner: the default runner-dev holds none of ${DVT_MARKS[*]}"; else bad "runner: $out"; fi
  if out="$(dvt_marks "$TMP/runner-dev-dvt" yes 2>&1)"; then ok "runner: the dvt runner-dev holds ${DVT_MARKS[*]}"; else bad "runner: $out"; fi
}

t_link() {
  local out rc=0
  [ -f "$LIB/libsigner_core.a" ] || { bad "link: no $LIB/libsigner_core.a (section core builds it)"; return; }
  # A default core under the dvt core's name, found first (CGO_LDFLAGS
  # comes before the package's own -L).
  mkdir -p "$TMP/wrong"
  cp "$LIB/libsigner_core.a" "$TMP/wrong/libsigner_core_dvt.a"
  out="$(runner "$TMP/runner-wrong" platform_dev,dvt CGO_LDFLAGS="-L$TMP/wrong" 2>&1)" || rc=$?
  if [ "$rc" != 0 ] && grep -q "undefined reference to .sc_signer_add_validator_group'" <<<"$out"; then
    ok "link: a dvt runner does not link against a default core (undefined sc_signer_add_validator_group)"
  else
    bad "link: a dvt runner against a default core (exit $rc): $(tail -n 3 <<<"$out")"
  fi
  # The other way: a DVT core under the default core's name. Both the DVT
  # core and the default binding (corelib.go) define sc_core_dvt_marker.
  [ -f "$LIB/libsigner_core_dvt.a" ] || { bad "link: no $LIB/libsigner_core_dvt.a (section core builds it)"; return; }
  rc=0
  cp "$LIB/libsigner_core_dvt.a" "$TMP/wrong/libsigner_core.a"
  out="$(runner "$TMP/runner-wrong-default" platform_dev CGO_LDFLAGS="-L$TMP/wrong" 2>&1)" || rc=$?
  if [ "$rc" != 0 ] && grep -q "multiple definition of .sc_core_dvt_marker'" <<<"$out"; then
    ok "link: a default runner does not link against a DVT core (sc_core_dvt_marker defined twice)"
  else
    bad "link: a default runner against a DVT core (exit $rc): $(tail -n 3 <<<"$out")"
  fi
}

t_go() {
  local tags race="${RACE--race}"
  tags="$(runner_tags runner-dev-dvt)"
  # shellcheck disable=SC2086 # race is one flag or none
  if (cd "$ROOT/signer-core" && go vet -tags dvt ./... && go test $race -count=1 -tags dvt ./core); then
    ok "go: signer-core vet and tests with -tags dvt"
  else
    bad "go: signer-core vet and tests with -tags dvt"
  fi
  # shellcheck disable=SC2086
  if (cd "$ROOT/tee-signer" && go vet -tags "$tags" ./... && go test $race -count=1 -tags "$tags" ./server .); then
    ok "go: tee-signer vet and tests with -tags $tags"
  else
    bad "go: tee-signer vet and tests with -tags $tags"
  fi
  # shellcheck disable=SC2086
  if runner "$TMP/runner-dev-dvt-admin" "$tags" &&
    (cd "$ROOT/signer-admin" && go vet -tags dvt ./... && SIGNER_ADMIN_DVT_RUNNER="$TMP/runner-dev-dvt-admin" \
      go test $race -count=1 -v -tags dvt ./... | grep -E '^(--- FAIL|ok|FAIL|panic)'); then
    ok "go: signer-admin vet and tests with -tags dvt, with a dvt dev runner"
  else
    bad "go: signer-admin vet and tests with -tags dvt, with a dvt dev runner"
  fi
}

# DV_EXIT_CMDS are the commands only a dvt signer-admin has.
DV_EXIT_CMDS=(dv-indices dv-exit dv-exit-post)

t_admin() {
  local bin out rc c
  DVT=0 bash "$ROOT/scripts/build-admin.sh" || { bad "admin: the default signer-admin does not build"; return; }
  DVT=1 bash "$ROOT/scripts/build-admin.sh" || { bad "admin: the dvt signer-admin does not build"; return; }
  for bin in signer-admin signer-admin-dvt; do
    for c in "${DV_EXIT_CMDS[@]}"; do
      rc=0
      out="$("$BUILD/$HOST_ARCH/bin/$bin" "$c" 2>&1)" || rc=$?
      case "$bin:$rc:$out" in
        signer-admin:1:*"unknown subcommand \"$c\""*) ok "admin: the default signer-admin refuses $c as unknown" ;;
        signer-admin-dvt:1:*"usage: signer-admin $c "*) ok "admin: the dvt signer-admin has $c" ;;
        *) bad "admin: $bin $c (exit $rc): $(head -n 2 <<<"$out")" ;;
      esac
    done
  done
  if grep -qaF dv-exit-post "$BUILD/$HOST_ARCH/bin/signer-admin"; then
    bad "admin: the default signer-admin holds the string dv-exit-post"
  else
    ok "admin: the default signer-admin holds no dv-exit-post"
  fi
}

t_ctest() {
  if DVT=1 FUZZ=0 bash "$ROOT/signer-core/scripts/test.sh"; then ok "ctest: the C suites of the DVT core"; else bad "ctest: the C suites of the DVT core"; fi
}

sections=("$@")
[ ${#sections[@]} -gt 0 ] || sections=(names core runner link)
for s in "${sections[@]}"; do
  start=$SECONDS
  case "$s" in
    names) t_names ;;
    core) t_core ;;
    runner) t_runner ;;
    link) t_link ;;
    admin) t_admin ;;
    go) t_go ;;
    ctest) t_ctest ;;
    *) echo "dvt-test: unknown section $s" >&2; exit 2 ;;
  esac
  log "dvt-test: $s took $((SECONDS - start)) s"
done
[ "$fails" = 0 ] || { echo "dvt-test: $fails failed" >&2; exit 1; }
echo "dvt-test: all passed"
