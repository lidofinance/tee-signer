#!/usr/bin/env bash
# Shows the tests catch real bugs: builds copies of the core with one
# deliberate bug each and checks that the matching suite now fails.
# Mutants are built under build/mutants/ and never touch src/.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

BUILD="$CORE_DIR/build/$HOST_ARCH"
BLST_LIB="$BUILD/blst/libblst.a"
[ -f "$BLST_LIB" ] || make -C "$CORE_DIR" -j"$(nproc)" blst >/dev/null
[ -f "$BUILD/eip3076.txt" ] || { echo "run scripts/test.sh first" >&2; exit 1; }

status=0
# mutant <name> <file> <sed expression> <test binary> <test args...>
mutant() {
  local name="$1" file="$2" expr="$3" bin="$4"
  shift 4
  local dir="$CORE_DIR/build/mutants/$name"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp -r "$CORE_DIR/src" "$CORE_DIR/include" "$CORE_DIR/tests" "$CORE_DIR/Makefile" "$dir/"
  sed -i -e "$expr" "$dir/$file"
  if cmp -s "$dir/$file" "$CORE_DIR/$file"; then
    echo "ERROR mutant $name: sed changed nothing in $file"
    status=1
    return
  fi
  if ! make -C "$dir" -j"$(nproc)" BUILD=out MARKFORMAT_DIR="$CORE_DIR/../markformat" BLST_SRC="$BLST_DIR" BLST_LIB="$BLST_LIB" "out/$bin" >"$dir/build.log" 2>&1; then
    echo "ERROR mutant $name: does not build (build/mutants/$name/build.log)"
    status=1
    return
  fi
  if "$dir/out/$bin" "$@" >"$dir/run.log" 2>&1; then
    echo "MISSED mutant $name: $bin still passes"
    status=1
  else
    echo "CAUGHT mutant $name: $bin fails ($(grep -E '^(SSZ_STATIC|BLS_SIGN|EIP3076|UNIT|restart property)' "$dir/run.log" | head -2 | tr '\n' ';'))"
  fi
}

mutant ssz-index src/ssz.c 's/chunk_u64(c\[1\], v->index);/chunk_u64(c[1], v->index + 1);/' \
  test_ssz_static "$CST_SSZ_DIR"
mutant ssz-pubkey-padding src/ssz.c 's/chunk_bytes(c\[1\], b + 32, 16);/memcpy(c[1], b + 16, 32);/' \
  test_unit "$CORE_DIR/tests/data"
mutant bls-dst src/bls.c 's/SSWU_RO_POP_/SSWU_RO_NUL_/' \
  test_bls_sign "$CST_BLS_DIR"
mutant no-surround-check src/slashing.c 's/if (source_epoch < st->ram.source_epoch)/if (0)/' \
  test_eip3076 "$BUILD/eip3076.txt"
mutant restart-forgets-source src/slashing.c 's/st->ram = st->committed;/st->ram = st->committed; st->ram.source_epoch = 0;/' \
  test_unit "$CORE_DIR/tests/data"
mutant window-source-too-low src/slashing.c 's/next.source_epoch = s_hi;/next.source_epoch = source_epoch ? source_epoch - 1 : 0;/' \
  test_unit "$CORE_DIR/tests/data"
mutant exit-allowlist-ignored src/policy.c 's/return SC_ERR_POLICY_EXIT;/return SC_OK;/' \
  test_unit "$CORE_DIR/tests/data"
mutant repeat-any-root src/signer.c 's/memcmp(last, root, SC_ROOT_LEN) == 0/memcmp(last, root, 0) == 0/' \
  test_unit "$CORE_DIR/tests/data"
# An import that keeps the repeat roots: a resend of a vote, block, PTC vote
# or envelope that the imported history covers would skip the marks.
mutant import-keeps-repeat-roots src/signer.c \
  's/memset(&v->repeat, 0, sizeof v->repeat);/(void)v;/; s/v->gloas \&= ~(G_PTC_ROOT | G_ENVELOPE_ROOT);//' \
  test_unit "$CORE_DIR/tests/data"
mutant device-window-source-too-low src/slashing.c 's/s_hi = source;/s_hi = source ? source - 1 : 0;/' \
  test_unit "$CORE_DIR/tests/data"
# The two ways the device mark's source bound rose above the signed source
# before the non-finality fix: a source window, and a cover that sets the
# bound to epoch - 1 (as the cover did then: in its check and its raise).
mutant device-source-window src/slashing.c 's/s_hi = source;/s_hi = sc_min64(sc_sat_add(source, ahead->source_epochs), next.target_epoch);/' \
  test_unit "$CORE_DIR/tests/data"
mutant cover-raises-source src/slashing.c 's/epoch <= device->target_epoch/epoch <= device->target_epoch \&\& (epoch ? epoch - 1 : 0) <= device->source_epoch/; s/ctx, epoch, 0, 0);/ctx, epoch, 1, epoch ? epoch - 1 : 0);/' \
  test_unit "$CORE_DIR/tests/data"
# sc_sign_root: any domain type accepted, and any RANDAO root accepted.
mutant root-any-domain src/signer.c 's/^    if (i == n)$/    if (0)/' \
  test_unit "$CORE_DIR/tests/data"
mutant root-randao-unchecked src/signer.c 's/if (memcmp(want, object_root, SC_ROOT_LEN) != 0)/if (0)/' \
  test_unit "$CORE_DIR/tests/data"
# sc_sign_root: a Gloas domain type signed before the Gloas fork epoch.
mutant root-gloas-before-fork src/signer.c 's/if (i >= ROOT_DOMAINS_FIRST_GLOAS \&\& /if (0 \&\& /' \
  test_unit "$CORE_DIR/tests/data"
# sc_signer_set_schedule: no margin epoch, activate_at ignored, sums that
# wrap, and the Gloas state left out of the comparison.
mutant schedule-no-margin src/signer.c 's/s->cfg.max_epochs_ahead), 1);/s->cfg.max_epochs_ahead), 0);/' \
  test_unit "$CORE_DIR/tests/data"
mutant schedule-ignores-activate-at src/signer.c 's/sc_max64(activate_at, now)/sc_max64(activate_at * 0, now)/' \
  test_unit "$CORE_DIR/tests/data"
mutant schedule-wrapping-sum src/signer.c 's/limit = sc_sat_add(sc_sat_add(limit, s->cfg.max_epochs_ahead), 1);/limit = limit + s->cfg.max_epochs_ahead + 1;/' \
  test_unit "$CORE_DIR/tests/data"
mutant schedule-ignores-gloas src/signer.c 's/return cfg->gloas_scheduled && epoch/return 0 \&\& epoch/' \
  test_unit "$CORE_DIR/tests/data"
exit $status
