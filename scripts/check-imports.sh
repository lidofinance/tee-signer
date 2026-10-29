#!/usr/bin/env bash
# Module boundaries. Each module of this repo uses another module only
# through its public packages:
#   1. no import of another module's internal/ packages (Go refuses most
#      of these; this check also catches build-tagged files that vet skips);
#   2. no import path of the dev repos this tree came from;
#   3. outside _test.go files, nothing of devkit/ or tests/;
#   4. every module of this repo that a module imports is required and
#      replaced in its go.mod, so the module builds on its own.
# Reads the sources only; exits non-zero on the first kind of violation.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
P=github.com/lidofinance/tee-signer
cd "$ROOT"
fail=0
bad() { echo "check-imports: $*" >&2; fail=1; }

mods=()
for m in */go.mod; do mods+=("${m%/go.mod}"); done

for m in "${mods[@]}"; do
  # Go files of this module, without nested modules and vendored code.
  files="$(find "$m" -name '*.go' -not -path '*/third_party/*' -not -path '*/testdata/*' |
    while read -r f; do
      d="$(dirname "$f")"; nested=0
      while [ "$d" != "$m" ] && [ "$d" != . ]; do [ -f "$d/go.mod" ] && nested=1; d="$(dirname "$d")"; done
      [ "$nested" = 1 ] || echo "$f"
    done)"
  [ -n "$files" ] || continue
  # file<TAB>import path, for every import of this repo or of the old trees
  imports="$(xargs -r grep -oHE '"('"$P"'|signercloud)/[^"]+"' <<<"$files" | tr -d '"' | sed 's/:/\t/')"
  while IFS=$'\t' read -r f imp; do
    [ -n "$imp" ] || continue
    case "$imp" in
      signercloud/*) bad "$f imports $imp (a path of the dev repos)"; continue ;;
    esac
    rest="${imp#"$P"/}"
    other="${rest%%/*}"
    [ "$other" != "$m" ] || continue
    case "/$rest/" in */internal/*) bad "$f imports $imp, an internal package of module $other" ;; esac
    case "$f" in
      *_test.go) ;;
      *)
        if [ "$m" = slashing-log ]; then
          case "$rest" in
            signer-core|signer-core/*) bad "$f imports $imp (the log must not depend on signing bindings)" ;;
          esac
        fi
        case "$rest" in
          devkit|devkit/*) bad "$f imports $imp outside a test (devkit is for tests)" ;;
          tests|tests/*) bad "$f imports $imp outside a test" ;;
        esac ;;
    esac
    grep -qE "^(require)?[[:space:]]*$P/$other[[:space:]]+v" "$m/go.mod" ||
      bad "$m/go.mod does not require $P/$other ($f imports it)"
    grep -qE "^(replace)?[[:space:]]*$P/$other[[:space:]]+=>[[:space:]]+\.\./$other$" "$m/go.mod" ||
      bad "$m/go.mod has no replace of $P/$other by ../$other"
  done <<<"$imports"
done

if [ "$fail" != 0 ]; then
  echo "check-imports: FAILED" >&2
  exit 1
fi
echo "check-imports: ${#mods[@]} modules, no internal import across modules, devkit and tests only in tests"
