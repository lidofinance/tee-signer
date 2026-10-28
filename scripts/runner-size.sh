#!/usr/bin/env bash
# Measures what each runner binary links and how big it is: a Markdown table.
#
#   scripts/runner-size.sh                  every runner build (common.sh), sizes from build/<arch>/bin
#   scripts/runner-size.sh --tags TAGS NAME one tag set, for example the one runner before the split:
#                                           --tags netgo,osusergo runner
#
# Columns:
#   ours          Go lines of our own packages that the binary links (cloc, code lines,
#                 test files left out)
#   third party   the same for packages outside the standard library and outside
#                 github.com/lidofinance/tee-signer/..., counting only the files the compiler uses for
#                 linux/amd64
#   package dirs  all non-test .go files in the directories of those third-party
#                 packages. It counts every OS's files of
#                 golang.org/x/sys/unix, so it is much larger than what is linked.
#   packages      third-party packages linked
#   bytes         size of build/<arch>/bin/<name> for x86_64 and aarch64; - if not built
#
# It reads go list and runs cloc, and needs no build; the sizes need one.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

command -v cloc >/dev/null || { echo "runner-size: cloc is not installed" >&2; exit 1; }

# code_lines <file with one path per line>: cloc's count of code lines, 0 for an empty list.
code_lines() {
  if [ -s "$1" ]; then
    cloc --list-file="$1" --csv --quiet --timeout 0 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }'
  else
    echo 0
  fi
}

# measure <name> <tags>: one table row.
measure() {
  local name="$1" tags="$2" tmp ours third dirs pkgs size_x86 size_arm mod dir files f
  tmp="$(mktemp -d)"
  # Lines of: module path, package directory, the Go files built for linux/amd64.
  (cd "$ROOT/tee-signer" && GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
    go list -deps -tags "$tags" -f '{{if not .Standard}}{{with .Module}}{{.Path}}{{else}}-{{end}} {{.Dir}} {{range .GoFiles}}{{.}} {{end}}{{range .CgoFiles}}{{.}} {{end}}{{end}}' .) >"$tmp/pkgs"
  : >"$tmp/ours"; : >"$tmp/third"; : >"$tmp/dirs"
  while read -r mod dir files; do
    [ -n "$mod" ] || continue
    for f in $files; do
      case "$mod" in
        github.com/lidofinance/tee-signer/*) echo "$dir/$f" >>"$tmp/ours" ;;
        *) echo "$dir/$f" >>"$tmp/third" ;;
      esac
    done
    case "$mod" in github.com/lidofinance/tee-signer/*) ;; *) echo "$dir" >>"$tmp/dirs" ;; esac
  done <"$tmp/pkgs"
  ours="$(code_lines "$tmp/ours")"
  third="$(code_lines "$tmp/third")"
  : >"$tmp/dirfiles"
  while read -r dir; do
    for f in "$dir"/*.go; do
      case "$f" in *_test.go) ;; *) echo "$f" >>"$tmp/dirfiles" ;; esac
    done
  done < <(sort -u "$tmp/dirs")
  dirs="$(code_lines "$tmp/dirfiles")"
  pkgs="$(sort -u "$tmp/dirs" | wc -l)"
  size_x86=-; size_arm=-
  f="$BUILD/x86_64/bin/$name"; if [ -f "$f" ]; then size_x86="$(stat -c %s "$f")"; fi
  f="$BUILD/aarch64/bin/$name"; if [ -f "$f" ]; then size_arm="$(stat -c %s "$f")"; fi
  printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$name" "$tags" "$ours" "$third" "$dirs" "$pkgs" "$size_x86" "$size_arm"
  rm -rf "$tmp"
}

echo "| binary | build tags | ours | third party | package dirs | packages | bytes x86_64 | bytes aarch64 |"
echo "|---|---|---:|---:|---:|---:|---:|---:|"
if [ "${1:-}" = --tags ]; then
  measure "${3:-runner}" "$2"
else
  for name in "${RUNNER_BINS[@]}"; do
    measure "$name" "netgo,osusergo,$(runner_tags "$name")"
  done
fi
