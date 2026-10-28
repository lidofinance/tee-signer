#!/usr/bin/env bash
# NTS interop test against the four public operators (Cloudflare, Netnod,
# PTB, time.nl): one NTS-KE and three queries per server, 34 s apart, then
# the quorum, through the runner's NTS clock (trusted-time/clock, tag nts). It
# needs the network, so it is not part of make test-offline or test-nts.sh.
#
# Traffic: TCP 4460 (NTS-KE) and UDP 123 (NTP) to time.cloudflare.com,
# nts.netnod.se, ptbtime1.ptb.de and ntppool1.time.nl, plus their DNS
# lookups. Nothing else. At most one query per server per 34 s, about 75 s
# in all, stopped at 290 s. The coarse check uses the host clock here, not
# HTTPS-date, so no other host is contacted.
#
# Needs build/nts/x86_64/lib/libsigner_nts.a (scripts/build-nts.sh).
# Output: logs/nts-interop.log (the test's lines) and logs/nts-interop.json.
#
# Usage: nts-interop.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
[ "$HOST_ARCH" = x86_64 ] || { echo "nts-interop: run on x86_64 (the network test is not run under qemu)" >&2; exit 2; }
lib="$NTS_OUT/x86_64/lib/libsigner_nts.a"
[ -f "$lib" ] || { echo "nts-interop: $lib is missing (scripts/build-nts.sh)" >&2; exit 1; }

bin="$NTS_OUT/x86_64/bin/clock-nts.test"
mkdir -p "$(dirname "$bin")"
rm -f "$bin" # go test -c keeps a file whose build ID matches; that ID does not cover the archive
(cd "$ROOT/trusted-time" && CGO_ENABLED=1 go test -c -trimpath -tags netgo,osusergo,nts \
  -ldflags "-s -w -linkmode external -extldflags -static" -o "$bin" ./clock)

log "nts-interop: $(sha256sum "$lib" | cut -c1-16)... libsigner_nts.a, start $(date -u +%FT%TZ)"
set +e
(cd "$ROOT/trusted-time/clock" && NTS_INTEROP=1 NTS_INTEROP_OUT="$LOGS/nts-interop.json" \
  timeout 290 "$bin" -test.run '^TestNTSInteropPublicServers$' -test.v -test.count=1) >"$LOGS/nts-interop.log" 2>&1
rc=$?
set -e
grep -E 'round|---|^(ok|PASS|FAIL)|interop took' "$LOGS/nts-interop.log" | sed 's/^ *//'
[ "$rc" = 0 ] || { echo "nts-interop: FAILED (exit $rc), see $LOGS/nts-interop.log" >&2; exit 1; }
log "nts-interop: passed; $LOGS/nts-interop.json"
