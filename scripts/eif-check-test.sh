#!/usr/bin/env bash
# Self-test of scripts/eif-check.sh on small made-up EIF files: a clean one
# passes, also with zero padding after a ramdisk's cpio trailer; a second
# archive after the trailer, a header that is not cpio newc, or a truncated
# entry fails. Offline, python3 only.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
CHECK="$ROOT/scripts/eif-check.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
expect() { # expect <pass|fail> <what> <eif>
  local got
  if bash "$CHECK" "$3" aarch64 --runner "$tmp/runner" >"$tmp/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$2" ]; then
    echo "eif-check self-test: $1: got $got, want $2" >&2
    sed 's/^/  /' "$tmp/out" >&2
    fails=$((fails + 1))
  fi
}

# Writes runner (the /runner the checks expect) and one EIF per case.
python3 -I - "$tmp" <<'PY'
import struct, sys

out = sys.argv[1]

def elf(tag):
    b = bytearray(64)
    b[0:4] = b"\x7fELF"
    b[4] = 2
    b[18:20] = struct.pack("<H", 0xB7)
    return bytes(b) + tag

def entry(name, data, mode=0o100755):
    n = name.encode() + b"\0"
    f = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(n), 0]
    h = b"070701" + b"".join(b"%08X" % x for x in f) + n
    h += b"\0" * (-len(h) % 4)
    return h + data + b"\0" * (-len(data) % 4)

def archive(files):
    return b"".join(entry(n, d) for n, d in files) + entry("TRAILER!!!", b"", 0)

def eif(boot, app):
    kern = bytearray(64)
    kern[56:60] = b"ARMd"
    secs = [(1, bytes(kern)), (2, b"console=ttyS0"), (3, boot), (3, app)]
    offs, sizes, body, pos = [], [], b"", 540
    for t, b in secs:
        offs.append(pos)
        sizes.append(len(b))
        s = struct.pack(">HHQ", t, 0, len(b)) + b
        body += s
        pos += len(s)
    hdr = b".eif" + struct.pack(">HHQQHH", 4, 1, 512 << 20, 2, 0, len(secs))
    hdr += struct.pack(">32Q", *(offs + [0] * (32 - len(offs))))
    hdr += struct.pack(">32Q", *(sizes + [0] * (32 - len(sizes))))
    return hdr + body

runner, evil = elf(b"runner"), elf(b"other runner")
open(out + "/runner", "wb").write(runner)
boot = archive([("init", elf(b"init")), ("nsm.ko", b"module")])
app = archive([("rootfs", b""), ("rootfs/runner", runner)])
second = archive([("rootfs/runner", evil)])
cases = {
    "clean": eif(boot, app),
    "padded": eif(boot + b"\0" * 512, app + b"\0" * 512),
    "second-image": eif(boot, app + second),
    "second-image-padded": eif(boot, app + b"\0" * 512 + second),
    "second-boot": eif(boot + archive([("init", elf(b"other init"))]), app),
    "not-newc": eif(boot, b"070707" + app[6:]),
    "truncated": eif(boot, app[:-200]),
}
for name, b in cases.items():
    open("%s/%s.eif" % (out, name), "wb").write(b)
PY

expect clean pass "$tmp/clean.eif"
expect "zero padding after the trailer" pass "$tmp/padded.eif"
expect "second archive in the image ramdisk" fail "$tmp/second-image.eif"
expect "second archive after zero padding" fail "$tmp/second-image-padded.eif"
expect "second archive in the bootstrap ramdisk" fail "$tmp/second-boot.eif"
expect "header that is not newc" fail "$tmp/not-newc.eif"
expect "truncated ramdisk" fail "$tmp/truncated.eif"

[ "$fails" -eq 0 ] || { echo "eif-check self-test: $fails case(s) failed" >&2; exit 1; }
log "eif-check self-test: passed"
