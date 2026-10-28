#!/usr/bin/env bash
# Reads a Nitro EIF file and checks it, without nitro-cli and without Nitro
# hardware. It prints PCR0/1/2 recomputed from the sections of the file, so
# an operator can compare them with a build or with `nitro-cli
# describe-enclaves`.
#
#   eif-check.sh <eif> <x86_64|aarch64> [--runner FILE] [--generic] [--chain FILE]
#                [--ca FILE] [--build-json FILE] [--blobs DIR]
#
#   --runner      the binary that must be /runner in the image (same sha256,
#                 and an ELF of the arch)
#   --generic     the image holds nothing of an operator: no /etc/signer
#                 (the setup comes from the host agent at every start)
#   --chain, --ca the files that must be /etc/signer/chain.json and
#                 /etc/signer/client-ca.pem in the image (the per-operator
#                 images before the setup)
#   --build-json  build-enclave output of nitro-cli: its PCR0/1/2 must equal
#                 the recomputed ones
#   --blobs       a nitro-cli blob directory: kernel, init and nsm.ko in the
#                 EIF must be those files
#
# Always checked: the EIF header and its arch flag, the kernel header (arm64
# "Image": the magic ARMd at offset 56; x86_64 bzImage: HdrS at 0x202), the
# arch of the init and runner ELF files. Exit 1 if a check fails.
#
# The layout is the one nitro-cli's image format crate writes (version 4):
# a header with up to 32 section offsets, then sections of type kernel (1),
# cmdline (2), ramdisk (3), signature (4) and metadata (5). The ramdisks are
# cpio "newc" archives. PCRn is SHA-384 of 48 zero bytes and the SHA-384 of
# the section bytes: PCR0 kernel, cmdline and all ramdisks, PCR1 kernel,
# cmdline and the first ramdisk (bootstrap), PCR2 the other ramdisks (the
# image). The metadata section is not measured. The PCRs it computes
# match the ones nitro-cli prints.
set -euo pipefail
exec python3 -I - "$@" <<'PY'
import argparse, hashlib, json, struct, sys

ap = argparse.ArgumentParser(prog="eif-check.sh")
ap.add_argument("eif")
ap.add_argument("arch", choices=["x86_64", "aarch64"])
ap.add_argument("--runner")
ap.add_argument("--generic", action="store_true")
ap.add_argument("--chain")
ap.add_argument("--ca")
ap.add_argument("--build-json")
ap.add_argument("--blobs")
a = ap.parse_args()

bad = []
def say(msg): print("[cloud] eif-check: " + msg)
def check(ok, msg):
    say(("ok   " if ok else "FAIL ") + msg)
    if not ok: bad.append(msg)
def sha(b): return hashlib.sha256(b).hexdigest()
def sha384(b): return hashlib.sha384(b).hexdigest()
def read(p):
    with open(p, "rb") as f: return f.read()

data = read(a.eif)
if data[:4] != b".eif":
    sys.exit("eif-check: %s is not an EIF (no .eif magic)" % a.eif)
version, flags, mem, cpus, _res, cnt = struct.unpack(">HHQQHH", data[4:28])
offs = struct.unpack(">32Q", data[28:284])
sizes = struct.unpack(">32Q", data[284:540])
say("%s: %d bytes, EIF version %d, default %d MiB and %d cpus, %d sections" % (a.eif, len(data), version, mem >> 20, cpus, cnt))
check(version == 4, "EIF version 4")
check((flags & 1) == (1 if a.arch == "aarch64" else 0), "header arch flag is %s (flags=%#x)" % ("arm64" if flags & 1 else "x86_64", flags))

secs = []
for i in range(cnt):
    t, f, size = struct.unpack(">HHQ", data[offs[i]:offs[i] + 12])
    if size != sizes[i] or offs[i] + 12 + size > len(data):
        sys.exit("eif-check: section %d does not fit the header" % i)
    secs.append((t, data[offs[i] + 12:offs[i] + 12 + size]))
kern = [b for t, b in secs if t == 1]
cmd = [b for t, b in secs if t == 2]
rd = [b for t, b in secs if t == 3]
if len(kern) != 1 or len(cmd) != 1 or len(rd) != 2:
    sys.exit("eif-check: want 1 kernel, 1 cmdline and 2 ramdisks, got %d, %d and %d" % (len(kern), len(cmd), len(rd)))
kern, cmd = kern[0], cmd[0]
say("sections: kernel %d bytes, cmdline %d bytes, ramdisks %d and %d bytes" % (len(kern), len(cmd), len(rd[0]), len(rd[1])))
say("kernel command line: " + cmd.decode("ascii", "replace").strip())

# Kernel header.
if a.arch == "aarch64":
    check(kern[56:60] == b"ARMd", "kernel is an arm64 Image: magic %r at offset 56" % kern[56:60])
    kname = "Image"
else:
    check(kern[0x202:0x206] == b"HdrS", "kernel is an x86 bzImage: magic %r at 0x202" % kern[0x202:0x206])
    kname = "bzImage"

# cpio "newc" archives.
def cpio(buf):
    out, pos = {}, 0
    while pos + 110 <= len(buf):
        if buf[pos:pos + 6] != b"070701":
            break
        f = [int(buf[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        mode, fsize, nsize = f[1], f[6], f[11]
        ns = pos + 110
        name = buf[ns:ns + nsize - 1].decode()
        do = (ns + nsize + 3) & ~3
        pos = (do + fsize + 3) & ~3
        if name == "TRAILER!!!":
            break
        out[name] = (mode, buf[do:do + fsize])
    return out
boot, app = cpio(rd[0]), cpio(rd[1])

want_machine = 0xB7 if a.arch == "aarch64" else 0x3E
def elf_ok(b):
    return b[:4] == b"\x7fELF" and b[4] == 2 and struct.unpack("<H", b[18:20])[0] == want_machine
for name in ("init",):
    check(name in boot and elf_ok(boot[name][1]), "bootstrap ramdisk /%s is a 64-bit %s ELF" % (name, a.arch))
check("nsm.ko" in boot, "bootstrap ramdisk has /nsm.ko")
check("rootfs/runner" in app, "image ramdisk has /runner (rootfs/runner)")
if "rootfs/runner" in app:
    mode, rb = app["rootfs/runner"]
    check(elf_ok(rb), "/runner is a 64-bit %s ELF, sha256 %s, mode %o" % (a.arch, sha(rb), mode & 0o7777))
    if a.runner:
        check(sha(rb) == sha(read(a.runner)), "/runner has the sha256 of %s" % a.runner)
if a.generic:
    extra = sorted(n for n in app if n.startswith("rootfs/etc/signer"))
    check(not extra, "no operator files in the image (rootfs/etc/signer: %s)" % (", ".join(extra) or "none"))
for opt, inimg in ((a.chain, "rootfs/etc/signer/chain.json"), (a.ca, "rootfs/etc/signer/client-ca.pem")):
    if opt:
        check(inimg in app and app[inimg][1] == read(opt), "/%s equals %s" % (inimg[len("rootfs/"):], opt))
if "rootfs/cmd" in app:
    say("enclave command (rootfs/cmd): " + " ".join(app["rootfs/cmd"][1].decode().split("\n")[:6]) + " ...")

if a.blobs:
    pairs = ((kern, kname), (boot.get("init", (0, b""))[1], "init"), (boot.get("nsm.ko", (0, b""))[1], "nsm.ko"))
    for got, fname in pairs:
        check(sha(got) == sha(read(a.blobs + "/" + fname)), "%s in the EIF is %s/%s" % (fname, a.blobs, fname))

# PCRs from the sections.
def pcr(parts):
    h = hashlib.sha384()
    for p in parts: h.update(p)
    return sha384(b"\0" * 48 + h.digest())
pcrs = {"PCR0": pcr([kern, cmd] + rd), "PCR1": pcr([kern, cmd, rd[0]]), "PCR2": pcr(rd[1:])}
for k, v in pcrs.items():
    say("%s (recomputed) %s" % (k, v))
if a.build_json:
    m = json.load(open(a.build_json))["Measurements"]
    for k, v in pcrs.items():
        check(m[k] == v, "%s equals the one nitro-cli printed" % k)

if bad:
    sys.exit("eif-check: %d check(s) failed" % len(bad))
say("all checks passed")
PY
