#!/usr/bin/env python3
"""Flattens slashing-protection-interchange-tests JSON into a line format
that test_eip3076.c reads without a JSON parser.

usage: eip3076_convert.py <tests/generated dir or .json file>...  > out.txt

Line format (space separated, integers in decimal, bytes in hex):
  T <name> <genesis_validators_root>
  S <should_succeed> <contains_slashable_data> <interchange_gvr> <format_version>
  IB <pubkey> <slot>                       imported signed block
  IA <pubkey> <source> <target>            imported signed attestation
  B <pubkey> <slot> <should_succeed> <signing_root>   block to sign after the import
  A <pubkey> <source> <target> <should_succeed> <signing_root>
  E                                        end of test

The signing root of a block or attestation to sign is "-" when the test
gives none. The roots of imported messages are not needed: the import
takes per-validator maxima only.

The converter checks the vector shape and exits 1 on the first fault: an
unknown or missing field, a number that is not a plain decimal u64, a bool
that is not a JSON bool, a root or pubkey that is not 0x-hex of the right
length. Whether the interchange is valid (its GVR, its version) is for the
runner to decide, so those values pass through.
"""
import json
import os
import re
import sys

U64 = re.compile(r"0|[1-9][0-9]*")
U64_MAX = 2**64 - 1
HEX = re.compile(r"0x[0-9a-fA-F]+")
VERSION = re.compile(r"[0-9]+")

TEST_KEYS = {"name", "genesis_validators_root", "steps"}
STEP_KEYS = {"should_succeed", "contains_slashable_data", "interchange", "blocks", "attestations"}
INTERCHANGE_KEYS = {"metadata", "data"}
METADATA_KEYS = {"interchange_format_version", "genesis_validators_root"}
RECORD_KEYS = {"pubkey", "signed_blocks", "signed_attestations"}
SIGNED_BLOCK_KEYS = {"slot"}
SIGNED_ATT_KEYS = {"source_epoch", "target_epoch"}
BLOCK_KEYS = {"pubkey", "slot", "should_succeed"}
ATT_KEYS = {"pubkey", "source_epoch", "target_epoch", "should_succeed"}
# Present in the vectors, not needed by the runner.
OPTIONAL_KEYS = {"signing_root", "should_succeed_complete"}


def fail(what, msg):
    sys.exit(f"eip3076_convert: {what}: {msg}")


def fields(v, what, required, optional=frozenset()):
    if not isinstance(v, dict):
        fail(what, "not an object")
    missing = required - v.keys()
    unknown = v.keys() - required - optional
    if missing:
        fail(what, f"missing fields {sorted(missing)}")
    if unknown:
        fail(what, f"unknown fields {sorted(unknown)}")
    return v


def items(v, what):
    if not isinstance(v, list):
        fail(what, "not an array")
    return [(f"{what}[{i}]", x) for i, x in enumerate(v)]


def u64(v, what):
    if not isinstance(v, str) or not U64.fullmatch(v) or int(v) > U64_MAX:
        fail(what, f"not a decimal u64 string: {v!r}")
    return v


def flag(v, what):
    if not isinstance(v, bool):
        fail(what, f"not a bool: {v!r}")
    return "1" if v else "0"


def hexbytes(v, n, what):
    if not isinstance(v, str) or not HEX.fullmatch(v) or len(v) != 2 + 2 * n:
        fail(what, f"not 0x-hex of {n} bytes: {v!r}")
    return v[2:]


def root(op, what):
    r = op.get("signing_root")
    return hexbytes(r, 32, f"{what}.signing_root") if r is not None else "-"


def version(v, what):
    if not isinstance(v, str) or not VERSION.fullmatch(v):
        fail(what, f"not a version string: {v!r}")
    return v


def convert(path):
    what = os.path.basename(path)
    with open(path) as f:
        try:
            t = json.load(f)
        except ValueError as e:
            fail(what, f"not JSON: {e}")
    fields(t, what, TEST_KEYS)
    name = t["name"]
    if not isinstance(name, str) or not re.fullmatch(r"\S+", name):
        fail(what, f"name is not one word: {name!r}")
    print("T", name, hexbytes(t["genesis_validators_root"], 32, f"{what}.genesis_validators_root"))
    for w, st in items(t["steps"], f"{what}.steps"):
        fields(st, w, STEP_KEYS)
        ic = fields(st["interchange"], f"{w}.interchange", INTERCHANGE_KEYS)
        md = fields(ic["metadata"], f"{w}.interchange.metadata", METADATA_KEYS)
        print("S", flag(st["should_succeed"], f"{w}.should_succeed"),
              flag(st["contains_slashable_data"], f"{w}.contains_slashable_data"),
              hexbytes(md["genesis_validators_root"], 32, f"{w}.interchange.metadata.genesis_validators_root"),
              version(md["interchange_format_version"], f"{w}.interchange.metadata.interchange_format_version"))
        for wr, rec in items(ic["data"], f"{w}.interchange.data"):
            fields(rec, wr, RECORD_KEYS)
            pk = hexbytes(rec["pubkey"], 48, f"{wr}.pubkey")
            for wb, blk in items(rec["signed_blocks"], f"{wr}.signed_blocks"):
                fields(blk, wb, SIGNED_BLOCK_KEYS, OPTIONAL_KEYS)
                print("IB", pk, u64(blk["slot"], f"{wb}.slot"))
            for wa, att in items(rec["signed_attestations"], f"{wr}.signed_attestations"):
                fields(att, wa, SIGNED_ATT_KEYS, OPTIONAL_KEYS)
                print("IA", pk, u64(att["source_epoch"], f"{wa}.source_epoch"),
                      u64(att["target_epoch"], f"{wa}.target_epoch"))
        for wb, blk in items(st["blocks"], f"{w}.blocks"):
            fields(blk, wb, BLOCK_KEYS, OPTIONAL_KEYS)
            print("B", hexbytes(blk["pubkey"], 48, f"{wb}.pubkey"), u64(blk["slot"], f"{wb}.slot"),
                  flag(blk["should_succeed"], f"{wb}.should_succeed"), root(blk, wb))
        for wa, att in items(st["attestations"], f"{w}.attestations"):
            fields(att, wa, ATT_KEYS, OPTIONAL_KEYS)
            print("A", hexbytes(att["pubkey"], 48, f"{wa}.pubkey"),
                  u64(att["source_epoch"], f"{wa}.source_epoch"),
                  u64(att["target_epoch"], f"{wa}.target_epoch"),
                  flag(att["should_succeed"], f"{wa}.should_succeed"), root(att, wa))
    print("E")


def main():
    paths = []
    for arg in sys.argv[1:]:
        if os.path.isdir(arg):
            paths += [os.path.join(arg, n) for n in sorted(os.listdir(arg)) if n.endswith(".json")]
        else:
            paths.append(arg)
    if not paths:
        fail("usage", "no vector files given")
    for p in paths:
        convert(p)


if __name__ == "__main__":
    main()
