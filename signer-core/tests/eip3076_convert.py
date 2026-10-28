#!/usr/bin/env python3
"""Flattens slashing-protection-interchange-tests JSON into a line format
that test_eip3076.c reads without a JSON parser.

usage: eip3076_convert.py <tests/generated dir>  > out.txt

Line format (space separated, integers in decimal, bytes in hex):
  T <name> <genesis_validators_root>
  S <should_succeed> <contains_slashable_data> <interchange_gvr> <format_version>
  IB <pubkey> <slot>                       imported signed block
  IA <pubkey> <source> <target>            imported signed attestation
  B <pubkey> <slot> <should_succeed>       block to sign after the import
  A <pubkey> <source> <target> <should_succeed>
  E                                        end of test
"""
import json
import os
import sys


def b(v):
    return "1" if v else "0"


def strip(h):
    return h[2:] if h.startswith("0x") else h


def main():
    d = sys.argv[1]
    for name in sorted(os.listdir(d)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(d, name)) as f:
            t = json.load(f)
        print("T", t["name"], strip(t["genesis_validators_root"]))
        for st in t["steps"]:
            ic = st["interchange"]
            md = ic.get("metadata", {})
            print("S", b(st["should_succeed"]), b(st["contains_slashable_data"]),
                  strip(md.get("genesis_validators_root", "")) or "-",
                  md.get("interchange_format_version", "-"))
            for rec in ic.get("data", []):
                pk = strip(rec["pubkey"])
                for blk in rec.get("signed_blocks", []):
                    print("IB", pk, int(blk["slot"]))
                for att in rec.get("signed_attestations", []):
                    print("IA", pk, int(att["source_epoch"]), int(att["target_epoch"]))
            for blk in st.get("blocks", []):
                print("B", strip(blk["pubkey"]), int(blk["slot"]), b(blk["should_succeed"]))
            for att in st.get("attestations", []):
                print("A", strip(att["pubkey"]), int(att["source_epoch"]),
                      int(att["target_epoch"]), b(att["should_succeed"]))
        print("E")


if __name__ == "__main__":
    main()
