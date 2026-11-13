#!/usr/bin/env python3
"""Turn the fingerprints.txt of scripts/generic-images.sh into measurements.json.

    release/measurements.py --tag TAG --commit SHA --chain CHAIN --variant VARIANT \
        FINGERPRINTS > measurements.json

The setup_line of each image is the line an approver puts into a setup or a
locked update (governance/setuptext: allowed_image_measurements = KIND HEX...).
Only the standard library; no network.
"""

import argparse
import json
import re
import sys

HEX = {"nitro.PCR0": 96, "nitro.PCR1": 96, "nitro.PCR2": 96, "azure.cce_policy": 64}


def read(path):
    values = {}
    with open(path, encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, value = line.split(None, 1)
            values[name] = value
    for name, size in HEX.items():
        if not re.fullmatch("[0-9a-f]{%d}" % size, values.get(name, "")):
            sys.exit(f"measurements: {name} is missing or not {size} hex digits")
    for name in ("azure.image", "gcp.image"):
        if not re.fullmatch("sha256:[0-9a-f]{64}", values.get(name, "")):
            sys.exit(f"measurements: {name} is missing or not sha256:<64 hex>")
    return values


def main():
    ap = argparse.ArgumentParser()
    for a in ("--tag", "--commit", "--chain", "--variant"):
        ap.add_argument(a, required=True)
    ap.add_argument("fingerprints")
    args = ap.parse_args()
    v = read(args.fingerprints)
    pcrs = [v["nitro.PCR0"], v["nitro.PCR1"], v["nitro.PCR2"]]
    gcp = v["gcp.image"].removeprefix("sha256:")
    out = {
        "format": 1,
        "tag": args.tag,
        "commit": args.commit,
        "chain": args.chain,
        "variant": args.variant,
        "images": {
            "nitro": {
                "arch": "aarch64",
                "pcr0": pcrs[0], "pcr1": pcrs[1], "pcr2": pcrs[2],
                "runner_sha256": v["nitro.runner"],
                "setup_line": "allowed_image_measurements = nitro " + " ".join("0x" + p for p in pcrs),
            },
            "azure": {
                "image_digest": v["azure.image"],
                "cce_policy_sha256": v["azure.cce_policy"],
                "runner_sha256": v["azure.runner"],
                "setup_line": "allowed_image_measurements = azure 0x" + v["azure.cce_policy"],
            },
            "gcp": {
                "image_digest": v["gcp.image"],
                "runner_sha256": v["gcp.runner"],
                "setup_line": "allowed_image_measurements = gcp 0x" + gcp,
            },
        },
        "parent_tools_sha256": {
            k.split(".", 1)[1]: v[k] for k in sorted(v) if k.startswith("parent.")
        },
    }
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
