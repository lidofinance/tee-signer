#!/usr/bin/env python3
"""Write an SPDX 2.3 JSON SBOM for one runner binary, from what the build used.

    release/sbom.py --name NAME --builder-packages FILE BINARY > NAME.spdx.json

Packages:
  - every Go module the binary links (go version -m -json: path, version, sum),
  - the Rust crates of trusted-time/rust/Cargo.lock (NTS builds: tag nts),
  - blst at its pin (scripts/common.sh),
  - the Debian packages of the release builder whose code a static link pulls
    in (glibc, the gcc runtime), from /builder-packages.txt of the builder.
Only the standard library; no network. Run it with the Go of the builder.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The builder packages whose code a static link of each GOARCH pulls in.
LINKED_DEBIAN = {
    "amd64": ("libc6-dev", "libgcc-12-dev", "gcc-12"),
    "arm64": ("libc6-dev-arm64-cross", "libgcc-12-dev-arm64-cross", "gcc-12-aarch64-linux-gnu"),
}


def spdx_id(*parts):
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", "-".join(parts))


def pkg(name, version, purl, checksum=None):
    p = {
        "SPDXID": spdx_id(name, version),
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}],
    }
    if checksum:
        p["checksums"] = [checksum]
    return p


def created():
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def common_pin(name):
    m = re.search(r'^%s="([^"]+)"' % name, (ROOT / "scripts/common.sh").read_text(), re.M)
    return m.group(1) if m else "NOASSERTION"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--builder-packages", required=True)
    ap.add_argument("binary")
    a = ap.parse_args()
    data = Path(a.binary).read_bytes()
    info = json.loads(subprocess.check_output(["go", "version", "-m", "-json", a.binary], text=True))
    packages, rels = [], []
    top = {
        "SPDXID": "SPDXRef-runner",
        "name": a.name,
        "versionInfo": info.get("Main", {}).get("Version", "(devel)"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(data).hexdigest()}],
        "comment": "go " + info["GoVersion"] + "; build settings: "
        + " ".join(f'{s["Key"]}={s["Value"]}' for s in info.get("Settings", [])),
    }
    packages.append(top)
    for d in info.get("Deps") or []:
        d = d.get("Replace") or d
        if d["Path"].startswith("github.com/lidofinance/tee-signer/"):
            continue
        packages.append(pkg(d["Path"], d.get("Version", ""), f'pkg:golang/{d["Path"]}@{d.get("Version", "")}'))
    packages.append(pkg("golang-stdlib", info["GoVersion"], f'pkg:golang/stdlib@{info["GoVersion"]}'))
    tags = next((s["Value"] for s in info.get("Settings", []) if s["Key"] == "-tags"), "")
    if "nts" in tags.split(","):
        lock = tomllib.loads((ROOT / "trusted-time/rust/Cargo.lock").read_text())
        for c in lock["package"]:
            if "source" not in c:
                continue
            ck = {"algorithm": "SHA256", "checksumValue": c["checksum"]} if "checksum" in c else None
            packages.append(pkg(c["name"], c["version"], f'pkg:cargo/{c["name"]}@{c["version"]}', ck))
    packages.append(pkg("blst", common_pin("BLST_TAG"), f'pkg:github/supranational/blst@{common_pin("BLST_COMMIT")}'))
    goarch = next((s["Value"] for s in info.get("Settings", []) if s["Key"] == "GOARCH"), "")
    cgo = next((s["Value"] for s in info.get("Settings", []) if s["Key"] == "CGO_ENABLED"), "0")
    linked = LINKED_DEBIAN.get(goarch, ()) if cgo == "1" else ()
    for line in Path(a.builder_packages).read_text().splitlines():
        f = line.split()
        if len(f) == 3 and f[0] in linked:
            packages.append(pkg(f[0], f[1], f"pkg:deb/debian/{f[0]}@{f[1]}?arch={f[2]}&distro=bookworm"))
    for p in packages[1:]:
        rels.append({"spdxElementId": "SPDXRef-runner", "relationshipType": "CONTAINS", "relatedSpdxElement": p["SPDXID"]})
    rels.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-runner"})
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": a.name,
        "documentNamespace": "https://github.com/lidofinance/tee-signer/sbom/" + top["checksums"][0]["checksumValue"],
        # The commit time, so two builds of one commit write the same file.
        "creationInfo": {"created": created(), "creators": ["Tool: release/sbom.py"]},
        "packages": packages,
        "relationships": rels,
    }
    json.dump(doc, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    sys.exit(main())
