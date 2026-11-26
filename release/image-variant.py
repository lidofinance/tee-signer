#!/usr/bin/env python3
"""Check that the built cloud images are of the variant a release lane names.

    release/image-variant.py VARIANT FINGERPRINTS GCP_OCI_TAR AZURE_POLICY...
    release/image-variant.py detect FINGERPRINTS GCP_OCI_TAR AZURE_POLICY...

prod: the GCP image config has the label tee.launch_policy.log_redirect=never
and each Azure CCE policy sets allow_stdio_access to false. test: always and
true. The GCP image checked is the manifest gcp.image of FINGERPRINTS, and
each AZURE_POLICY (policy.rego) must hash to its azure.cce_policy, so the
files checked are the ones measured. detect prints the variant the
images are of, and fails when they are of neither. Only the standard library; no network.
"""

import hashlib
import json
import re
import sys
import tarfile

# variant: (GCP log_redirect label, Azure allow_stdio_access)
WANT = {"prod": ("never", "false"), "test": ("always", "true")}


def die(msg):
    sys.exit("image-variant: " + msg)


def read(path):
    values = {}
    with open(path, encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                name, value = line.split(None, 1)
                values[name] = value
    return values


def blob(tar, digest):
    m = re.fullmatch("sha256:([0-9a-f]{64})", digest or "")
    if not m:
        die(f"bad digest {digest!r} in the GCP OCI archive")
    try:
        data = tar.extractfile("blobs/sha256/" + m.group(1)).read()
    except (KeyError, AttributeError):
        die(f"no blob {digest} in the GCP OCI archive")
    if hashlib.sha256(data).hexdigest() != m.group(1):
        die(f"blob {digest} does not match its digest")
    return json.loads(data)


def gcp_log_redirect(path, digest):
    with tarfile.open(path) as tar:
        try:
            index = json.load(tar.extractfile("index.json"))
        except (KeyError, AttributeError):
            die(f"no index.json in {path}")
        if digest not in [m.get("digest") for m in index.get("manifests", [])]:
            die(f"{path} has no manifest {digest} (gcp.image)")
        config = blob(tar, blob(tar, digest)["config"]["digest"])
    labels = (config.get("config") or {}).get("Labels") or {}
    return labels.get("tee.launch_policy.log_redirect")


def observed(fingerprints, gcp_tar, policies):
    """The GCP log_redirect label and, per policy, the allow_stdio_access
    values found. Each policy must be the measured one."""
    v = read(fingerprints)
    redirect = gcp_log_redirect(gcp_tar, v.get("gcp.image"))
    stdio = []
    for p in policies:
        with open(p, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != v.get("azure.cce_policy"):
            die(f"{p} is not the measured CCE policy (azure.cce_policy)")
        stdio.append({x.decode() for x in re.findall(rb'"allow_stdio_access"\s*:\s*(true|false)', data)})
    return redirect, stdio


def main():
    if len(sys.argv) < 5 or sys.argv[1] not in [*WANT, "detect"]:
        die("usage: image-variant.py prod|test|detect FINGERPRINTS GCP_OCI_TAR AZURE_POLICY...")
    variant, fingerprints, gcp_tar, policies = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    got, stdio = observed(fingerprints, gcp_tar, policies)
    if variant == "detect":
        # detect: print the one variant the images are of.
        for name, (redirect, flag) in WANT.items():
            if got == redirect and all(found == {flag} for found in stdio):
                print(name)
                return
        seen = [sorted(found) or "none" for found in stdio]
        die(f"the images are of no one variant: GCP log_redirect {got!r}, Azure allow_stdio_access {seen}")
    redirect, flag = WANT[variant]
    if got != redirect:
        die(f"the GCP image has log_redirect {got!r}, a {variant} image has {redirect!r}")
    for p, found in zip(policies, stdio):
        if found != {flag}:
            die(f"{p} has allow_stdio_access {sorted(found) or 'none'}, a {variant} image has {flag}")
    print(f"image-variant: {variant}: GCP log_redirect {redirect}, Azure allow_stdio_access {flag} in {len(policies)} policies")


if __name__ == "__main__":
    main()
