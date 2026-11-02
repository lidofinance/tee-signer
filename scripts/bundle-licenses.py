#!/usr/bin/env python3
"""Write <binary>.licenses/ beside each Go binary, using its build metadata.

Uses only the standard library and already-cached Go modules; no network access.
The bundle is attribution material, not an audit of redistribution obligations.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent.parent
FIRST_PARTY = "github.com/lidofinance/tee-signer/"
CARGO_LOCK = ROOT / "trusted-time/rust/Cargo.lock"
CARGO_HOME = ROOT / "build/nts/cargo-home"
NOTICE_NAME = re.compile(r"^(licen[sc]e|copying|copyright|notice|patents)([._-].*)?$", re.I)


def run(*args):
    return subprocess.check_output(args, text=True, env={
        **os.environ, "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off",
    })


def notice_files(directory):
    return sorted(p for p in directory.rglob("*") if p.is_file() and NOTICE_NAME.match(p.name))


def add_notices(sections, label, directory):
    files = notice_files(directory)
    if not files:
        raise ValueError(f"{label}: no licence or notice files in {directory}")
    for path in files:
        sections.append((f"{label} / {path.relative_to(directory).as_posix()}",
                         path.read_text(encoding="utf-8")))


def lock_crates(lock_text):
    """(name, version, sha256) of each crate in a Cargo.lock that has a checksum."""
    try:
        import tomllib
    except ImportError:  # Python 3.10: Cargo.lock is flat enough to read by line.
        packages, package = [], None
        for line in lock_text.splitlines():
            line = line.strip()
            if line == "[[package]]":
                package = {}
                packages.append(package)
            elif line.startswith("["):
                package = None
            elif package is not None and " = " in line:
                key, value = line.split(" = ", 1)
                if value.startswith('"') and value.endswith('"'):
                    package[key] = value[1:-1]
    else:
        packages = tomllib.loads(lock_text).get("package", [])
    return sorted((p["name"], p["version"], p["checksum"]) for p in packages if "checksum" in p)


def add_crate_notices(sections, lock, cargo_home):
    """Notices of every crates.io crate of the lock, read from its .crate archive
    in the cargo home after checking the archive against the lock's sha256."""
    for name, version, checksum in lock_crates(lock.read_text()):
        archives = sorted((cargo_home / "registry/cache").glob(f"*/{name}-{version}.crate"))
        if not archives:
            raise ValueError(f"Rust crate {name} {version}: no archive in {cargo_home}: run scripts/fetch-nts.sh")
        for archive in archives:
            data = archive.read_bytes()
            if hashlib.sha256(data).hexdigest() != checksum:
                raise ValueError(f"Rust crate {name} {version}: {archive} differs from its sha256 in {lock.name}")
        with tempfile.TemporaryDirectory() as tmp, tarfile.open(fileobj=io.BytesIO(data)) as tar:
            # Only plain files and folders below the crate's folder. Python
            # before 3.12 has no extraction filter, so check every member.
            for member in tar.getmembers():
                if (member.name.startswith("/") or ".." in PurePosixPath(member.name).parts
                        or not (member.isfile() or member.isdir())):
                    raise ValueError(f"Rust crate {name} {version}: {archive} holds {member.name!r},"
                                     " a link, a special file or a path outside the crate")
            if hasattr(tarfile, "data_filter"):
                tar.extractall(tmp, filter="data")
            else:
                tar.extractall(tmp)
            add_notices(sections, f"Rust crate {name}-{version}", Path(tmp) / f"{name}-{version}")


def collect(binary, module_dirs):
    info = json.loads(run("go", "version", "-m", "-json", str(binary)))
    settings = {s["Key"]: s["Value"] for s in info.get("Settings", [])}
    goversion = run("go", "env", "GOVERSION").strip()
    if info["GoVersion"] != goversion:
        raise ValueError(f"{binary}: use the Go toolchain that built it ({info['GoVersion']})")
    sections = []
    goroot = Path(run("go", "env", "GOROOT").strip())
    # Official Go archives put LICENSE in GOROOT; some distributions split it out.
    go_license = Path(os.environ.get("GO_LICENSE_DIR", goroot)) / "LICENSE"
    if not go_license.is_file() and "GO_LICENSE_DIR" not in os.environ:
        go_license = Path("/usr/share/licenses/go/LICENSE")
    sections.append((f"Go {goversion} / LICENSE", go_license.read_text()))
    if (goroot / "PATENTS").is_file():
        sections.append((f"Go {goversion} / PATENTS", (goroot / "PATENTS").read_text()))
    # The standard library embeds vendored packages that are absent from Deps.
    add_notices(sections, f"Go {goversion} / src/vendor", goroot / "src/vendor")
    deps = info.get("Deps", [])
    for dep in sorted(deps, key=lambda d: d["Path"]):
        if dep["Path"].startswith(FIRST_PARTY):
            continue
        actual = dep.get("Replace", dep)
        if actual.get("Version", "") in ("", "(devel)"):
            raise ValueError(f"{dep['Path']}: external local replacements need a licence review")
        module = f"{actual['Path']}@{actual['Version']}"
        if module not in module_dirs:
            module_dirs[module] = Path(json.loads(run("go", "mod", "download", "-json", module))["Dir"])
        add_notices(sections, module, module_dirs[module])
        # Its precompiled native archive's upstream notices are not in the module.
        if actual["Path"] == "github.com/pk910/hashtree-bindings":
            raise ValueError("hashtree-bindings needs its native upstream notices before distribution")
    if any(d["Path"] == FIRST_PARTY + "signer-core" for d in deps):
        add_notices(sections, "blst (signer-core/third_party/blst)",
                    ROOT / "signer-core/third_party/blst")
    rust = "nts" in settings.get("-tags", "").split(",")
    if rust:
        # Every crates.io crate of Cargo.lock, build-only crates too.
        add_crate_notices(sections, CARGO_LOCK, CARGO_HOME)
    # A distributor can supply notices for its C runtime, linker runtime or overlay.
    if os.environ.get("SIGNER_EXTRA_LICENSE_DIR"):
        add_notices(sections, "Distributor-supplied notices", Path(os.environ["SIGNER_EXTRA_LICENSE_DIR"]))
    return sections, settings


def bundle(binary, module_dirs):
    sections, settings = collect(binary, module_dirs)
    extra = {}
    if "nts" in settings.get("-tags", "").split(","):
        arch = {"amd64": "x86_64", "arm64": "aarch64"}[settings["GOARCH"]]
        extra["RUST_STANDARD_LIBRARY.html"] = (
            ROOT / "build/nts" / arch / "licenses/RUST_STANDARD_LIBRARY.html").read_bytes()
    text = ("Third-party licences and notices for " + binary.name + "\n"
            "Binary SHA-256: " + hashlib.sha256(binary.read_bytes()).hexdigest() + "\n\n"
            "Third-party components retain their own terms. Some notice sets include\n"
            "files not linked into this binary; this is not a package or audit scope list.\n\n")
    for title, contents in sections:
        text += "=" * 72 + "\n" + title + "\n" + "=" * 72 + "\n" + contents.rstrip() + "\n\n"
    extra.update({"LICENSE": (ROOT / "LICENSE").read_bytes(),
                  "THIRD_PARTY_NOTICES": text.encode("utf-8")})
    # Finish collecting first: a missing dependency notice must fail the build.
    out = Path(str(binary) + ".licenses")
    out.mkdir(exist_ok=True, mode=0o755)
    out.chmod(0o755)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES", "RUST_STANDARD_LIBRARY.html"):
        path = out / name
        if name in extra:
            path.write_bytes(extra[name])
            path.chmod(0o644)
        elif path.exists():
            path.unlink()
    print(f"licences: {binary.name}: {len(sections)} notice files -> {out}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="+", type=Path)
    args = parser.parse_args()
    module_dirs = {}
    for binary in args.binaries:
        bundle(binary.resolve(), module_dirs)


if __name__ == "__main__":
    main()
