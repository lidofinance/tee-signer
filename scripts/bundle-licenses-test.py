#!/usr/bin/env python3
"""Regression checks for distribution notices; no network or native build."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bundle_licenses", Path(__file__).with_name("bundle-licenses.py"))
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "runner"
        self.binary.write_bytes(b"binary fixture")
        self.goroot = self.root / "go"
        (self.goroot / "src/vendor/example").mkdir(parents=True)
        (self.goroot / "LICENSE").write_text("Go BSD licence")
        (self.goroot / "src/vendor/example/LICENSE").write_text("vendored standard library notice")
        self.module = self.root / "module"
        self.module.mkdir()
        (self.module / "LICENSE").write_text("dependency licence")
        (self.module / "NOTICE").write_text("upstream attribution")
        self.info = {"GoVersion": "go1.26.0", "Settings": [], "Deps": [
            {"Path": "example.org/lib", "Version": "v1.0.0"},
        ]}
        env = patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        mock = patch.object(licenses, "run", side_effect=self.run_command)
        mock.start()
        self.addCleanup(mock.stop)

    def run_command(self, *args):
        if args[1:3] == ("version", "-m"):
            return json.dumps(self.info)
        if args[1:] == ("env", "GOVERSION"):
            return "go1.26.0\n"
        if args[1:] == ("env", "GOROOT"):
            return str(self.goroot)
        if args[1:4] == ("mod", "download", "-json"):
            return json.dumps({"Dir": str(self.module)})
        raise AssertionError(args)

    def test_bundle_preserves_upstream_notice_and_is_repeatable(self):
        licenses.bundle(self.binary, {})
        out = Path(str(self.binary) + ".licenses")
        before = {p.name: p.read_bytes() for p in out.iterdir()}
        text = before["THIRD_PARTY_NOTICES"].decode()
        for required in ("upstream attribution", "dependency licence", "vendored standard library notice",
                         "example.org/lib@v1.0.0", "Go BSD licence"):
            self.assertIn(required, text)
        self.assertNotIn(str(self.root), text)
        self.assertEqual(before["LICENSE"], (licenses.ROOT / "LICENSE").read_bytes())
        licenses.bundle(self.binary, {})
        self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o644 for p in out.iterdir()))

    def test_missing_dependency_notices_fail_before_writing_bundle(self):
        for p in self.module.iterdir():
            p.unlink()
        with self.assertRaisesRegex(ValueError, "no licence or notice"):
            licenses.bundle(self.binary, {})
        self.assertFalse(Path(str(self.binary) + ".licenses").exists())

    def test_native_archive_without_reviewed_notices_is_rejected(self):
        self.info["Deps"][0]["Path"] = "github.com/pk910/hashtree-bindings"
        with self.assertRaisesRegex(ValueError, "native upstream notices"):
            licenses.bundle(self.binary, {})

    def test_external_local_replacement_is_rejected(self):
        self.info["Deps"][0]["Replace"] = {"Path": "../external"}
        with self.assertRaisesRegex(ValueError, "external local replacements"):
            licenses.bundle(self.binary, {})


if __name__ == "__main__":
    unittest.main()
