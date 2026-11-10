#!/usr/bin/env python3
"""Tests of cce-policy-check.py, offline. The good policies in testdata are
az confcom 2.3.0 output for testdata/template-runner.json and a stand-in
runner image (testdata/images-runner.json holds what deploy.sh read from
that image). Each tampered policy changes one thing in the good one and
must be refused."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CHECK = HERE / "cce-policy-check.py"
DATA = HERE / "testdata"
GOOD = (DATA / "policy-runner.rego").read_text()
PREFIX = "containers := "


def run(*args):
    return subprocess.run([sys.executable, "-I", str(CHECK), *map(str, args)], capture_output=True, text=True)


def containers(text):
    line = next(l for l in text.split("\n") if l.startswith(PREFIX))
    return json.loads(line[len(PREFIX):])


def with_containers(text, cs):
    old = next(l for l in text.split("\n") if l.startswith(PREFIX))
    return text.replace(old, PREFIX + json.dumps(cs, separators=(",", ":"), sort_keys=True))


def edit_runner(fn):
    cs = containers(GOOD)
    fn(next(c for c in cs if c["name"] == "runner"))
    return with_containers(GOOD, cs)


class CheckTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def check(self, policy, stdio="enable", images=None, template=None):
        p = self.dir / "policy.rego"
        p.write_text(policy)
        img = DATA / "images-runner.json"
        if images is not None:
            img = self.dir / "images.json"
            img.write_text(json.dumps(images))
        tpl = DATA / "template-runner.json"
        if template is not None:
            tpl = self.dir / "template.json"
            tpl.write_text(json.dumps(template))
        return run("check", p, tpl, img, stdio)

    def refused(self, policy, want, **kw):
        r = self.check(policy, **kw)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(want, r.stderr)

    def test_confcom_policy_passes(self):
        r = self.check(GOOD)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_confcom_policy_without_stdio_passes(self):
        r = self.check((DATA / "policy-runner-no-stdio.rego").read_text(), stdio="disable")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_stdio_setting_must_match(self):
        self.refused(GOOD, "allow_stdio_access", stdio="disable")

    def test_exec_process_refused(self):
        self.refused(edit_runner(lambda c: c.update(exec_processes=[{"command": ["/bin/sh"], "signals": []}])),
                     "container runner: exec_processes")

    def test_elevated_refused(self):
        self.refused(edit_runner(lambda c: c.update(allow_elevated=True)), "container runner: allow_elevated")

    def test_extra_capability_refused(self):
        self.refused(edit_runner(lambda c: c["capabilities"]["bounding"].append("CAP_SYS_ADMIN")),
                     "container runner: capabilities")

    def test_extra_mount_refused(self):
        self.refused(edit_runner(lambda c: c["mounts"].append(
            {"destination": "/host", "options": ["rbind", "rw"], "source": "sandbox:///.+", "type": "bind"})),
            "container runner: mounts")

    def test_extra_container_refused(self):
        cs = containers(GOOD)
        extra = dict(next(c for c in cs if c["name"] == "runner"), name="shell", command=["/bin/sh"])
        self.refused(with_containers(GOOD, cs + [extra]), "containers: shell")

    def test_second_runner_refused(self):
        cs = containers(GOOD)
        self.refused(with_containers(GOOD, cs + [next(c for c in cs if c["name"] == "runner")]), "more than once")

    def test_missing_pause_container_refused(self):
        cs = [c for c in containers(GOOD) if c["name"] != "pause-container"]
        self.refused(with_containers(GOOD, cs), "pause-container")

    def test_other_pause_container_refused(self):
        cs = containers(GOOD)
        next(c for c in cs if c["name"] == "pause-container")["command"] = ["/bin/sh"]
        self.refused(with_containers(GOOD, cs), "container pause-container: command")

    def test_wrong_layer_refused(self):
        self.refused(edit_runner(lambda c: c["layers"].__setitem__(1, "00" * 32)), "container runner: layers")

    def test_other_image_layers_refused(self):
        images = json.loads((DATA / "images-runner.json").read_text())
        images["runner"]["layers"] = ["11" * 32]
        self.refused(GOOD, "container runner: layers", images=images)

    def test_other_command_refused(self):
        self.refused(edit_runner(lambda c: c["command"].append("-debug")), "container runner: command")

    def test_extra_env_rule_refused(self):
        self.refused(edit_runner(lambda c: c["env_rules"].append({"pattern": "GODEBUG=.*", "required": False, "strategy": "re2"})),
                     "container runner: env_rules")

    def test_wider_env_rule_refused(self):
        def widen(c):
            for r in c["env_rules"]:
                if r["pattern"] == "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin":
                    r.update(pattern="PATH=.*", strategy="re2")
        self.refused(edit_runner(widen), "container runner: env_rules")

    def test_env_rule_order_does_not_matter(self):
        r = self.check(edit_runner(lambda c: c["env_rules"].reverse()))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_debug_flags_refused(self):
        for flag in ("allow_dump_stacks", "allow_runtime_logging", "allow_unencrypted_scratch"):
            with self.subTest(flag=flag):
                self.refused(GOOD.replace(f"{flag} := false", f"{flag} := true"), "differs from the policy confcom 2.3.0 writes")

    def test_rule_override_refused(self):
        self.refused(GOOD.replace("exec_in_container := data.framework.exec_in_container",
                                  'exec_in_container := {"allowed": true}'), "differs from the policy confcom 2.3.0 writes")

    def test_added_rule_refused(self):
        self.refused(GOOD + '\nexec_external := {"allowed": true}', "differs from the policy confcom 2.3.0 writes")

    def test_other_fragment_refused(self):
        self.refused(GOOD.replace("mcr.microsoft.com/aci/aci-cc-infra-fragment", "example.com/fragment"),
                     "differs from the policy confcom 2.3.0 writes")

    def test_other_api_version_refused(self):
        self.refused(GOOD.replace('api_version := "0.11.0"', 'api_version := "0.10.0"'),
                     "differs from the policy confcom 2.3.0 writes")

    def test_duplicate_key_refused(self):
        line = next(l for l in GOOD.split("\n") if l.startswith(PREFIX))
        self.refused(GOOD.replace(line, line.replace('"allow_elevated":false', '"allow_elevated":true,"allow_elevated":false', 1)),
                     "duplicate key")

    def test_not_a_policy_refused(self):
        self.refused("policy", "differs from the policy confcom 2.3.0 writes")

    def test_template_env_literal_is_exact_rule(self):
        tpl = json.loads((DATA / "template-runner.json").read_text())
        env = tpl["resources"][0]["properties"]["containers"][0]["properties"]["environmentVariables"]
        env.append({"name": "MODE", "value": "fixed"})
        cs = containers(GOOD)
        next(c for c in cs if c["name"] == "runner")["env_rules"].insert(
            1, {"pattern": "MODE=fixed", "required": False, "strategy": "string"})
        r = self.check(with_containers(GOOD, cs), template=tpl)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unmodelled_template_property_refused(self):
        tpl = json.loads((DATA / "template-runner.json").read_text())
        tpl["resources"][0]["properties"]["containers"][0]["properties"]["securityContext"] = {"privileged": True}
        self.refused(GOOD, "securityContext", template=tpl)

    def test_image_user_refused(self):
        images = json.loads((DATA / "images-runner.json").read_text())
        images["runner"]["user"] = "1000"
        self.refused(GOOD, "user", images=images)

    def test_render_matches_confcom(self):
        r = run("render", DATA / "template-runner.json", DATA / "images-runner.json", "enable")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, GOOD)


if __name__ == "__main__":
    unittest.main()
