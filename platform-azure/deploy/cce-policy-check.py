#!/usr/bin/env python3
"""Checks the CCE policy that az confcom wrote, before deploy.sh prints or
pins its hash.

  cce-policy-check.py check POLICY TEMPLATE IMAGES STDIO
  cce-policy-check.py render TEMPLATE IMAGES STDIO

POLICY is the decoded policy (policy.rego), TEMPLATE the rendered template
that az confcom read, STDIO enable or disable. IMAGES is JSON that deploy.sh
writes from the local images, one entry per container name of TEMPLATE:

  {"runner": {"layers": [...], "env": ["PATH=..."], "working_dir": "/",
              "user": "", "stop_signal": ""}}

layers are the dm-verity root hashes that dmverity-vhd gives for the image,
the rest comes from the image config (docker image inspect).

render prints the policy that confcom 2.3.0 writes for TEMPLATE and IMAGES.
check refuses POLICY unless:
  - every line outside the containers list is the text confcom 2.3.0
    writes: API and framework versions, the one Microsoft infrastructure
    fragment, the flags (no stack dumps, no runtime logging, no
    unencrypted scratch) and every rule bound to the framework;
  - the containers list is canonical JSON with no duplicate key;
  - it holds each template container once, plus confcom's pause container,
    and nothing else;
  - each container equals the one built from the template and its image:
    the template's command, the image's layer hashes, no exec process, not
    elevated, the default capabilities, the resolv.conf mount only, and env
    rules that are the template's variables (a literal value gives an exact
    rule, a parameter without a default gives NAME=.*), the image's own
    variables and confcom's fixed infrastructure rules. Their order does
    not matter.

Python standard library only.
"""

import json
import sys

HEADER = """package policy

import future.keywords.every
import future.keywords.in

api_version := "0.11.0"
framework_version := "0.2.3"

fragments := [
  {
    "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
    "minimum_svn": "4"
  }
]

containers := """

RULES = ["mount_device", "unmount_device", "mount_overlay", "unmount_overlay", "create_container",
         "exec_in_container", "exec_external", "shutdown_container", "signal_container_process",
         "plan9_mount", "plan9_unmount", "get_properties", "dump_stacks", "runtime_logging",
         "load_fragment", "scratch_mount", "scratch_unmount", "rw_mount_device"]

FOOTER = """

allow_properties_access := true
allow_dump_stacks := false
allow_runtime_logging := false
allow_environment_variable_dropping := true
allow_unencrypted_scratch := false
allow_capability_dropping := true

""" + "".join(f"{r} := data.framework.{r}\n" for r in RULES) + """
reason := {"errors": data.framework.errors}"""

CAPS = ["CAP_AUDIT_WRITE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
        "CAP_MKNOD", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP",
        "CAP_SETUID", "CAP_SYS_CHROOT"]
PAUSE_CAPS = ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
              "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
              "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"]
# confcom adds these to every Linux container: the TERM rule, then the
# fabric, managed identity and restart rules (internal_config.json).
INFRA_ENV = [("TERM=xterm", "string")] + [(p, "re2") for p in [
    "(?i)(FABRIC)_.+=.+", "HOSTNAME=.+", "T(E)?MP=.+", "FabricPackageFileName=.+", "HostedServiceName=.+",
    "IDENTITY_API_VERSION=.+", "IDENTITY_HEADER=.+", "IDENTITY_SERVER_THUMBPRINT=.+",
    "azurecontainerinstance_restarted_by=.+"]]
RESOLV_MOUNT = {"destination": "/etc/resolv.conf", "options": ["rbind", "rshared", "rw"],
                "source": "sandbox:///tmp/atlas/resolvconf/.+", "type": "bind"}
ANY_USER = {"group_idnames": [{"pattern": "", "strategy": "any"}], "umask": "0022",
            "user_idname": {"pattern": "", "strategy": "any"}}
PAUSE_NAME = "pause-container"
PAUSE_LAYER = "16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"
# Container properties of the template that this check models. Others
# (volumeMounts, securityContext, probes) change the policy in ways it does
# not rebuild, so it refuses them.
KNOWN_PROPERTIES = {"image", "command", "ports", "environmentVariables", "resources"}


class Refused(Exception):
    pass


def caps(names):
    return {"ambient": [], "bounding": names, "effective": names, "inheritable": [], "permitted": names}


def env_rule(pattern, strategy, required=False):
    return {"pattern": pattern, "required": required, "strategy": strategy}


def no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Refused(f"duplicate key {k!r} in the containers list")
        out[k] = v
    return out


def template_env(template, container):
    """The env rules confcom makes from a container's environmentVariables."""
    params = template.get("parameters", {})
    rules = []
    for var in container["properties"].get("environmentVariables", []):
        name = var["name"]
        values = [var[k] for k in ("value", "secureValue") if k in var]
        if len(values) != 1 or not isinstance(values[0], str):
            raise Refused(f"container {container['name']}: variable {name} needs one string value or secureValue")
        value = values[0]
        if value.startswith("["):
            p = value.removeprefix("[parameters('").removesuffix("')]")
            if value != f"[parameters('{p}')]" or p not in params:
                raise Refused(f"container {container['name']}: variable {name} is {value}; only a literal or [parameters('x')] is checked")
            if "defaultValue" in params[p]:
                rules.append(env_rule(f"{name}={params[p]['defaultValue']}", "string"))
            else:
                rules.append(env_rule(f"{name}=.*", "re2"))
        else:
            rules.append(env_rule(f"{name}={value}", "string"))
    return rules


def expected_containers(template, images, stdio):
    try:
        group = template["resources"][0]["properties"]
        tcs = group["containers"]
    except (KeyError, IndexError, TypeError):
        raise Refused("the template has no container group with containers")
    out = []
    for tc in tcs:
        name = tc["name"]
        props = tc["properties"]
        extra = sorted(set(props) - KNOWN_PROPERTIES)
        if extra:
            raise Refused(f"container {name}: template property {', '.join(extra)} is not modelled by this check")
        command = props.get("command")
        if not isinstance(command, list) or not all(isinstance(a, str) and not a.startswith("[") for a in command):
            raise Refused(f"container {name}: the template command must be a list of literal strings")
        img = images.get(name)
        if img is None:
            raise Refused(f"container {name}: no image facts")
        if img.get("user", ""):
            raise Refused(f"container {name}: the image sets user {img['user']!r}; this check models the default user only")
        if img.get("stop_signal", ""):
            raise Refused(f"container {name}: the image sets stop signal {img['stop_signal']!r}; this check models the default only")
        layers = img.get("layers")
        if not layers or not all(isinstance(h, str) and len(h) == 64 for h in layers):
            raise Refused(f"container {name}: no layer hashes for its image")
        env = template_env(template, tc) + [env_rule(e, "string") for e in img.get("env", [])]
        env += [env_rule(p, s) for p, s in INFRA_ENV]
        out.append({
            "allow_elevated": False, "allow_stdio_access": stdio, "capabilities": caps(CAPS),
            "command": command, "env_rules": env, "exec_processes": [], "layers": layers,
            "mounts": [RESOLV_MOUNT], "name": name, "no_new_privileges": False,
            "seccomp_profile_sha256": "", "signals": [9, 15], "user": ANY_USER,
            "working_dir": img.get("working_dir") or "/",
        })
    out.append({
        "allow_elevated": False, "allow_stdio_access": stdio, "capabilities": caps(PAUSE_CAPS),
        "command": ["/pause"],
        "env_rules": [env_rule("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "string", True),
                      env_rule("TERM=xterm", "string")],
        "exec_processes": [], "layers": [PAUSE_LAYER], "mounts": [], "name": PAUSE_NAME,
        "no_new_privileges": False, "seccomp_profile_sha256": "", "signals": [9, 15], "user": ANY_USER,
        "working_dir": "/",
    })
    return out


def text_of(cs):
    return HEADER + json.dumps(cs, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + FOOTER


def short(v):
    s = json.dumps(v, sort_keys=True)
    return s if len(s) <= 300 else s[:300] + "..."


def comparable(c):
    c = dict(c)
    if isinstance(c.get("env_rules"), list):
        c["env_rules"] = sorted(c["env_rules"], key=lambda r: json.dumps(r, sort_keys=True))
    return c


def check(policy, template, images, stdio):
    if not policy.startswith(HEADER):
        raise Refused("the policy text before the containers list differs from the policy confcom 2.3.0 writes")
    line, sep, _ = policy[len(HEADER):].partition("\n")
    if not sep:
        raise Refused("the policy text differs from the policy confcom 2.3.0 writes")
    try:
        got = json.loads(line, object_pairs_hook=no_duplicates)
    except ValueError as e:
        raise Refused(f"the containers list is not JSON: {e}")
    if not isinstance(got, list) or not all(isinstance(c, dict) and isinstance(c.get("name"), str) for c in got):
        raise Refused("the containers list is not a list of named containers")
    if policy != text_of(got):
        raise Refused("the policy text around or in the containers list differs from the policy confcom 2.3.0 writes")
    want = expected_containers(template, images, stdio)
    names = [c["name"] for c in got]
    for n in sorted(set(names)):
        if names.count(n) > 1:
            raise Refused(f"container {n} is in the policy more than once")
    want_by = {c["name"]: c for c in want}
    extra = sorted(set(names) - set(want_by))
    missing = sorted(set(want_by) - set(names))
    if extra or missing:
        raise Refused(f"containers: {', '.join(extra) or 'none'} not in the template; missing: {', '.join(missing) or 'none'}")
    problems = []
    for c in got:
        g, w = comparable(c), comparable(want_by[c["name"]])
        for k in sorted(set(g) | set(w)):
            # Compared as JSON text: in Python 0 == False and 1 == True,
            # but the policy language reads 0 as true.
            if json.dumps(g.get(k), sort_keys=True) != json.dumps(w.get(k), sort_keys=True):
                problems.append(f"container {c['name']}: {k} is {short(g.get(k))}, want {short(w.get(k))}")
    if problems:
        raise Refused("\n".join(problems))


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def stdio_flag(arg):
    if arg not in ("enable", "disable"):
        raise Refused("STDIO must be enable or disable")
    return arg == "enable"


def main(argv):
    try:
        if len(argv) == 5 and argv[0] == "check":
            with open(argv[1], encoding="utf-8", newline="") as f:
                policy = f.read()
            check(policy, load_json(argv[2]), load_json(argv[3]), stdio_flag(argv[4]))
            return 0
        if len(argv) == 4 and argv[0] == "render":
            sys.stdout.write(text_of(expected_containers(load_json(argv[1]), load_json(argv[2]), stdio_flag(argv[3]))))
            return 0
    except Refused as e:
        print(f"CCE policy refused: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        # Unreadable or malformed input: refuse with the cause, no traceback.
        print(f"CCE policy refused: cannot read the input: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
