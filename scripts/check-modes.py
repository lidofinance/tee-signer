#!/usr/bin/env python3
"""Mode guard: every shell script that is run as a command is executable in git.

  python3 -B scripts/check-modes.py [dir]     default: this repo

Two rules, on the git index (git ls-files -s), so a checkout gets the mode:
  - a tracked *.sh with a #! line has mode 100755; a script without one is
    sourced (common.sh) and needs no executable bit;
  - a *.sh that a Markdown file or the Makefile runs as a command, in a
    code block or a code span of more than one word, as "x.sh", "./x.sh"
    or "dir/x.sh" (after any VAR=value words), is tracked with mode
    100755. "bash x.sh" and ". x.sh" do not need the bit and are not
    checked.
"""
import os
import re
import shlex
import subprocess
import sys

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), ".."))
os.chdir(root)

modes = {}
for line in subprocess.run(["git", "ls-files", "-s"], check=True, capture_output=True, text=True).stdout.splitlines():
    meta, path = line.split("\t", 1)
    modes[path] = meta.split()[0]

fail = []
for path, mode in sorted(modes.items()):
    if not path.endswith(".sh") or "/third_party/" in "/" + path:
        continue
    with open(path, "rb") as f:
        shebang = f.read(2) == b"#!"
    if shebang and mode != "100755":
        fail.append(f"{path}: has a #! line but mode {mode}; run git update-index --chmod=+x {path}")

ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SCRIPT = re.compile(r"^(\./)?[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\.sh$")


def commands(text):
    """The first word of each command in a line of shell, after VAR=value words."""
    for part in re.split(r"&&|\|\||[;|(]", text):
        try:
            words = shlex.split(part.strip().removeprefix("$ "), comments=True)
        except ValueError:
            words = part.split()
        while words and (ASSIGN.match(words[0]) or words[0] in ("sudo", "env", "time", "exec")):
            words = words[1:]
        if words:
            yield words[0]


def resolve(doc, name):
    """The tracked path a doc's script name points to, from the root or the doc's folder."""
    for base in ("", os.path.dirname(doc)):
        p = os.path.normpath(os.path.join(base, name))
        if p in modes:
            return p
    return None


docs = [p for p in modes if p.endswith(".md") and "/third_party/" not in "/" + p] + ["Makefile"]
for doc in sorted(docs):
    if not os.path.exists(doc):
        continue
    with open(doc, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    fenced = False
    for n, line in enumerate(lines, 1):
        if doc.endswith(".md") and line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if doc == "Makefile":
            spans = [line[1:]] if line.startswith("\t") else []
        elif fenced:
            spans = [line]
        else:
            # A code span that is one word names a file; one with more
            # words (arguments, VAR=value) is a command line.
            spans = [s for s in re.findall(r"`([^`]+)`", line) if len(s.split()) > 1]
        for span in spans:
            for cmd in commands(span):
                if not SCRIPT.match(cmd):
                    continue
                p = resolve(doc, cmd)
                if p and modes[p] != "100755":
                    fail.append(f"{doc}:{n}: runs {cmd}, but {p} has mode {modes[p]}; run git update-index --chmod=+x {p}")

for f in fail:
    print("check-modes:", f)
if fail:
    sys.exit(1)
print("check-modes: every script run as a command is executable")
