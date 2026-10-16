#!/usr/bin/env python3
"""Static hygiene checks for GitHub Actions workflows (no YAML dependency, line based).

Checks, per workflow file:
  1. every ``uses:`` of a third-party action is pinned to a full 40-character commit SHA;
  2. a top-level ``permissions:`` block exists (least privilege by default);
  3. ``pull_request_target`` is not used;
  4. no ``run:`` script interpolates attacker-controllable context directly
     (``github.event.*``, ``github.head_ref``); pass such values through ``env:`` instead.

    python scripts/check_workflows.py .github/workflows
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

USES_RE = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")
DANGEROUS_RE = re.compile(r"\$\{\{\s*(github\.event\.|github\.head_ref)")
RUN_RE = re.compile(r"^(?P<indent>\s*)-?\s*run:\s*(?P<rest>.*)$")


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    if not any(re.match(r"^permissions:", line) for line in lines):
        problems.append(f"{path}: no top-level 'permissions:' block")
    run_indent: int | None = None
    for number, line in enumerate(lines, start=1):
        if re.match(r"^\s*pull_request_target\s*:", line) or re.search(r"\[.*pull_request_target.*\]", line):
            problems.append(f"{path}:{number}: pull_request_target runs untrusted code with secrets")
        uses = USES_RE.match(line)
        if uses:
            ref = uses.group("ref")
            if not ref.startswith(("./", "docker://")) and not SHA_RE.search(ref):
                problems.append(f"{path}:{number}: '{ref}' is not pinned to a full commit SHA")
            if ref.startswith("docker://") and "@sha256:" not in ref:
                problems.append(f"{path}:{number}: '{ref}' is not pinned to an image digest")
        run = RUN_RE.match(line)
        if run:
            run_indent = len(run.group("indent"))
            if DANGEROUS_RE.search(run.group("rest")):
                problems.append(f"{path}:{number}: untrusted expression interpolated into a shell command")
            if not run.group("rest").strip().startswith(("|", ">")) and run.group("rest").strip():
                run_indent = None  # single-line run
            continue
        if run_indent is not None:
            indent = len(line) - len(line.lstrip())
            if line.strip() and indent <= run_indent:
                run_indent = None
            elif DANGEROUS_RE.search(line):
                problems.append(f"{path}:{number}: untrusted expression interpolated into a shell command")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_workflows.py DIRECTORY", file=sys.stderr)
        return 2
    files = sorted(Path(argv[1]).glob("*.y*ml"))
    if not files:
        print(f"no workflow files found in {argv[1]}", file=sys.stderr)
        return 2
    problems = [p for f in files for p in check_file(f)]
    for problem in problems:
        print(problem)
    print(f"checked {len(files)} workflow file(s): {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
