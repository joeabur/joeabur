"""Helpers that extract and execute fenced code blocks from the Markdown docs.

Conventions (see CONTRIBUTING.md):
  <!-- fim-test:run -->      next ```bash block is executed by the test-suite (in order, one shell)
  <!-- fim-test:expect -->   next ```text block is *illustrative output* that must match the real
                             output of the preceding run block after normalising volatile values
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK_RE = re.compile(r"^<!--\s*fim-test:(run|expect)\s*-->$")


@dataclass
class Block:
    kind: str  # run | expect | plain
    lang: str
    text: str
    line: int


def parse_blocks(md: str) -> list[Block]:
    blocks: list[Block] = []
    lines = md.splitlines()
    pending: str | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        m = MARK_RE.match(line.strip())
        if m:
            pending = m.group(1)
        elif line.startswith("```"):
            lang = line[3:].strip()
            start = i + 1
            j = start
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            blocks.append(Block(pending or "plain", lang, "\n".join(lines[start:j]), i + 1))
            pending = None
            i = j
        elif line.strip():
            pending = None if not line.strip().startswith("<!--") else pending
        i += 1
    return blocks


_NORMALISERS = [
    (re.compile(r"/tmp/fim-tutorial\.[A-Za-z0-9]{6}"), "/tmp/fim-tutorial.XXXXXX"),
    (re.compile(r"\b[0-9a-f]{64}\b"), "<SHA256>"),
    (re.compile(r"\b[0-9a-f]{16}…"), "<SHA16>…"),
    (re.compile(r"\b[0-9a-f]{12}\b"), "<ID>"),
    (re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?([+-]\d\d:\d\d|Z)?"), "<TS>"),
    (re.compile(r"\brt=\d+"), "rt=<EPOCH_MS>"),
    (re.compile(r"host=\S+"), "host=<HOST>"),
    (re.compile(r"dvchost=\S+"), "dvchost=<HOST>"),
    (re.compile(r"user=\S+\(uid \d+\)"), "user=<USER>"),
    (re.compile(r'"hostname": "[^"]*"'), '"hostname": "<HOST>"'),
    (re.compile(r"sha256:[0-9a-f]{64}"), "sha256:<KEYID>"),
]


def normalise(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        for rx, rep in _NORMALISERS:
            line = rx.sub(rep, line)
        out.append(line.rstrip())
    return out


def run_blocks(blocks: list[Block], env_extra: dict[str, str] | None = None) -> dict[int, str]:
    """Run every `run` block in a single bash session; return {block index: combined output}."""
    script = ["exec 2>&1"]
    idx = [i for i, b in enumerate(blocks) if b.kind == "run"]
    for i in idx:
        script.append(f"echo '<<<FIMBLOCK {i}>>>'")
        script.append(blocks[i].text)
        script.append("")
    env = {**os.environ, "PATH": f"{ROOT}/.venv/bin:{os.environ['PATH']}", **(env_extra or {})}
    env.pop("FIM_CONFIG", None)
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", "\n".join(script)],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    outputs: dict[int, str] = {}
    current = None
    for line in proc.stdout.splitlines():
        m = re.fullmatch(r"<<<FIMBLOCK (\d+)>>>", line)
        if m:
            current = int(m.group(1))
            outputs[current] = ""
        elif current is not None:
            outputs[current] += line + "\n"
    return outputs


def expect_matches(expected: str, actual: str) -> tuple[bool, str]:
    """Every non-blank expected line (except those starting with '...') must occur, in order."""
    act = normalise(actual)
    pos = 0
    for want in normalise(expected):
        if not want.strip() or want.strip().startswith("..."):
            continue
        try:
            pos = act.index(want, pos) + 1
        except ValueError:
            return False, want
    return True, ""
