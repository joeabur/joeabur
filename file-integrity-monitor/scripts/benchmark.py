"""Synthetic scale benchmark: builds a tree of small files plus one large file in a temp dir,
then measures baseline create / scan / 1-change scan wall time and peak RSS of the fim child.

Usage: python scripts/benchmark.py [--files N] [--big-mib M] [--dirs D]
Only creates and deletes its own mkdtemp() workspace.
"""

from __future__ import annotations

import argparse
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(cmd: list[str]) -> tuple[float, float, str]:
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    t0 = time.monotonic()
    p = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
    wall = time.monotonic() - t0
    peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss  # max over all children so far
    return wall, max(peak_kib, before), p.stdout + f"[exit {p.returncode}]"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=300_000)
    ap.add_argument("--dirs", type=int, default=300)
    ap.add_argument("--big-mib", type=int, default=512)
    a = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix="fim-bench."))
    try:
        data, state = work / "data", work / "state"
        data.mkdir()
        per = a.files // a.dirs
        for d in range(a.dirs):
            sub = data / f"d{d:04d}"
            sub.mkdir()
            for i in range(per):
                (sub / f"f{i:05d}.txt").write_bytes(b"x" * (64 + i % 512))
        with (data / "big.bin").open("wb") as fh:
            for _ in range(a.big_mib):
                fh.write(os.urandom(1 << 20))
        cfg = work / "fim.toml"
        cfg.write_text(f'[baseline]\ndir = "{state}/b"\n[scan]\nroots = ["{data}"]\n')
        fim = [sys.executable, "-m", "fim.cli", "-c", str(cfg)]
        print(f"tree: {per * a.dirs + 1} files, {a.dirs} dirs, {a.big_mib} MiB large file")
        for label, cmd in (("baseline create", ["baseline", "create"]), ("full scan (clean)", ["scan"])):
            wall, rss, out = run([*fim, *cmd])
            print(
                f"{label:22s} {wall:7.1f} s   peak RSS {rss / 1024:7.0f} MiB   {out.strip().splitlines()[-1]}"
            )
        bl = max((state / "b").glob("baseline-*.json"), key=lambda p: p.stat().st_size)
        print(f"baseline file size     {bl.stat().st_size / 2**20:7.1f} MiB")
        with (data / "d0010" / "f00001.txt").open("ab") as fh:
            fh.write(b"tamper")
        wall, rss, out = run([*fim, "scan", "-q"])
        print(
            f"full scan (1 change)   {wall:7.1f} s   peak RSS {rss / 1024:7.0f} MiB   {out.strip().splitlines()[-1]}"
        )
    finally:
        if work.name.startswith("fim-bench.") and work.parent == Path(tempfile.gettempdir()):
            shutil.rmtree(work)


if __name__ == "__main__":
    main()
