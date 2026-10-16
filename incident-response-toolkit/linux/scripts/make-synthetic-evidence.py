#!/usr/bin/env python3
"""Regenerate examples/synthetic-evidence from the synthetic fake root filesystem.

Developer tool: the committed output is already in the repository. Usage:
    python scripts/make-synthetic-evidence.py [--baseline]
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from rootfs_builder import NOW, build_rootfs, fake_runner  # noqa: E402

from linux_ir.collect import run_collection  # noqa: E402
from linux_ir.config import load_config, redaction_patterns  # noqa: E402
from linux_ir.context import Context  # noqa: E402
from linux_ir.utils.redact import Redactor  # noqa: E402


def _patch_environment() -> None:
    """Make the output independent of the machine that generates it (kernel, tools, uid, wall-clock times)."""
    import linux_ir.collect as collect_mod
    import linux_ir.collectors.inventory as inv_mod
    import linux_ir.platform_info as pi

    real = pi.detect_platform

    def synthetic(root: Path = Path("/")) -> dict:
        d = real(root)
        d.update(
            kernel="5.15.0-synthetic",
            architecture="x86_64",
            architecture_supported=True,
            python="3.12.0",
            euid=1000,
            is_root=False,
            container=None,
            timestamp_utc="2026-03-10T12:00:00Z",
            tools={t: f"/usr/bin/{t}" for t in ("ss", "ip", "journalctl", "systemctl", "who")},
        )
        return d

    inv_mod.detect_platform = synthetic
    collect_mod.detect_platform = synthetic
    collect_mod.euid = lambda: 1000
    collect_mod.utcnow_iso = lambda: "2026-03-10T12:00:00Z"


def make(dest_parent: Path, name: str, baseline: bool) -> Path:
    cfg = load_config()
    with tempfile.TemporaryDirectory() as td:
        root = build_rootfs(Path(td) / "rootfs")
        if baseline:  # a "known good" earlier state: remove the suspicious additions
            for rel in (
                "etc/systemd/system/evil-updater.service",
                "tmp/.cache/kworker-upd",
                "etc/ld.so.preload",
                "etc/systemd/system/multi-user.target.wants/evil-updater.service",
            ):
                (root / rel).unlink()
        ctx = Context(
            config=cfg,
            redactor=Redactor(redaction_patterns(cfg), True),
            deep=True,
            root=root,
            runner=fake_runner,
            now=NOW,
            home=root / "home/analyst",
            hostname="synthetic-host",
            log_window_hours=24,
        )
        out = dest_parent / name
        if out.exists():
            shutil.rmtree(out)
        evdir, _, _ = run_collection(
            ctx, "extended", ["inventory", "processes", "network", "persistence", "logs", "files"], Path(td) / "out"
        )
        shutil.copytree(evdir, out)
    return out


if __name__ == "__main__":
    _patch_environment()
    base = ROOT / "examples" / "synthetic-evidence"
    print(make(base, "case-001", False))
    print(make(base, "baseline", True))
