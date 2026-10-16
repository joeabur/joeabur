#!/usr/bin/env python3
"""Regenerate examples/synthetic-evidence from the synthetic fake macOS filesystem.

Developer tool: the committed output is already in the repository.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from rootfs_builder import HOME, NOW, build_rootfs, fake_runner, fake_runner_factory  # noqa: E402

from mac_ir.collect import run_collection  # noqa: E402
from mac_ir.config import load_config, redaction_patterns  # noqa: E402
from mac_ir.context import Context  # noqa: E402
from mac_ir.utils.redact import Redactor  # noqa: E402


def _patch_environment() -> None:
    """Make the output independent of the machine that generates it (OS, tools, uid, wall-clock times)."""
    import mac_ir.collect as collect_mod
    import mac_ir.collectors.inventory as inv_mod
    import mac_ir.platform_info as pi

    real = pi.detect_platform

    def synthetic() -> dict:
        d = real()
        d.update(
            system="Darwin",
            is_macos=True,
            product_version="14.4.1",
            major_version=14,
            version_supported=True,
            pretty_name="macOS 14.4.1",
            kernel="23.4.0",
            architecture="arm64",
            architecture_supported=True,
            python="3.12.0",
            euid=501,
            is_root=False,
            timestamp_utc="2026-03-10T12:00:00Z",
            tools={t: f"/usr/bin/{t}" for t in ("sw_vers", "ps", "lsof", "netstat", "ifconfig", "log")},
        )
        return d

    inv_mod.detect_platform = synthetic
    collect_mod.detect_platform = synthetic
    collect_mod.euid = lambda: 501
    collect_mod.utcnow_iso = lambda: "2026-03-10T12:00:00Z"


def make(dest_parent: Path, name: str, baseline: bool) -> Path:
    cfg = load_config()
    runner = fake_runner
    with tempfile.TemporaryDirectory() as td:
        root = build_rootfs(Path(td) / "rootfs")
        if baseline:  # earlier "known good" state without the suspicious additions
            for rel in (
                "Library/LaunchDaemons/com.example.updater.plist",
                "private/tmp/.cache/kworker-upd",
                f"{HOME}/Library/LaunchAgents/com.example.agent.plist",
            ):
                (root / rel).unlink()
            runner = fake_runner_factory()
        ctx = Context(
            config=cfg,
            redactor=Redactor(redaction_patterns(cfg), True),
            deep=True,
            root=root,
            runner=runner,
            now=NOW,
            home=root / HOME,
            hostname="synthetic-mac",
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
