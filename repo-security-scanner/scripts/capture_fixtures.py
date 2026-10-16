#!/usr/bin/env python3
"""Capture sanitised real scanner output for tests/fixtures/scanner-output/.

Requires the real scanners on PATH (and network for Trivy's DB / OSV's databases).
Run manually when a scanner schema changes; commit the result after reviewing it.

    python scripts/capture_fixtures.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from reposcan.adapters import ALL_ADAPTERS, ScanContext  # noqa: E402
from reposcan.config import Config  # noqa: E402
from reposcan.runner import read_bounded_file, run_command  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "scanner-output"
DEMO = ROOT / "sample-data" / "demo-repo"
CLEAN = ROOT / "sample-data" / "clean-repo"


def sanitise(text: str) -> str:
    text = text.replace(str(DEMO), "/repo").replace(str(CLEAN), "/repo")
    return re.sub(r"/(?:home|tmp|root)/[^\"\s]*reposcan-[^/\"]*", "/work", text)


def trim(name: str, data: object) -> object:
    if name == "semgrep" and isinstance(data, dict):
        for key in ("time", "profiling_results", "skipped_rules", "paths"):
            data.pop(key, None)
    if name == "trivy" and isinstance(data, dict):
        data.pop("ReportID", None)
        data.pop("CreatedAt", None)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                for key in (
                    "CVSS",
                    "VendorSeverity",
                    "DataSource",
                    "PublishedDate",
                    "LastModifiedDate",
                    "Layer",
                    "PkgIdentifier",
                ):
                    vuln.pop(key, None)
                vuln["References"] = vuln.get("References", [])[:3]
                vuln["Description"] = vuln.get("Description", "")[:200]
            for mis in result.get("Misconfigurations", []):
                mis["Description"] = mis.get("Description", "")[:200]
    if name == "osv-scanner" and isinstance(data, dict):
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    vuln["details"] = vuln.get("details", "")[:200]
                    vuln["references"] = vuln.get("references", [])[:3]
                    for affected in vuln.get("affected", []):
                        affected.pop("versions", None)
                        affected.pop("database_specific", None)
                        affected.pop("ecosystem_specific", None)
    return data


def capture(target: Path, suffix: str, config: Config) -> None:
    for cls in ALL_ADAPTERS:
        adapter = cls()
        with tempfile.TemporaryDirectory(prefix="reposcan-capture-") as tmp:
            ctx = ScanContext(
                target=target,
                workdir=Path(tmp),
                config=config,
                offline=False,
                timeout=300,
                max_output_bytes=64 * 1024 * 1024,
            )
            exe, _ = adapter.discover(ctx)
            report = Path(tmp) / "report.json"
            argv = adapter.build_argv(ctx, exe, report)
            result = run_command(
                argv,
                cwd=Path(tmp),
                env=adapter._env(ctx),
                timeout=300,
                max_output_bytes=64 * 1024 * 1024,
            )
            print(adapter.name, suffix, "exit", result.returncode)
            data = json.loads(read_bounded_file(report, 64 * 1024 * 1024))
            data = trim(adapter.name, data)
            text = sanitise(json.dumps(data, indent=2, sort_keys=True)) + "\n"
            (OUT / f"{adapter.name}-{suffix}.json").write_text(text, encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    config = Config.model_validate({"scanners": {"osv": {"enabled": True, "mode": "local-db"}}})
    capture(DEMO, "demo", config)
    capture(CLEAN, "clean", config)


if __name__ == "__main__":
    main()
