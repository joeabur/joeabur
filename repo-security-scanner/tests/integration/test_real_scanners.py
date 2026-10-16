"""Integration tests that invoke the REAL scanners on bundled, intentionally vulnerable fixtures.

Run with:  pytest -m integration
Gitleaks and Semgrep run fully offline. Trivy and OSV-Scanner need their vulnerability
databases, so they are opt-in:  REPOSCAN_ITEST_NETWORK=1 pytest -m integration
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from reposcan.cli import app
from reposcan.schemas import ScanResult

from ..helpers import FIXTURES

pytestmark = pytest.mark.integration

runner = CliRunner()
OFFLINE = "gitleaks,semgrep"
NETWORK = os.environ.get("REPOSCAN_ITEST_NETWORK") == "1"
SARIF_SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text())


def need(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        pytest.skip(f"not installed: {', '.join(missing)}")


def scan(repo: Path, out: Path, *extra: str) -> tuple[int, ScanResult | None, str]:
    res = runner.invoke(app, ["scan", str(repo), "--output-dir", str(out), *extra])
    report = out / "reposcan-report.json"
    data = ScanResult.model_validate_json(report.read_text()) if report.exists() else None
    return res.exit_code, data, res.output


@pytest.fixture(autouse=True)
def _tools() -> None:
    need("gitleaks", "semgrep")


def test_doctor_sees_supported_versions() -> None:
    res = runner.invoke(app, ["doctor", "--json"])
    rows = {r["scanner"]: r for r in json.loads(res.output)["scanners"]}
    assert rows["gitleaks"]["status"] == "ok" and rows["semgrep"]["status"] == "ok"


def test_demo_repo_produces_expected_findings(demo_repo: Path, tmp_path: Path) -> None:
    code, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", OFFLINE)
    assert code == 1 and data is not None
    found = {(f.scanner, f.rule_id, f.file, f.line) for f in data.findings}
    assert ("gitleaks", "reposcan-synthetic-token", "app/settings.py", 4) in found
    assert ("gitleaks", "generic-api-key", "app/settings.py", 7) in found
    assert ("semgrep", "reposcan.python.sql-string-concat", "app/server.py", 13) in found
    assert ("semgrep", "reposcan.python.subprocess-shell-true", "app/server.py", 18) in found
    assert ("semgrep", "reposcan.python.weak-hash", "app/server.py", 23) in found
    assert ("semgrep", "reposcan.python.eval-call", "app/server.py", 28) in found
    assert data.summary.total == 6


def test_clean_repo_exits_zero(clean_repo: Path, tmp_path: Path) -> None:
    code, data, _ = scan(clean_repo, tmp_path / "o", "--scanners", OFFLINE)
    assert code == 0 and data is not None and data.findings == []
    assert all(r.status == "ok" for r in data.scanners)


def test_scanner_failure_is_distinct_from_findings(clean_repo: Path, tmp_path: Path) -> None:
    bad_rules = tmp_path / "bad.yml"
    bad_rules.write_text(
        "rules:\n  - id: broken\n    message: x\n    severity: ERROR\n    languages: [python]\n    pattern: (((\n"
    )
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[scanners.semgrep]\nrules = ["{bad_rules}"]\n')
    code, data, output = scan(clean_repo, tmp_path / "o", "--scanners", OFFLINE, "--config", str(cfg))
    assert code == 3 and data is not None
    assert {r.name: r.status for r in data.scanners}["semgrep"] in {"failed", "malformed_output"}
    assert "incomplete" in output


def test_reports_never_contain_secret_values(demo_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "o"
    _, _, output = scan(
        demo_repo, out, "--scanners", OFFLINE, "--format", "json,html,sarif,md,codequality", "-v"
    )
    blobs = [output, *[p.read_text() for p in out.iterdir()]]
    for blob in blobs:
        assert "AAAABBBBCCCCDDDDEEEEFFFF" not in blob
        assert "q7Xk2vR9mTz4WbN8pLc3YdHs6JfGa1Ue" not in blob


def test_sarif_from_real_scan_is_schema_valid(demo_repo: Path, tmp_path: Path) -> None:
    scan(demo_repo, tmp_path / "o", "--scanners", OFFLINE, "--format", "sarif")
    sarif = json.loads((tmp_path / "o" / "reposcan.sarif").read_text())
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(sarif)
    assert sum(len(r["results"]) for r in sarif["runs"]) == 6


# ---- repository-controlled suppression must not hide findings ------------------------------------------


def test_repo_semgrepignore_and_gitignore_cannot_hide_findings(demo_repo: Path, tmp_path: Path) -> None:
    (demo_repo / ".semgrepignore").write_text("app/\n")
    (demo_repo / ".gitignore").write_text("app/\n")
    code, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "semgrep")
    assert code == 1 and data is not None and data.summary.by_scanner == {"semgrep": 4}


def test_semgrep_has_no_hidden_default_exclusions(clean_repo: Path, tmp_path: Path) -> None:
    for d in ("tests", "test", "node_modules/x", "vendor", "docs"):
        (clean_repo / d).mkdir(parents=True)
        (clean_repo / d / "a.py").write_text('import subprocess\nsubprocess.call("ls " + x, shell=True)\n')
    _, data, _ = scan(clean_repo, tmp_path / "o", "--scanners", "semgrep")
    assert data is not None
    assert {f.file for f in data.findings} == {
        f"{d}/a.py" for d in ("tests", "test", "node_modules/x", "vendor", "docs")
    }


def test_nosemgrep_comment_cannot_hide_findings(clean_repo: Path, tmp_path: Path) -> None:
    (clean_repo / "hidden.py").write_text(
        'import subprocess\nsubprocess.call("ls " + x, shell=True)  # nosemgrep\n'
    )
    code, data, _ = scan(clean_repo, tmp_path / "o", "--scanners", "semgrep")
    assert code == 1 and data is not None
    assert [f.file for f in data.findings] == ["hidden.py"]


def test_inline_allow_comment_and_nosemgrep_cannot_hide_secrets(demo_repo: Path, tmp_path: Path) -> None:
    (demo_repo / "app" / "extra.py").write_text(
        'token = "DEMO_TOKEN_ZZZZYYYYXXXXWWWWVVVVUUUU"  # gitleaks:allow\n'
    )
    _, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "gitleaks")
    assert data is not None
    assert any(f.file == "app/extra.py" for f in data.findings)


def test_repo_gitleaksignore_fails_closed(demo_repo: Path, tmp_path: Path) -> None:
    (demo_repo / ".gitleaksignore").write_text(f"{demo_repo}/app/settings.py:reposcan-synthetic-token:4\n")
    code, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "gitleaks")
    assert code == 3 and data is not None and ".gitleaksignore" in (data.scanners[0].error or "")
    code, data, _ = scan(demo_repo, tmp_path / "o2", "--scanners", "gitleaks", "--allow-repo-ignore-files")
    assert code == 1 and data is not None
    assert any("gitleaksignore" in w for w in data.warnings)


def test_repo_gitleaks_toml_is_not_used(demo_repo: Path, tmp_path: Path) -> None:
    (demo_repo / ".gitleaks.toml").write_text('title = "weak"\n[allowlist]\npaths = [".*"]\n')
    _, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "gitleaks")
    assert data is not None and data.summary.total == 2


def test_symlink_pointing_outside_is_not_followed(demo_repo: Path, clean_repo: Path, tmp_path: Path) -> None:
    (clean_repo / "link").symlink_to(demo_repo)
    code, data, _ = scan(clean_repo, tmp_path / "o", "--scanners", OFFLINE)
    assert code == 0 and data is not None and data.scope.symlinks_skipped == 1


def test_hostile_filenames_do_not_break_or_inject(clean_repo: Path, tmp_path: Path) -> None:
    name = "x'; touch pwned; echo '.py"
    (clean_repo / name).write_text("eval(input())\n")
    code, data, output = scan(clean_repo, tmp_path / "o", "--scanners", OFFLINE)
    assert not (clean_repo / "pwned").exists() and not Path("pwned").exists()
    assert data is not None and "\x1b" not in output
    assert code in {0, 1}


# ---- network-backed scanners ------------------------------------------------------------------------------


@pytest.mark.skipif(not NETWORK, reason="set REPOSCAN_ITEST_NETWORK=1 (downloads vulnerability databases)")
def test_trivy_finds_vulnerable_dependencies_and_iac_issues(demo_repo: Path, tmp_path: Path) -> None:
    need("trivy")
    code, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "trivy")
    assert code == 1 and data is not None
    kinds = {f.kind.value for f in data.findings}
    assert kinds == {"dependency", "misconfiguration"}
    assert any(f.rule_id == "CVE-2019-10906" and f.file == "requirements.txt" for f in data.findings)
    assert any(f.rule_id == "DS-0002" or f.rule_id.endswith("DS-0002") for f in data.findings)


@pytest.mark.skipif(not NETWORK, reason="set REPOSCAN_ITEST_NETWORK=1 (downloads vulnerability databases)")
def test_osv_scanner_local_db_mode(demo_repo: Path, tmp_path: Path) -> None:
    need("osv-scanner")
    cfg = tmp_path / "c.toml"
    cfg.write_text('[scanners.osv]\nenabled = true\nmode = "local-db"\n')
    code, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "osv-scanner", "--config", str(cfg))
    assert code == 1 and data is not None
    assert any(f.rule_id == "CVE-2019-10906" for f in data.findings)


@pytest.mark.skipif(not NETWORK, reason="set REPOSCAN_ITEST_NETWORK=1")
def test_trivy_offline_without_db_fails_loudly_instead_of_passing(demo_repo: Path, tmp_path: Path) -> None:
    need("trivy")
    cache = tmp_path / "empty-cache"
    cache.mkdir()
    cfg = tmp_path / "c.toml"
    cfg.write_text('[scan]\nenv_passthrough = ["TRIVY_CACHE_DIR"]\n')
    os.environ["TRIVY_CACHE_DIR"] = str(cache)
    try:
        code, data, _ = scan(
            demo_repo, tmp_path / "o", "--scanners", "trivy", "--offline", "--config", str(cfg)
        )
    finally:
        del os.environ["TRIVY_CACHE_DIR"]
    assert code == 3 and data is not None and data.scanners[0].status == "failed"


def _unshare_works() -> bool:
    import subprocess

    exe = shutil.which("unshare")
    if exe is None:
        return False
    return subprocess.run([exe, "-rn", "true"], capture_output=True, check=False).returncode == 0


@pytest.mark.skipif(not _unshare_works(), reason="needs unshare(1) with user+network namespaces")
def test_default_path_needs_no_network_at_all(demo_repo: Path, tmp_path: Path) -> None:
    """Run Gitleaks + Semgrep inside a network namespace that has no interfaces."""
    import subprocess
    import sys

    probe = subprocess.run(
        [
            "unshare",
            "-rn",
            sys.executable,
            "-c",
            "import socket,sys\ntry:\n    socket.create_connection(('1.1.1.1', 53), timeout=2)\nexcept OSError:\n    sys.exit(0)\nsys.exit(1)",
        ],
        capture_output=True,
        check=False,
    )
    assert probe.returncode == 0, "network namespace is not isolated; test would prove nothing"
    out = tmp_path / "o"
    run = subprocess.run(
        [
            "unshare",
            "-rn",
            sys.executable,
            "-m",
            "reposcan",
            "scan",
            str(demo_repo),
            "--scanners",
            OFFLINE,
            "--output-dir",
            str(out),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1, run.stdout + run.stderr
    data = ScanResult.model_validate_json((out / "reposcan-report.json").read_text())
    assert data.summary.total == 6 and all(r.status == "ok" for r in data.scanners)


@pytest.mark.skipif(not NETWORK, reason="set REPOSCAN_ITEST_NETWORK=1 (Trivy fetches its check bundle)")
def test_trivy_inline_ignore_cannot_hide_misconfigurations(clean_repo: Path, tmp_path: Path) -> None:
    need("trivy")
    tf = (
        'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n'
        'resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.b.id\n'
        "  #trivy:ignore:AVD-AWS-0086\n  block_public_acls = false\n  block_public_policy = true\n"
        "  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n"
    )
    (clean_repo / "main.tf").write_text(tf)
    code, data, _ = scan(clean_repo, tmp_path / "o", "--scanners", "trivy")
    assert code == 3 and data is not None and "trivy:ignore" in (data.scanners[0].error or "")


@pytest.mark.skipif(not NETWORK, reason="set REPOSCAN_ITEST_NETWORK=1 (downloads vulnerability databases)")
def test_repo_osv_scanner_toml_cannot_hide_vulnerabilities(demo_repo: Path, tmp_path: Path) -> None:
    need("osv-scanner")
    (demo_repo / "osv-scanner.toml").write_text(
        '[[IgnoredVulns]]\nid = "CVE-2019-10906"\nreason = "attacker says so"\n'
        '[[IgnoredVulns]]\nid = "GHSA-462w-v97r-4m45"\nreason = "attacker says so"\n'
        '[[IgnoredVulns]]\nid = "PYSEC-2019-217"\nreason = "attacker says so"\n'
    )
    cfg = tmp_path / "c.toml"
    cfg.write_text('[scanners.osv]\nenabled = true\nmode = "local-db"\n')
    _, data, _ = scan(demo_repo, tmp_path / "o", "--scanners", "osv-scanner", "--config", str(cfg))
    assert data is not None
    assert any(f.rule_id == "CVE-2019-10906" for f in data.findings)
