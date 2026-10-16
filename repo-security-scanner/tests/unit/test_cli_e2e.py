"""End-to-end CLI tests using fake scanner executables that replay real captured output."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import date, timedelta
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from reposcan.cli import app
from reposcan.schemas import ScanResult

from ..helpers import FIXTURES, install_clean_scanners, install_demo_scanners, make_fake_scanner

runner = CliRunner()
SARIF_SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text())
SECRET_VALUES = ("AAAABBBBCCCCDDDDEEEEFFFF", "q7Xk2vR9mTz4WbN8pLc3YdHs6JfGa1Ue")
NO_OSV = "gitleaks,semgrep,trivy"
EXPIRY = (date.today() + timedelta(days=90)).isoformat()


def invoke(*args: str, **kw: object):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args), **kw)  # type: ignore[arg-type]


def load(out: Path) -> ScanResult:
    return ScanResult.model_validate_json((out / "reposcan-report.json").read_text())


# ---- the three distinguishable outcomes ------------------------------------------------------


def test_clean_scan_exits_0(bin_dir: Path, clean_repo: Path, tmp_path: Path) -> None:
    install_clean_scanners(bin_dir)
    out = tmp_path / "out"
    res = invoke("scan", str(clean_repo), "--output-dir", str(out), "--scanners", NO_OSV)
    assert res.exit_code == 0, res.output
    data = load(out)
    assert data.exit_code == 0 and data.findings == [] and all(r.status == "ok" for r in data.scanners)
    assert "policy satisfied" in res.output


def test_finding_scan_exits_1(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    out = tmp_path / "out"
    res = invoke("scan", str(demo_repo), "--output-dir", str(out), "--scanners", NO_OSV)
    assert res.exit_code == 1, res.output
    data = load(out)
    assert data.policy.passed is False and data.summary.by_status["new"] == 22
    assert data.summary.by_scanner == {"gitleaks": 2, "semgrep": 4, "trivy": 16}
    assert "policy failed" in res.output


def test_scanner_failure_exits_3_even_with_no_findings(
    bin_dir: Path, clean_repo: Path, tmp_path: Path
) -> None:
    install_clean_scanners(bin_dir)
    make_fake_scanner(bin_dir, "semgrep", exit_code=2, stderr="internal error", report="{}")
    res = invoke("scan", str(clean_repo), "--output-dir", str(tmp_path / "o"), "--scanners", NO_OSV)
    assert res.exit_code == 3, res.output
    data = load(tmp_path / "o")
    assert {r.name: r.status for r in data.scanners} == {
        "gitleaks": "ok",
        "semgrep": "failed",
        "trivy": "ok",
    }
    assert "results are incomplete" in data.exit_reason


def test_scanner_failure_outranks_policy_failure(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    make_fake_scanner(bin_dir, "trivy", exit_code=1, stderr="db error", report="{}")
    res = invoke("scan", str(demo_repo), "--output-dir", str(tmp_path / "o"), "--scanners", NO_OSV)
    assert res.exit_code == 3
    assert load(tmp_path / "o").summary.by_status["new"] == 6  # partial findings are still reported


def test_missing_scanner_exits_3(bin_dir: Path, clean_repo: Path, tmp_path: Path) -> None:
    install_clean_scanners(bin_dir, only=("gitleaks", "semgrep"))
    res = invoke("scan", str(clean_repo), "--output-dir", str(tmp_path / "o"), "--scanners", NO_OSV)
    assert res.exit_code == 3 and "trivy" in res.output and "not_found" in res.output


def test_version_mismatch_exits_3(bin_dir: Path, clean_repo: Path, tmp_path: Path) -> None:
    install_clean_scanners(bin_dir)
    make_fake_scanner(bin_dir, "gitleaks", version="7.0.0", report="[]")
    res = invoke("scan", str(clean_repo), "--output-dir", str(tmp_path / "o"), "--scanners", "gitleaks")
    assert res.exit_code == 3 and "version_mismatch" in res.output


def test_timeout_exits_3(bin_dir: Path, clean_repo: Path, tmp_path: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", sleep=30)
    res = invoke(
        "scan",
        str(clean_repo),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        "gitleaks",
        "--timeout",
        "1",
    )
    assert res.exit_code == 3 and "timeout" in res.output


# ---- configuration and usage errors exit 2 ----------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "/no/such/dir"],
        ["scan", ".", "--scanners", "nmap"],
        ["scan", ".", "--fail-on", "severe"],
        ["scan", ".", "--format", "pdf"],
        ["scan", ".", "--config", "/no/such.toml"],
        ["scan", ".", "--baseline", "/no/such.json"],
        ["scan", ".", "--image", "--evil"],
        ["scan", ".", "--history"],
        ["scan", ".", "--no-such-flag"],
    ],
)
def test_config_errors_exit_2(
    args: list[str], tmp_path: Path, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    res = invoke(*args)
    assert res.exit_code == 2, res.output


def test_config_file_in_scanned_repo_is_never_loaded(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    (demo_repo / "reposcan.toml").write_text('[policy]\nfail_on = "none"\n')
    install_demo_scanners(bin_dir, demo_repo)
    res = invoke("scan", str(demo_repo), "--output-dir", str(tmp_path / "o"), "--scanners", NO_OSV)
    assert res.exit_code == 1


# ---- policy flags ------------------------------------------------------------------------------------


def test_fail_on_none_reports_without_failing(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    res = invoke(
        "scan",
        str(demo_repo),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        NO_OSV,
        "--fail-on",
        "none",
    )
    assert res.exit_code == 0 and load(tmp_path / "o").summary.total == 22


def test_fail_on_critical_threshold(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    res = invoke(
        "scan",
        str(demo_repo),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        "gitleaks,semgrep",
        "--fail-on",
        "critical",
    )
    assert res.exit_code == 0  # no criticals among secrets + SAST findings


# ---- baseline workflow -------------------------------------------------------------------------------


def test_baseline_create_then_clean_then_new_finding(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    base_file = tmp_path / "baseline.json"
    created = invoke(
        "baseline",
        "create",
        str(demo_repo),
        "--owner",
        "team-a",
        "--reason",
        "legacy demo code",
        "--expires",
        EXPIRY,
        "--baseline-file",
        str(base_file),
        "--scanners",
        NO_OSV,
    )
    assert created.exit_code == 0, created.output
    assert "22 finding(s) accepted" in created.output
    entries = json.loads(base_file.read_text())["entries"]
    assert len(entries) == 22 and all(e["owner"] == "team-a" and e["expires"] == EXPIRY for e in entries)

    res = invoke(
        "scan",
        str(demo_repo),
        "--baseline",
        str(base_file),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        NO_OSV,
    )
    assert res.exit_code == 0, res.output
    data = load(tmp_path / "o")
    assert data.summary.by_status == {"new": 0, "baseline": 22, "suppressed": 0}
    assert all(f.status_detail and "team-a" in f.status_detail for f in data.findings)

    # A NEW vulnerability appears: it must fail the build even though a baseline exists.
    extra = json.loads(
        (FIXTURES / "scanner-output" / "semgrep-demo.json").read_text().replace("/repo", str(demo_repo))
    )
    extra["results"].append({**extra["results"][0], "check_id": "reposcan.python.brand-new-rule"})
    make_fake_scanner(bin_dir, "semgrep", report=json.dumps(extra))
    res = invoke(
        "scan",
        str(demo_repo),
        "--baseline",
        str(base_file),
        "--output-dir",
        str(tmp_path / "o2"),
        "--scanners",
        NO_OSV,
    )
    assert res.exit_code == 1
    new = [f for f in load(tmp_path / "o2").findings if f.status.value == "new"]
    assert [f.rule_id for f in new] == ["reposcan.python.brand-new-rule"]


def test_baseline_create_requires_owner_and_reason(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    res = invoke("baseline", "create", str(demo_repo), "--baseline-file", str(tmp_path / "b.json"))
    assert res.exit_code == 2 and not (tmp_path / "b.json").exists()


def test_baseline_create_refuses_incomplete_scan(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo, only=("gitleaks", "semgrep"))
    res = invoke(
        "baseline",
        "create",
        str(demo_repo),
        "--owner",
        "o",
        "--reason",
        "legacy",
        "--expires",
        EXPIRY,
        "--baseline-file",
        str(tmp_path / "b.json"),
        "--scanners",
        NO_OSV,
    )
    assert res.exit_code == 3 and not (tmp_path / "b.json").exists()


def test_baseline_create_requires_expiry_for_critical(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    res = invoke(
        "baseline",
        "create",
        str(demo_repo),
        "--owner",
        "o",
        "--reason",
        "legacy",
        "--baseline-file",
        str(tmp_path / "b.json"),
        "--scanners",
        NO_OSV,
    )
    assert res.exit_code == 2 and "require an expiry" in res.output and not (tmp_path / "b.json").exists()


def test_baseline_review_flags_expired_entries(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    base_file = tmp_path / "b.json"
    invoke(
        "baseline",
        "create",
        str(demo_repo),
        "--owner",
        "o",
        "--reason",
        "legacy",
        "--expires",
        EXPIRY,
        "--baseline-file",
        str(base_file),
        "--scanners",
        NO_OSV,
    )
    ok = invoke("baseline", "review", str(base_file), "--strict")
    assert ok.exit_code == 0 and "[ok]" in ok.output
    data = json.loads(base_file.read_text())
    data["entries"][0]["expires"] = "2000-01-01"
    base_file.write_text(json.dumps(data))
    bad = invoke("baseline", "review", str(base_file), "--strict")
    assert bad.exit_code == 1 and "EXPIRED" in bad.output
    # and the scan treats the expired entry as new again
    res = invoke(
        "scan",
        str(demo_repo),
        "--baseline",
        str(base_file),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        NO_OSV,
    )
    assert res.exit_code == 1
    assert any(f.suppression_expired for f in load(tmp_path / "o").findings)


# ---- secrets never leak -----------------------------------------------------------------------------


def test_no_report_or_console_output_contains_secret_values(
    bin_dir: Path, demo_repo: Path, tmp_path: Path
) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    out = tmp_path / "out"
    res = invoke(
        "scan",
        str(demo_repo),
        "--output-dir",
        str(out),
        "--scanners",
        NO_OSV,
        "-v",
        "--format",
        "json,html,sarif,md,codequality",
        "--github-annotations",
    )
    blobs = [res.output] + [p.read_text() for p in out.iterdir()]
    for blob in blobs:
        for secret in SECRET_VALUES:
            assert secret not in blob


def test_semgrep_evidence_withheld_on_lines_with_secrets(
    bin_dir: Path, demo_repo: Path, tmp_path: Path
) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    sg = json.loads(
        (FIXTURES / "scanner-output" / "semgrep-demo.json").read_text().replace("/repo", str(demo_repo))
    )
    sg["results"].append(
        {
            "check_id": "r.hardcoded",
            "path": str(demo_repo / "app/settings.py"),
            "start": {"line": 7, "col": 1, "offset": 100},
            "end": {"line": 7, "col": 40},
            "extra": {
                "severity": "ERROR",
                "message": "hard-coded",
                "lines": "requires login",
                "metadata": {},
            },
        }
    )
    make_fake_scanner(bin_dir, "semgrep", report=json.dumps(sg))
    invoke("scan", str(demo_repo), "--output-dir", str(tmp_path / "o"), "--scanners", NO_OSV)
    hit = next(f for f in load(tmp_path / "o").findings if f.rule_id == "r.hardcoded")
    assert "withheld" in (hit.evidence or "") and "q7Xk2v" not in (hit.evidence or "")


# ---- other commands ---------------------------------------------------------------------------------


def test_report_render_roundtrip_and_validation(bin_dir: Path, demo_repo: Path, tmp_path: Path) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    invoke(
        "scan",
        str(demo_repo),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        NO_OSV,
        "--format",
        "json",
    )
    res = invoke(
        "report",
        "render",
        "--input",
        str(tmp_path / "o" / "reposcan-report.json"),
        "--format",
        "html,sarif",
        "--output-dir",
        str(tmp_path / "r"),
    )
    assert res.exit_code == 0
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(
        json.loads((tmp_path / "r" / "reposcan.sarif").read_text())
    )
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": "x"}')
    assert invoke("report", "render", "--input", str(bad)).exit_code == 2


def test_doctor_reports_each_scanner(bin_dir: Path) -> None:
    install_clean_scanners(bin_dir, only=("gitleaks", "semgrep"))
    make_fake_scanner(bin_dir, "trivy", version="0.10.0")
    res = invoke("doctor")
    assert res.exit_code == 3
    assert "gitleaks" in res.output and "version_mismatch" in res.output
    as_json = json.loads(invoke("doctor", "--json", "--all").output)["scanners"]
    assert {r["scanner"]: r["status"] for r in as_json} == {
        "gitleaks": "ok",
        "semgrep": "ok",
        "trivy": "version_mismatch",
        "osv-scanner": "not_found",
    }


def test_config_validate(tmp_path: Path) -> None:
    good = tmp_path / "c.toml"
    good.write_text('[policy]\nfail_on = "low"\n')
    assert invoke("config", "validate", str(good)).exit_code == 0
    good.write_text("[policy]\nfail_on = 3\n")
    assert invoke("config", "validate", str(good)).exit_code == 2


def test_github_annotations_and_summary(
    bin_dir: Path, demo_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_demo_scanners(bin_dir, demo_repo)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    res = invoke(
        "scan",
        str(demo_repo),
        "--output-dir",
        str(tmp_path / "o"),
        "--scanners",
        NO_OSV,
        "--github-annotations",
        "--github-summary",
    )
    assert res.output.count("::error ") >= 5
    assert "reposcan: ❌ failed" in summary.read_text()


def test_output_inside_target_warns(bin_dir: Path, clean_repo: Path) -> None:
    install_clean_scanners(bin_dir)
    res = invoke("scan", str(clean_repo), "--output-dir", str(clean_repo / "out"), "--scanners", NO_OSV)
    assert res.exit_code == 0 and "inside the scan target" in res.output


def test_version_command() -> None:
    assert "reposcan" in invoke("version").output


# ---- real process signals --------------------------------------------------------------------------


def test_sigterm_cancels_with_exit_130(bin_dir: Path, clean_repo: Path, tmp_path: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", sleep=60)
    env = {**os.environ, "PATH": f"{bin_dir}"}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "reposcan",
            "scan",
            str(clean_repo),
            "--scanners",
            "gitleaks",
            "--output-dir",
            str(tmp_path / "o"),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(2.5)
    proc.send_signal(signal.SIGTERM)
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 130, (out, err)
    assert "cancelled" in out


def test_unexpected_exception_exits_4_not_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A crash must never be mistaken for a policy failure (exit 1)."""
    from reposcan import cli

    secret = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"

    def boom() -> None:
        raise RuntimeError(f"unexpected {secret}")

    monkeypatch.setattr(cli, "app", boom)
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 4
    err = capsys.readouterr().err
    assert "internal error (RuntimeError)" in err and secret not in err


def test_keyboard_interrupt_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    from reposcan import cli

    def interrupted() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "app", interrupted)
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 130


# ---- update-db -------------------------------------------------------------------------------------------


def test_update_db_runs_trivy_download_only(bin_dir: Path, tmp_path: Path) -> None:
    log = tmp_path / "args.log"
    script = bin_dir / "trivy"
    script.write_text(
        f"#!{sys.executable}\nimport sys\nargs = sys.argv[1:]\n"
        "if args[:1] == ['--version']:\n    print('Version: 0.76.0'); sys.exit(0)\n"
        f"open({str(log)!r}, 'w').write(' '.join(args))\n"
    )
    script.chmod(0o755)
    res = invoke("update-db")
    assert res.exit_code == 0 and "up to date" in res.output
    assert log.read_text().startswith("image --download-db-only")
    assert "--disable-telemetry" in log.read_text()


def test_update_db_failure_and_missing_trivy_exit_3(bin_dir: Path) -> None:
    assert invoke("update-db").exit_code == 3  # not installed
    make_fake_scanner(bin_dir, "trivy", exit_code=1, stderr="registry unreachable")
    res = invoke("update-db")
    assert res.exit_code == 3 and "download failed" in res.output
