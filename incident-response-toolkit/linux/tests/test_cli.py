import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from linux_ir.cli import main

REPO = Path(__file__).resolve().parents[1]
CASE = REPO / "examples/synthetic-evidence/case-001"
BASE = REPO / "examples/synthetic-evidence/baseline"
IOCS = REPO / "examples/iocs.json"
RULES = REPO / "rules"


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    for cmd in ("info", "doctor", "collect", "scan", "report", "verify-manifest", "seal"):
        assert cmd in out
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0


@pytest.mark.parametrize("argv", [[], ["bogus"], ["collect"], ["scan"], ["verify-manifest"], ["collect", "--output"]])
def test_usage_errors_exit_2(argv):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2


def test_info_json(capsys):
    assert main(["info", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["system"]


def test_doctor_runs(capsys):
    assert main(["doctor"]) in (0, 1)
    assert "[" in capsys.readouterr().out


def test_collect_dry_run_writes_nothing(tmp_path, capsys):
    out = tmp_path / "ev"
    assert main(["collect", "--dry-run", "--profile", "basic", "--output", str(out)]) == 0
    text = capsys.readouterr().out
    assert "DRY RUN" in text and "[processes]" in text and "[files]" not in text
    assert not out.exists()
    assert main(["collect", "--dry-run", "--profile", "extended", "--output", str(out)]) == 0
    assert "[files]" in capsys.readouterr().out and not out.exists()


def test_collect_validation(tmp_path, capsys):
    assert main(["collect", "--profile", "nope", "--output", str(tmp_path)]) == 2
    assert main(["collect", "--collectors", "bogus", "--output", str(tmp_path)]) == 2
    assert main(["collect", "--log-hours", "0", "--output", str(tmp_path)]) == 2
    assert main(["collect", "--import-log", str(tmp_path / "none.log"), "--output", str(tmp_path)]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="live collection needs Linux")
def test_live_collect_scan_report_verify(tmp_path, capsys):
    assert (
        main(["collect", "--profile", "basic", "--collectors", "inventory,processes", "--output", str(tmp_path / "ev")])
        == 0
    )
    line = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("EVIDENCE_DIR=")][0]
    evdir = Path(line.split("=", 1)[1])
    assert main(["verify-manifest", "--input", str(evdir)]) == 0
    assert main(["scan", "--input", str(evdir), "--rules", str(RULES)]) == 0
    assert main(["report", "--input", str(evdir), "--rules", str(RULES), "--output", str(tmp_path / "rep")]) == 0
    assert (tmp_path / "rep/report.json").is_file()


def test_scan_synthetic_with_iocs_and_exit_codes(capsys):
    args = ["scan", "--input", str(CASE), "--rules", str(RULES), "--iocs", str(IOCS), "--baseline", str(BASE)]
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "LIR-PERS-002" in out and "IOC-MATCH-IP" in out
    assert main(args + ["--fail-on-findings"]) == 10
    capsys.readouterr()
    assert main(args + ["--json"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), list)


def test_scan_bad_inputs(tmp_path, capsys):
    assert main(["scan", "--input", str(tmp_path / "missing")]) == 2
    assert main(["scan", "--input", str(CASE), "--iocs", str(tmp_path / "x.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 1, "indicators": [{"type": "ip", "value": "nope"}]}')
    assert main(["scan", "--input", str(CASE), "--rules", str(RULES), "--iocs", str(bad)]) == 1
    assert "invalid IP" in capsys.readouterr().err


def test_tampered_evidence_blocks_scan_and_verify_fails(tmp_path, capsys):
    cp = tmp_path / "case"
    shutil.copytree(CASE, cp)
    p = cp / "artifacts/processes.json"
    p.write_text(p.read_text().replace("sshd", "sshX", 1))
    assert main(["verify-manifest", "--input", str(cp)]) == 3
    assert "FAIL" in capsys.readouterr().out
    assert main(["scan", "--input", str(cp), "--rules", str(RULES)]) == 3
    assert main(["scan", "--input", str(cp), "--rules", str(RULES), "--allow-unverified"]) == 0
    assert "FAILED integrity" in capsys.readouterr().out


def test_report_cli_and_no_overwrite(tmp_path):
    out = tmp_path / "rep"
    assert main(["report", "--input", str(CASE), "--rules", str(RULES), "--iocs", str(IOCS), "--output", str(out)]) == 0
    rep = json.loads((out / "report.json").read_text())
    assert rep["ioc_matches"] and rep["integrity"]["ok"] and "hunter2" not in json.dumps(rep)
    assert main(["report", "--input", str(CASE), "--rules", str(RULES), "--output", str(out)]) == 1


def test_seal(tmp_path):
    ev = tmp_path / "e"
    shutil.copytree(CASE / "artifacts", ev / "artifacts")
    assert main(["seal", "--input", str(ev)]) == 0
    assert main(["verify-manifest", "--input", str(ev)]) == 0
    assert main(["seal", "--input", str(ev)]) == 1
    assert main(["seal", "--input", str(tmp_path)]) == 2


def test_python_dash_m_entrypoint():
    r = subprocess.run([sys.executable, "-m", "linux_ir", "--version"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "linux-ir-toolkit" in r.stdout
