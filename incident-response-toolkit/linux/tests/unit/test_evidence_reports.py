import csv
import io
import json
import os
import shutil
from pathlib import Path

import pytest

from linux_ir.collect import plan_collection, run_collection
from linux_ir.config import load_config, redaction_patterns
from linux_ir.evidence.manifest import EvidenceError, load_evidence, verify_manifest
from linux_ir.models import Finding
from linux_ir.reporting.report import build_report, executive_summary, to_csv, write_reports
from linux_ir.utils.paths import UnsafePathError, create_unique_dir, safe_join, write_exclusive
from linux_ir.utils.redact import Redactor

REPO = Path(__file__).resolve().parents[2]
CASE = REPO / "examples/synthetic-evidence/case-001"
ALL = ["inventory", "processes", "network", "persistence", "logs", "files"]


@pytest.fixture()
def collected(ctx, tmp_path):
    return run_collection(ctx, "extended", ALL, tmp_path / "out")


def red():
    return Redactor(redaction_patterns(load_config()), True)


def test_collection_writes_private_manifested_evidence(collected):
    evdir, digest, manifest = collected
    assert oct(evdir.stat().st_mode & 0o777) == "0o700"
    assert all(oct(p.stat().st_mode & 0o777) == "0o600" for p in evdir.rglob("*.json"))
    assert {a["name"] for a in manifest["artifacts"]} == set(ALL)
    assert manifest["tool"]["name"] == "linux-ir-toolkit" and manifest["started_at"].endswith("Z")
    res = verify_manifest(evdir)
    assert res["ok"] and res["manifest_sha256"] == digest and res["verified"] == len(manifest["files"])
    assert "not independently tamper-proof" in " ".join(manifest["limitations"])


def test_verify_detects_modification_deletion_and_additions(collected):
    evdir, *_ = collected
    target = evdir / "artifacts/processes.json"
    target.write_text(target.read_text().replace("sshd", "sshX", 1))
    res = verify_manifest(evdir)
    assert not res["ok"] and res["modified"][0]["path"] == "artifacts/processes.json"
    (evdir / "artifacts/logs.json").unlink()
    (evdir / "artifacts/extra.json").write_text("{}")
    res = verify_manifest(evdir)
    assert "artifacts/logs.json" in res["missing"] and "artifacts/extra.json" in res["unexpected"]


def test_verify_rejects_traversal_entries_and_bad_manifest(collected):
    evdir, *_ = collected
    m = json.loads((evdir / "manifest.json").read_text())
    m["files"].append({"path": "../../etc/passwd", "size": 1, "sha256": "0" * 64})
    (evdir / "manifest.json").write_text(json.dumps(m))
    res = verify_manifest(evdir)
    assert res["unsafe"] and not res["ok"]
    (evdir / "manifest.json").write_text("{broken")
    assert verify_manifest(evdir)["error"]
    (evdir / "manifest.json").unlink()
    assert "not found" in verify_manifest(evdir)["error"]


def test_symlink_in_evidence_is_flagged(collected):
    evdir, *_ = collected
    p = evdir / "artifacts/files.json"
    p.unlink()
    os.symlink(evdir / "artifacts/logs.json", p)
    assert verify_manifest(evdir)["unsafe"]


def test_unique_output_never_overwrites(tmp_path):
    assert create_unique_dir(tmp_path, "x") != create_unique_dir(tmp_path, "x")
    f = tmp_path / "f"
    write_exclusive(f, b"1")
    with pytest.raises(FileExistsError):
        write_exclusive(f, b"2")
    link = tmp_path / "link"
    os.symlink(f, link)
    with pytest.raises(OSError):
        write_exclusive(link, b"3")


@pytest.mark.parametrize("rel", ["../x", "/abs", "a/../../x", "", "a\x00b"])
def test_safe_join_rejects(tmp_path, rel):
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, rel)


def test_safe_join_rejects_symlink_escape(tmp_path):
    (tmp_path / "outside").mkdir()
    base = tmp_path / "base"
    base.mkdir()
    os.symlink(tmp_path / "outside", base / "evil")
    with pytest.raises(UnsafePathError):
        safe_join(base, "evil/file")


def test_dry_run_plan_has_no_side_effects(ctx, tmp_path):
    plan = plan_collection(ctx, ["inventory", "logs"])
    assert plan[0]["operations"] and not (tmp_path / "out").exists()


def test_failed_collector_does_not_stop_others(ctx, tmp_path, monkeypatch):
    from linux_ir.collectors import REGISTRY

    def boom(c):
        raise RuntimeError("boom")

    monkeypatch.setattr(REGISTRY["network"], "collect", boom)
    _, _, manifest = run_collection(ctx, "basic", ["network", "inventory"], tmp_path / "o")
    st = {a["name"]: a["status"] for a in manifest["artifacts"]}
    assert st["network"] == "failed" and st["inventory"] == "ok"
    assert "boom" in json.dumps(manifest["artifacts"]) and "logs" in manifest["coverage"]["skipped"]


def test_load_evidence_malformed(tmp_path):
    with pytest.raises(EvidenceError):
        load_evidence(tmp_path)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/x.json").write_text("{bad")
    with pytest.raises(EvidenceError):
        load_evidence(tmp_path)


def finding(**kw):
    base = dict(
        rule_id="LIR-X-001",
        rule_version=1,
        title="=SUM(A1)",
        description="d",
        category="c",
        severity="high",
        confidence="low",
        classification="heuristic",
        artifact="processes",
        evidence_ref="artifacts/p.json#records[0]",
        why="password=hunter2 leaked",
        false_positives=["fp"],
        next_steps=["ns"],
        attack=["T1059"],
    )
    base.update(kw)
    return Finding(**base)


def test_report_redaction_csv_injection_and_sections():
    arts, manifest = load_evidence(CASE)
    rep = build_report(
        arts,
        manifest,
        [finding(), finding(rule_id="IOC-MATCH-IP", classification="ioc_match")],
        None,
        [],
        {"ok": True, "verified": 3},
        red(),
    )
    assert "hunter2" not in json.dumps(rep)
    assert len(rep["heuristic_findings"]) == 1 and len(rep["ioc_matches"]) == 1
    assert rep["detection_counts_by_severity"]["high"] == 1 and rep["not_assessed"]
    rows = list(csv.DictReader(io.StringIO(to_csv(rep))))
    assert rows[0]["title"].startswith("'=")
    assert set(rows[0]) >= {"rule_id", "severity", "confidence", "evidence_ref"}


def test_write_reports_all_files_and_no_overwrite(tmp_path):
    arts, manifest = load_evidence(CASE)
    rep = build_report(arts, manifest, [finding()], None, [], None, red())
    names = {p.name for p in write_reports(rep, tmp_path / "r", CASE / "manifest.json")}
    assert names == {
        "report.json",
        "findings.csv",
        "executive-summary.md",
        "technical-report.md",
        "evidence-manifest.json",
        "evidence-manifest.sha256",
    }
    md = (tmp_path / "r/executive-summary.md").read_text()
    assert "not** confirmation of compromise" in md and "clean" in md
    with pytest.raises(FileExistsError):
        write_reports(rep, tmp_path / "r", None)


def test_incomplete_collection_is_called_out():
    arts, manifest = load_evidence(CASE)
    arts = json.loads(json.dumps(arts))
    arts["logs"]["errors"].append(
        {"collector": "logs", "source": "/var/log/auth.log", "kind": "permission_denied", "message": "x"}
    )
    arts["logs"]["status"] = "partial"
    rep = build_report(arts, manifest, [], None, [], {"ok": True, "verified": 1}, red())
    text = executive_summary(rep)
    assert "Incomplete coverage" in text and "None." in text


def test_committed_fixtures_verify_and_tamper_copy_fails(tmp_path):
    assert verify_manifest(CASE)["ok"]
    assert verify_manifest(REPO / "examples/synthetic-evidence/baseline")["ok"]
    dst = tmp_path / "copy"
    shutil.copytree(CASE, dst)
    (dst / "artifacts/network.json").write_text("{}")
    assert not verify_manifest(dst)["ok"]


def test_static_report_text_is_not_mangled_by_redaction():
    arts, manifest = load_evidence(CASE)
    rep = build_report(arts, manifest, [], None, [], None, red())
    assert "[REDACTED]" not in json.dumps(rep["not_assessed"] + rep["limitations"])
