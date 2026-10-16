from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from reposcan.baseline import (
    Baseline,
    add_to_baseline,
    apply_acceptance,
    load_baseline,
    review_baseline,
    save_baseline,
)
from reposcan.config import Config, PolicySettings, Suppression
from reposcan.errors import ConfigError
from reposcan.policy import evaluate
from reposcan.schemas import FindingStatus, Severity

from .factories import finding

TODAY = date(2026, 6, 1)


def cfg(**policy: object) -> Config:
    return Config.model_validate({"policy": policy})


def baseline_with(*findings, expires: date | None = None, config: Config | None = None) -> Baseline:  # type: ignore[no-untyped-def]
    base, _ = add_to_baseline(
        None,
        list(findings),
        owner="team-a",
        reason="legacy code",
        expires=expires,
        today=TODAY,
        config=config or cfg(require_expiry_at_or_above="none"),
    )
    return base


# ---- baseline -----------------------------------------------------------------------------


def test_new_findings_are_not_silently_accepted() -> None:
    old, fresh = finding("old"), finding("fresh")
    result, warnings = apply_acceptance([old, fresh], baseline_with(old), [], TODAY)
    status = {f.rule_id: f.status for f in result}
    assert status == {"old": FindingStatus.BASELINE, "fresh": FindingStatus.NEW}
    assert not warnings


def test_accepted_findings_keep_owner_and_reason_visible() -> None:
    f = finding("old")
    result, _ = apply_acceptance([f], baseline_with(f), [], TODAY)
    assert "team-a" in (result[0].status_detail or "") and "legacy code" in (result[0].status_detail or "")


def test_expired_baseline_entry_makes_finding_new_again() -> None:
    f = finding("old")
    base = baseline_with(f, expires=TODAY + timedelta(days=10))
    later = TODAY + timedelta(days=11)
    result, warnings = apply_acceptance([f], base, [], later)
    assert result[0].status is FindingStatus.NEW and result[0].suppression_expired
    assert any("expired" in w for w in warnings)


def test_entry_valid_on_its_expiry_day() -> None:
    f = finding("old")
    base = baseline_with(f, expires=TODAY)
    result, _ = apply_acceptance([f], base, [], TODAY)
    assert result[0].status is FindingStatus.BASELINE


def test_stale_entries_are_reported() -> None:
    gone = finding("gone")
    _, warnings = apply_acceptance([], baseline_with(gone), [], TODAY)
    assert any("stale" in w for w in warnings)


def test_line_moves_do_not_break_baseline() -> None:
    a = finding("r", line=3)
    b = finding("r", line=30)
    b = b.model_copy(update={"fingerprint": a.fingerprint})
    result, _ = apply_acceptance([b], baseline_with(a), [], TODAY)
    assert result[0].status is FindingStatus.BASELINE


def test_high_and_critical_require_expiry_by_policy() -> None:
    crit = finding("c", Severity.CRITICAL)
    with pytest.raises(ConfigError, match="require an expiry"):
        add_to_baseline(None, [crit], owner="o", reason="because", expires=None, today=TODAY, config=cfg())
    add_to_baseline(
        None,
        [crit],
        owner="o",
        reason="because",
        expires=TODAY + timedelta(days=30),
        today=TODAY,
        config=cfg(),
    )


def test_expiry_bounds() -> None:
    f = finding("r")
    with pytest.raises(ConfigError, match="past"):
        add_to_baseline(
            None,
            [f],
            owner="o",
            reason="because",
            expires=TODAY - timedelta(days=1),
            today=TODAY,
            config=cfg(),
        )
    with pytest.raises(ConfigError, match="max_accept_days"):
        add_to_baseline(
            None,
            [f],
            owner="o",
            reason="because",
            expires=TODAY + timedelta(days=4000),
            today=TODAY,
            config=cfg(max_accept_days=365),
        )


def test_add_to_baseline_is_idempotent_and_extends() -> None:
    a, b = finding("a"), finding("b")
    base, added = add_to_baseline(
        None,
        [a],
        owner="o",
        reason="reason one",
        expires=None,
        today=TODAY,
        config=cfg(require_expiry_at_or_above="none"),
    )
    assert len(added) == 1
    base2, added2 = add_to_baseline(
        base,
        [a, b],
        owner="o2",
        reason="reason two",
        expires=None,
        today=TODAY,
        config=cfg(require_expiry_at_or_above="none"),
    )
    assert [f.rule_id for f in added2] == ["b"] and len(base2.entries) == 2
    assert {e.owner for e in base2.entries} == {"o", "o2"}


def test_baseline_roundtrip_is_stable(tmp_path: Path) -> None:
    base = baseline_with(finding("a"), finding("b", Severity.LOW))
    path = tmp_path / "b.json"
    save_baseline(base, path)
    first = path.read_text()
    save_baseline(load_baseline(str(path)), path)
    assert path.read_text() == first
    assert oct(path.stat().st_mode & 0o777) in {"0o600", "0o644"}


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"schema_version": 2, "entries": []}',
        '{"entries": [{"fingerprint": "zz"}]}',
        '{"entries": [], "extra": 1}',
    ],
)
def test_malicious_or_malformed_baselines_are_rejected(tmp_path: Path, text: str) -> None:
    p = tmp_path / "b.json"
    p.write_text(text)
    with pytest.raises(ConfigError):
        load_baseline(str(p))


def test_baseline_cannot_execute_code(tmp_path: Path) -> None:
    p = tmp_path / "b.json"
    p.write_text('{"entries": [{"fingerprint": "__import__(\'os\').system(\'id\')"}]}')
    with pytest.raises(ConfigError):
        load_baseline(str(p))


def test_review_rows_flag_problems() -> None:
    f1, f2, f3 = finding("a"), finding("b"), finding("c")
    base = baseline_with(f1)
    base, _ = add_to_baseline(
        base,
        [f2],
        owner="o",
        reason="soon",
        expires=TODAY + timedelta(days=5),
        today=TODAY,
        config=cfg(require_expiry_at_or_above="none"),
    )
    base, _ = add_to_baseline(
        base,
        [f3],
        owner="o",
        reason="x" * 5,
        expires=TODAY + timedelta(days=100),
        today=TODAY,
        config=cfg(require_expiry_at_or_above="none"),
    )
    rows = {r["rule"]: r["health"] for r in review_baseline(base, [f2, f3], TODAY + timedelta(days=1))}
    assert rows["a"] == "no-expiry,STALE" and rows["b"] == "expires-soon" and rows["c"] == "ok"
    expired = {r["rule"]: r["health"] for r in review_baseline(base, None, TODAY + timedelta(days=50))}
    assert "EXPIRED" in expired["b"]


# ---- suppressions --------------------------------------------------------------------------


def supp(**kw: object) -> Suppression:
    return Suppression.model_validate({"owner": "sec", "reason": "approved risk", **kw})


def test_rule_and_path_suppression() -> None:
    a, b = finding("rule.x", file="tests/a.py"), finding("rule.x", file="app/a.py")
    result, _ = apply_acceptance([a, b], None, [supp(rule_id="rule.x", path="tests/*")], TODAY)
    assert {f.file: f.status for f in result} == {
        "tests/a.py": FindingStatus.SUPPRESSED,
        "app/a.py": FindingStatus.NEW,
    }


def test_suppression_by_fingerprint_and_scanner_scope() -> None:
    a = finding("r", scanner="semgrep")
    result, _ = apply_acceptance([a], None, [supp(fingerprint=a.fingerprint)], TODAY)
    assert result[0].status is FindingStatus.SUPPRESSED
    result, _ = apply_acceptance([a], None, [supp(rule_id="r", scanner="trivy")], TODAY)
    assert result[0].status is FindingStatus.NEW


def test_expired_suppression_does_not_apply() -> None:
    a = finding("r")
    result, warnings = apply_acceptance(
        [a], None, [supp(rule_id="r", expires=TODAY - timedelta(days=1))], TODAY
    )
    assert result[0].status is FindingStatus.NEW and result[0].suppression_expired
    assert any("expired" in w for w in warnings)


def test_unused_suppressions_are_reported() -> None:
    _, warnings = apply_acceptance([finding("r")], None, [supp(rule_id="other")], TODAY)
    assert any("matched nothing" in w for w in warnings)


# ---- policy -------------------------------------------------------------------------------------


def test_policy_threshold() -> None:
    findings = [finding("a", Severity.MEDIUM), finding("b", Severity.LOW)]
    assert evaluate(findings, PolicySettings(fail_on="high")).passed
    assert not evaluate(findings, PolicySettings(fail_on="medium")).passed
    assert evaluate(findings, PolicySettings(fail_on="medium"), "critical").passed
    assert evaluate(findings, PolicySettings(fail_on="high"), "low").violating_findings == 2


def test_policy_ignores_accepted_findings_unless_configured() -> None:
    f = finding("a", Severity.CRITICAL, status=FindingStatus.BASELINE)
    assert evaluate([f], PolicySettings(fail_on="high")).passed
    assert not evaluate([f], PolicySettings(fail_on="high", fail_on_baseline=True)).passed


def test_policy_none_is_report_only() -> None:
    result = evaluate([finding("a", Severity.CRITICAL)], PolicySettings(fail_on="none"))
    assert result.passed and "report-only" in result.reasons[0]


def test_policy_mentions_expired_acceptance() -> None:
    f = finding("a", Severity.HIGH, suppression_expired=True)
    assert "expired" in " ".join(evaluate([f], PolicySettings()).reasons)
