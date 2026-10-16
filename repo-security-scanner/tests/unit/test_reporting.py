from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest

from reposcan.errors import ConfigError
from reposcan.reporting.html_report import render_html
from reposcan.reporting.json_report import render_json
from reposcan.reporting.markdown import (
    md_escape,
    render_codequality,
    render_github_annotations,
    render_markdown,
)
from reposcan.reporting.sarif import build_sarif, render_sarif
from reposcan.reporting.writer import write_reports, write_text_safely
from reposcan.schemas import FindingStatus, ScanResult, Severity

from ..helpers import FIXTURES
from .factories import dep_finding, finding, result

SARIF_SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text())

XSS = "<script>alert(1)</script><img src=x onerror=alert(1)>\"'&"


def sample() -> ScanResult:
    return result(
        [
            finding("r.sast", Severity.HIGH, file="app/a.py", line=7),
            finding(
                "r.secret",
                Severity.HIGH,
                scanner="gitleaks",
                file="cfg/.env",
                line=2,
                evidence='token = "ab[REDACTED:32]"',
            ),
            dep_finding(),
            finding(
                "r.med",
                Severity.MEDIUM,
                file="b.py",
                status=FindingStatus.BASELINE,
                status_detail="baseline: team-a: legacy",
            ),
            finding("r.low", Severity.LOW, file=None, line=None, artifact="alpine:3.20 (alpine 3.20)"),
        ]
    )


# ---- SARIF -----------------------------------------------------------------------------------


def test_sarif_validates_against_official_schema() -> None:
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(build_sarif(sample()))


def test_sarif_empty_result_validates() -> None:
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(build_sarif(result([])))


def test_sarif_with_hostile_values_validates() -> None:
    r = result([finding("r‮<x>", title=XSS, file="we ird/é.py")])
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(build_sarif(r))


def test_sarif_semantics() -> None:
    sarif = build_sarif(sample())
    assert sarif["version"] == "2.1.0" and {r["automationDetails"]["id"] for r in sarif["runs"]} == {
        "reposcan/gitleaks",
        "reposcan/semgrep",
        "reposcan/trivy",
    }
    results = [x for run in sarif["runs"] for x in run["results"]]
    by_rule = {x["ruleId"]: x for x in results}
    assert by_rule["r.sast"]["level"] == "error" and by_rule["r.sast"]["baselineState"] == "new"
    assert by_rule["r.med"]["baselineState"] == "unchanged"
    assert by_rule["r.med"]["suppressions"][0]["justification"].startswith("baseline: team-a")
    assert "suppressions" not in by_rule["r.sast"]
    assert by_rule["r.sast"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert by_rule["r.low"]["locations"][0]["logicalLocations"][0]["name"].startswith("alpine")
    assert all(x["partialFingerprints"]["reposcan/v1"] for x in results)


def test_sarif_marks_failed_scanner_invocations() -> None:
    from reposcan.schemas import ScannerRun

    runs = [ScannerRun(name="semgrep", status="failed", exit_code=2, error="boom")]
    sarif = build_sarif(result([], runs=runs))
    inv = sarif["runs"][0]["invocations"][0]
    assert (
        inv["executionSuccessful"] is False
        and inv["toolExecutionNotifications"][0]["message"]["text"] == "boom"
    )


# ---- determinism --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "render", [render_json, render_html, render_sarif, render_markdown, render_codequality]
)
def test_reports_are_deterministic(render) -> None:  # type: ignore[no-untyped-def]
    a, b = sample(), sample()
    b.findings.reverse()  # input order must not matter once sorted by the model
    b.findings.sort(key=lambda f: f.sort_key())
    assert render(a) == render(b) == render(a)


def test_json_roundtrips_through_schema() -> None:
    text = render_json(sample())
    assert ScanResult.model_validate_json(text) == sample()
    assert text.endswith("\n") and json.loads(text)["metadata"]["schema_version"] == "1.0"


def test_source_date_epoch_makes_timestamps_reproducible(monkeypatch: pytest.MonkeyPatch) -> None:
    from reposcan.orchestrator import now_utc

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert now_utc().isoformat() == "2023-11-14T22:13:20+00:00"


# ---- HTML ---------------------------------------------------------------------------------------


def test_html_escapes_all_untrusted_fields() -> None:
    r = result(
        [
            finding(XSS, title=XSS, file=f"{XSS}.py", evidence=XSS, status_detail=XSS),
            dep_finding(),
        ]
    )
    r.warnings.append(XSS)
    r.scanners[0].error = XSS
    html = render_html(r)
    assert "<script>" not in html and "<img" not in html and "onerror=alert(1)>" not in html
    assert "&lt;script&gt;" in html and "&#x27;" in html and "&quot;" in html


def test_html_has_no_scripts_or_external_resources_and_a_strict_csp() -> None:
    html = render_html(sample())
    assert "<script" not in html.lower()
    assert not re.search(r"(?:src|href)=[\"']?https?:", html)
    assert "default-src 'none'" in html and "style-src 'sha256-" in html


def test_html_css_hash_matches_inline_style() -> None:
    import base64
    import hashlib

    html = render_html(sample())
    css = re.search(r"<style>(.*?)</style>", html, re.S).group(1)  # type: ignore[union-attr]
    digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in html


# ---- markdown / annotations / code quality ------------------------------------------------------


def test_markdown_escapes_html_mentions_and_links() -> None:
    r = result([finding("rule", title="x", file="@octocat/<b>bold</b>[a](https://evil.example)|x.py")])
    md = render_markdown(r)
    assert ("<b>" not in md and "@octocat" not in md.replace("@​", "")) or "@​" in md
    assert "https://evil.example" not in md
    assert "|x.py" not in md.replace("\\|", "")


def test_md_escape_truncates_and_strips_newlines() -> None:
    out = md_escape("a\nb\r" + "z" * 500, limit=40)
    assert "\n" not in out and len(out) <= 45


def test_markdown_lists_only_new_findings_in_table() -> None:
    md = render_markdown(sample())
    assert "r.sast" in md and "r.med" not in md and "Accepted (baseline/suppressed): 1" in md


def test_github_annotations_encode_workflow_command_injection() -> None:
    evil = "x\n::error::injected\r\n,file=/etc/passwd"
    out = render_github_annotations(result([finding("r", title=evil, file="a,b:c.py")]))
    # A workflow command is only recognised at the start of a line: the payload must stay on one line.
    assert len(out.splitlines()) == 1 and out.startswith("::error file=")
    assert "%0A" in out and "\r" not in out
    assert "file=a%2Cb%3Ac.py" in out


def test_github_annotations_skip_accepted_and_cap() -> None:
    many = [finding(f"r{i}", file=f"f{i}.py") for i in range(80)]
    assert render_github_annotations(result(many)).count("::error") == 50
    assert render_github_annotations(result([finding("a", status=FindingStatus.BASELINE)])) == ""


def test_codequality_format() -> None:
    items = json.loads(render_codequality(sample()))
    assert {i["check_name"] for i in items} == {"r.sast", "r.secret", "CVE-2024-0001", "r.low"}
    for item in items:
        assert item["severity"] in {"info", "minor", "major", "critical", "blocker"}
        assert set(item) == {"description", "check_name", "fingerprint", "severity", "location"}


# ---- writer --------------------------------------------------------------------------------------


def test_write_reports_creates_expected_files_with_private_mode(tmp_path: Path) -> None:
    paths = write_reports(sample(), tmp_path / "out", ["json", "html", "sarif", "md", "codequality"])
    assert {p.name for p in paths} == {
        "reposcan-report.json",
        "reposcan-report.html",
        "reposcan.sarif",
        "reposcan-summary.md",
        "gl-code-quality-report.json",
    }
    assert all(oct(p.stat().st_mode & 0o777) == "0o600" for p in paths)
    assert not list((tmp_path / "out").glob(".*.tmp"))


def test_write_reports_rejects_unknown_format(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        write_reports(sample(), tmp_path, ["pdf"])


def test_writer_refuses_symlink_destination(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    (tmp_path / "reposcan-report.json").symlink_to(victim)
    with pytest.raises(ConfigError, match="symbolic link"):
        write_reports(sample(), tmp_path, ["json"])
    assert victim.read_text() == "keep"


def test_write_text_safely_overwrites_atomically(tmp_path: Path) -> None:
    write_text_safely(tmp_path, "x.txt", "one")
    write_text_safely(tmp_path, "x.txt", "two")
    assert (tmp_path / "x.txt").read_text() == "two"
