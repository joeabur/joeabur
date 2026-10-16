"""SARIF 2.1.0 output (one run per scanner)."""

from __future__ import annotations

import json
from typing import Any

from ..schemas import Finding, FindingStatus, ScanResult, Severity

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def _result(f: Finding) -> dict[str, Any]:
    text = f.title if not f.remediation else f"{f.title} — {f.remediation}"
    uri = f.file or "."
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
    }
    if f.line:
        region: dict[str, Any] = {"startLine": f.line}
        if f.end_line and f.end_line >= f.line:
            region["endLine"] = f.end_line
        location["physicalLocation"]["region"] = region
    if f.artifact:
        location["logicalLocations"] = [{"name": f.artifact, "kind": "module"}]
    props: dict[str, Any] = {
        "severity": f.severity.value,
        "kind": f.kind.value,
        "security-severity": _SCORE[f.severity],
        "status": f.status.value,
    }
    if f.cve:
        props["cve"] = f.cve
    if f.cwe:
        props["cwe"] = f.cwe
    if f.dependency:
        props["dependency"] = f.dependency.model_dump(mode="json", exclude_none=True)
    if f.evidence:
        props["evidence"] = f.evidence
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "level": _LEVEL[f.severity],
        "message": {"text": text},
        "locations": [location],
        "partialFingerprints": {"reposcan/v1": f.fingerprint},
        "baselineState": "new" if f.status is FindingStatus.NEW else "unchanged",
        "properties": props,
    }
    if f.status is not FindingStatus.NEW:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": f.status_detail or f.status.value,
            }
        ]
    return result


def build_sarif(result: ScanResult) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    for run in sorted(result.scanners, key=lambda r: r.name):
        findings = [f for f in result.findings if f.scanner == run.name]
        rules: dict[str, dict[str, Any]] = {}
        for f in findings:
            rules.setdefault(
                f.rule_id,
                {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.title[:200]},
                    "defaultConfiguration": {"level": _LEVEL[f.severity]},
                    "properties": {"tags": ["security", f.kind.value, *f.cwe]},
                },
            )
        driver: dict[str, Any] = {
            "name": run.name,
            "informationUri": "https://github.com/joeabur/joeabur",
            "rules": [rules[k] for k in sorted(rules)],
        }
        if run.version:
            driver["version"] = run.version
        runs.append(
            {
                "tool": {"driver": driver},
                "automationDetails": {"id": f"reposcan/{run.name}"},
                "invocations": [
                    {
                        "executionSuccessful": run.status == "ok",
                        "exitCode": run.exit_code if run.exit_code is not None else -1,
                        **(
                            {
                                "toolExecutionNotifications": [
                                    {"level": "error", "message": {"text": run.error}}
                                ]
                            }
                            if run.error
                            else {}
                        ),
                    }
                ],
                "results": [_result(f) for f in findings],
            }
        )
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": runs}


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
