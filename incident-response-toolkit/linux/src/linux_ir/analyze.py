"""Shared analysis pipeline used by ``scan`` and ``report``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .detections.engine import evaluate, find_rules_dir, load_rules
from .evidence.manifest import load_evidence, verify_manifest
from .ioc.matcher import match_iocs
from .ioc.schema import load_iocs
from .models import Finding


def analyze(
    evdir: Path, config: dict[str, Any], iocs: Path | None, rules_dir: Path | None, baseline: Path | None
) -> dict[str, Any]:
    arts, manifest = load_evidence(evdir)
    verification = verify_manifest(evdir) if manifest else None
    base_arts = load_evidence(baseline)[0] if baseline else None
    rules = load_rules(find_rules_dir(rules_dir))
    det = config["detection"]
    findings, notes = evaluate(
        rules, arts, base_arts, det["max_findings_per_rule"], det["max_regex_input_chars"], det["max_records"]
    )
    ioc_meta = None
    ioc_warnings: list[str] = []
    if iocs:
        cip = config["ioc"]["case_insensitive_paths"]
        ioc_meta, inds, ioc_warnings = load_iocs(iocs, cip)
        findings += match_iocs(arts, inds, config["ioc"]["match_subdomains"], cip)
    findings.sort(key=lambda f: (["critical", "high", "medium", "low", "info"].index(f.severity), f.rule_id))
    if verification is None:
        notes.append("no manifest.json present: integrity could not be verified")
    return {
        "artifacts": arts,
        "manifest": manifest,
        "verification": verification,
        "findings": findings,
        "notes": notes + ioc_warnings,
        "ioc_meta": ioc_meta,
        "rules_count": len(rules),
    }


def finding_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.to_dict() for f in findings]
