"""Report generation: JSON, CSV, executive-summary and technical Markdown."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .. import PLATFORM_LABEL, TOOL_NAME, __version__
from ..evidence.manifest import LIMITATIONS
from ..models import SEVERITIES, Finding
from ..utils.paths import sha256_bytes, write_exclusive
from ..utils.redact import Redactor
from ..utils.timeutil import utcnow_iso

STATIC_NOT_ASSESSED = [
    "Memory contents, disk slack/unallocated space and deleted-file recovery (live collection only).",
    "Browser profiles, credential stores, private keys and credential hashes (never collected by design).",
    "Kernel-level malware and anything hidden by SIP/TCC-protected locations cannot be assessed from user space.",
    "Unified-log events that macOS redacts (<private>), expires or restricts to administrators.",
    "Remote/centralised logs and any host not examined by this run.",
]
CSV_FIELDS = [
    "rule_id",
    "rule_version",
    "classification",
    "severity",
    "confidence",
    "category",
    "title",
    "artifact",
    "evidence_ref",
    "why",
    "attack",
    "false_positives",
    "next_steps",
]


def _observations(arts: dict[str, dict[str, Any]], manifest: dict[str, Any] | None) -> list[str]:
    obs: list[str] = []
    host = next((r for r in arts.get("inventory", {}).get("records", []) if r.get("kind") == "host"), None)
    if host:
        obs.append(
            f"Host {host.get('hostname')} runs {host.get('pretty_name') or host.get('distribution')} "
            f"(kernel {host.get('kernel')}, {host.get('architecture')}); init system: "
            f"{(host.get('init') or {}).get('name')}; uptime {host.get('uptime_seconds')}s."
        )
    if "processes" in arts:
        recs = arts["processes"]["records"]
        obs.append(
            f"{len(recs)} processes were recorded; "
            f"{sum(1 for r in recs if r.get('visibility') == 'limited')} had limited visibility."
        )
    if "network" in arts:
        socks = [r for r in arts["network"]["records"] if r.get("kind") == "socket"]
        listening = [r for r in socks if r.get("state") in ("LISTEN", "UNCONN")]
        obs.append(f"{len(socks)} sockets recorded, {len(listening)} listening/unconnected.")
    if "persistence" in arts:
        c = Counter(r.get("kind") for r in arts["persistence"]["records"])
        obs.append("Persistence artifacts: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items()) if k) + ".")
    if "logs" in arts:
        c2 = Counter(r.get("event_type") for r in arts["logs"]["records"] if r.get("kind") == "auth_event")
        obs.append(
            "Authentication events in window: "
            + (", ".join(f"{k}={v}" for k, v in sorted(c2.items())) or "none recognised")
            + "."
        )
    if manifest:
        obs.append(
            f"Collection ran {manifest.get('started_at')} → {manifest.get('finished_at')} UTC; "
            f"privileged={manifest.get('privileged')}."
        )
    return obs


def build_report(
    arts: dict[str, dict[str, Any]],
    manifest: dict[str, Any] | None,
    findings: list[Finding],
    ioc_meta: dict[str, Any] | None,
    rule_notes: list[str],
    verification: dict[str, Any] | None,
    redactor: Redactor,
) -> dict[str, Any]:
    heur = [f for f in findings if f.classification == "heuristic"]
    iocs = [f for f in findings if f.classification == "ioc_match"]
    errors: list[dict[str, Any]] = []
    coverage: dict[str, list[str]] = {}
    unexamined: list[str] = []
    for name, doc in arts.items():
        coverage.setdefault(doc["status"], []).append(name)
        errors.extend({"artifact": name, **e} for e in doc["errors"])
    if manifest:
        for name in manifest.get("coverage", {}).get("skipped", []):
            unexamined.append(f"collector '{name}' was not run")
        for a in manifest.get("artifacts", []):
            if a["status"] in ("partial", "failed", "unavailable"):
                unexamined.append(f"collector '{a['name']}' status={a['status']}")
    counts = Counter(f.severity for f in heur)
    ioc_counts = Counter(f.severity for f in iocs)
    host = (manifest or {}).get("host") or {}
    report = {
        "schema_version": 1,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": utcnow_iso(),
        "platform": PLATFORM_LABEL,
        "host": host,
        "scope": {
            k: (manifest or {}).get(k)
            for k in (
                "profile",
                "collectors_requested",
                "started_at",
                "finished_at",
                "privileged",
                "euid",
                "log_window_hours",
            )
        },
        "integrity": verification,
        "artifact_counts": {n: len(d["records"]) for n, d in arts.items()},
        "coverage": coverage,
        "detection_counts_by_severity": {s: counts.get(s, 0) for s in SEVERITIES},
        "ioc_counts_by_severity": {s: ioc_counts.get(s, 0) for s in SEVERITIES},
        "confirmed_observations": _observations(arts, manifest),
        "heuristic_findings": [f.to_dict() for f in heur],
        "ioc_matches": [f.to_dict() for f in iocs],
        "ioc_file": ioc_meta,
        "collection_errors": errors,
        "not_assessed": STATIC_NOT_ASSESSED + unexamined + rule_notes,
        "limitations": LIMITATIONS,
        "recommended_next_steps": _next_steps(heur, iocs, errors, verification),
    }
    return redactor.data(report)


def _next_steps(
    heur: list[Finding], iocs: list[Finding], errors: list[Any], verification: dict[str, Any] | None
) -> list[str]:
    steps = []
    if verification is not None and not verification.get("ok"):
        steps.append("Evidence integrity verification FAILED: do not rely on these results until resolved.")
    if iocs:
        steps.append("Triage IOC matches first: validate indicator provenance and trace each evidence reference.")
    if heur:
        steps.append("Review heuristic findings by severity; each lists false positives and next steps.")
    if errors:
        steps.append(
            "Review collection errors; re-run affected collectors with appropriate (authorised) privileges "
            "if the missing data matters."
        )
    steps.append("Preserve the evidence directory and store a copy of the manifest SHA-256 separately.")
    return steps


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, quoting=csv.QUOTE_ALL)
    w.writeheader()
    for f in report["heuristic_findings"] + report["ioc_matches"]:
        row = {k: f.get(k, "") for k in CSV_FIELDS}
        for k in ("attack", "false_positives", "next_steps"):
            row[k] = " | ".join(f.get(k, []))
        # neutralise spreadsheet formula injection
        for k, v in row.items():
            if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
                row[k] = "'" + v
        w.writerow(row)
    return buf.getvalue()


def _md_escape(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def _finding_md(f: dict[str, Any]) -> str:
    lines = [
        f"#### {f['rule_id']} v{f['rule_version']} — {f['title']}",
        f"- **Severity / confidence:** {f['severity']} / {f['confidence']} ({f['classification']})",
        f"- **Evidence:** `{f['evidence_ref']}`",
        f"- **Why it matched:** {f['why']}",
        f"- **ATT&CK:** {', '.join(f['attack']) or 'n/a'}",
        "- **Known false positives:**",
        *[f"  - {x}" for x in f["false_positives"]],
        "- **Next steps:**",
        *[f"  - {x}" for x in f["next_steps"]],
        "",
    ]
    return "\n".join(lines)


def executive_summary(r: dict[str, Any]) -> str:
    sev = r["detection_counts_by_severity"]
    integ = r["integrity"]
    cov_bad = [k for k in ("partial", "failed", "unavailable", "skipped") if r["coverage"].get(k)]
    out = [
        f"# Executive Summary — {r['tool']['name']} {r['tool']['version']}",
        "",
        f"Generated: {r['generated_at']} UTC · Host: **{r['host'].get('hostname', 'unknown')}**",
        "",
        "> This report lists *indicators and leads*. A finding or IOC match is **not** confirmation of "
        "compromise, and the absence of findings is **not** proof that the host is clean.",
        "",
        "## Integrity",
        "",
        (
            "Manifest verification: **PASSED** (" + str(integ["verified"]) + " files)"
            if integ and integ.get("ok")
            else "Manifest verification: **FAILED or not performed**: treat results with caution."
        ),
        "",
        "## Counts",
        "",
        "| Severity | Heuristic findings | IOC matches |",
        "|---|---|---|",
        *[f"| {s} | {sev[s]} | {r['ioc_counts_by_severity'][s]} |" for s in reversed(SEVERITIES)],
        "",
        "## Collection coverage",
        "",
    ]
    if cov_bad or r["collection_errors"]:
        out.append(
            f"**Incomplete coverage:** {len(r['collection_errors'])} collection error(s); "
            f"artifacts with status {', '.join(cov_bad) or 'ok'}. Results reflect only what could be read."
        )
    else:
        out.append("All requested collectors completed without errors (within their documented scope).")
    out += ["", "## Top findings", ""]
    top = sorted(r["heuristic_findings"] + r["ioc_matches"], key=lambda f: -SEVERITIES.index(f["severity"]))[:5]
    out += [f"- **{f['severity'].upper()}** {f['rule_id']}: {f['why']}" for f in top] or ["- None."]
    out += ["", "## Recommended next steps", "", *[f"1. {s}" for s in r["recommended_next_steps"]], ""]
    return "\n".join(out)


def technical_report(r: dict[str, Any]) -> str:
    out = [
        f"# Technical Findings Report — {r['tool']['name']} {r['tool']['version']}",
        "",
        f"Generated {r['generated_at']} UTC.",
        "",
        "## Host and scope",
        "",
        "```json",
        json.dumps({"host": r["host"], "scope": r["scope"]}, indent=2, default=str),
        "```",
        "",
        "## Artifact counts",
        "",
        "| Artifact | Records | Status |",
        "|---|---|---|",
    ]
    status_of = {n: s for s, names in r["coverage"].items() for n in names}
    out += [f"| {n} | {c} | {status_of.get(n, '?')} |" for n, c in sorted(r["artifact_counts"].items())]
    out += [
        "",
        "## 1. Confirmed observations",
        "",
        *[f"- {o}" for o in r["confirmed_observations"]],
        "",
        "## 2. Heuristic findings",
        "",
    ]
    out += [_finding_md(f) for f in r["heuristic_findings"]] or ["None.", ""]
    out += [
        "## 3. IOC matches",
        "",
        "An IOC match means a value equals a supplied indicator; it does not confirm compromise.",
        "",
    ]
    if r["ioc_file"]:
        out += [
            f"IOC file: {r['ioc_file'].get('name')} ({r['ioc_file'].get('indicator_count')} indicators, "
            f"synthetic={r['ioc_file'].get('synthetic')})",
            "",
        ]
    out += [_finding_md(f) for f in r["ioc_matches"]] or ["None (or no IOC file supplied).", ""]
    out += ["## 4. Collection errors", ""]
    out += ["| Artifact | Source | Kind | Message |", "|---|---|---|---|"]
    out += [
        f"| {e['artifact']} | {_md_escape(e['source'])} | {e['kind']} | {_md_escape(e['message'])} |"
        for e in r["collection_errors"]
    ] or ["| – | – | – | none |"]
    out += [
        "",
        "## 5. Areas not assessed",
        "",
        *[f"- {x}" for x in r["not_assessed"]],
        "",
        "## Known limitations",
        "",
        *[f"- {x}" for x in r["limitations"]],
        "",
    ]
    return "\n".join(out)


def write_reports(report: dict[str, Any], outdir: Path, manifest_src: Path | None) -> list[Path]:
    outdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {
        "report.json": json.dumps(report, indent=2, default=str) + "\n",
        "findings.csv": to_csv(report),
        "executive-summary.md": executive_summary(report),
        "technical-report.md": technical_report(report),
    }
    written = []
    for name, text in files.items():
        p = outdir / name
        write_exclusive(p, text.encode())
        written.append(p)
    if manifest_src and manifest_src.is_file():
        data = manifest_src.read_bytes()
        p = outdir / "evidence-manifest.json"
        write_exclusive(p, data)
        written.append(p)
        write_exclusive(outdir / "evidence-manifest.sha256", f"{sha256_bytes(data)}  evidence-manifest.json\n".encode())
        written.append(outdir / "evidence-manifest.sha256")
    return written
