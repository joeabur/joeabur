"""Markdown pull-request summary, GitHub annotations and GitLab Code Quality output."""

from __future__ import annotations

import json
import re
from typing import Any

from ..schemas import FindingStatus, ScanResult, Severity

MAX_TABLE_ROWS = 50
MAX_ANNOTATIONS = 50
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~])")


def md_escape(text: str | None, limit: int = 160) -> str:
    """Escape Markdown/HTML and neutralise @mentions and autolinks in untrusted text."""
    value = (text or "").replace("\r", " ").replace("\n", " ")
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    value = _MD_SPECIAL.sub(r"\\\1", value)
    return value.replace("@", "@​").replace("&", "&amp;").replace("://", ":&#47;&#47;")


def render_markdown(result: ScanResult) -> str:
    ok = result.exit_code == 0
    lines = [
        f"## reposcan: {'✅ passed' if ok else '❌ failed'}",
        "",
        f"{md_escape(result.exit_reason, 300)} (exit code {result.exit_code})",
        "",
        "| Severity | All | New |",
        "|---|---:|---:|",
    ]
    for sev, total in result.summary.by_severity.items():
        lines.append(f"| {sev} | {total} | {result.summary.new_by_severity.get(sev, 0)} |")
    lines += [
        "",
        "### Scanners",
        "",
        "| Scanner | Status | Version | Findings |",
        "|---|---|---|---:|",
    ]
    for r in result.scanners:
        note = f" — {md_escape(r.error, 120)}" if r.error else ""
        lines.append(
            f"| {md_escape(r.name)} | {md_escape(r.status)}{note} | "
            f"{md_escape(r.version or '-')} | {r.finding_count} |"
        )
    new = [f for f in result.findings if f.status is FindingStatus.NEW]
    lines += ["", f"### New findings ({len(new)})", ""]
    if new:
        lines += ["| Severity | Scanner | Rule | Location |", "|---|---|---|---|"]
        for f in new[:MAX_TABLE_ROWS]:
            loc = f.file or f.artifact or "-"
            loc = f"{loc}:{f.line}" if f.line and f.file else loc
            lines.append(
                f"| {f.severity.value} | {md_escape(f.scanner)} | {md_escape(f.rule_id, 60)} | "
                f"{md_escape(loc, 90)} |"
            )
        if len(new) > MAX_TABLE_ROWS:
            lines.append(f"\n…and {len(new) - MAX_TABLE_ROWS} more (see the JSON/SARIF report).")
    else:
        lines.append("No new findings.")
    accepted = len(result.findings) - len(new)
    lines += ["", f"Accepted (baseline/suppressed): {accepted}"]
    if result.warnings:
        lines += ["", "### Warnings", ""] + [f"- {md_escape(w, 300)}" for w in result.warnings]
    return "\n".join(lines) + "\n"


def _gh_escape(text: str, *, prop: bool = False) -> str:
    out = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        out = out.replace(":", "%3A").replace(",", "%2C")
    return out


def render_github_annotations(result: ScanResult) -> str:
    """GitHub workflow commands for new findings (all values percent-encoded)."""
    out = []
    for f in [x for x in result.findings if x.status is FindingStatus.NEW][:MAX_ANNOTATIONS]:
        level = "error" if f.severity.rank >= Severity.HIGH.rank else "warning"
        props = []
        if f.file:
            props.append(f"file={_gh_escape(f.file, prop=True)}")
            if f.line:
                props.append(f"line={f.line}")
        props.append(f"title={_gh_escape(f'{f.scanner}: {f.rule_id}', prop=True)}")
        out.append(f"::{level} {','.join(props)}::{_gh_escape(f'[{f.severity.value}] {f.title}')}")
    return "\n".join(out) + ("\n" if out else "")


_CQ = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
}


def render_codequality(result: ScanResult) -> str:
    """GitLab Code Quality JSON, shown as merge-request widgets (new findings only)."""
    items: list[dict[str, Any]] = []
    for f in result.findings:
        if f.status is not FindingStatus.NEW:
            continue
        items.append(
            {
                "description": f"[{f.scanner}] {f.title}"[:500],
                "check_name": f.rule_id,
                "fingerprint": f.fingerprint,
                "severity": _CQ[f.severity],
                "location": {"path": f.file or ".", "lines": {"begin": f.line or 1}},
            }
        )
    return json.dumps(items, indent=2, sort_keys=True) + "\n"
