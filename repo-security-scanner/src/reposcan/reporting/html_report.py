"""Self-contained HTML report.

Every dynamic value is escaped with :func:`html.escape`; the page ships no
script, loads no external resource and carries a restrictive CSP.
"""

from __future__ import annotations

import base64
import hashlib
from html import escape

from ..schemas import Finding, FindingStatus, ScanResult

_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f23;--mut:#586069;--line:#d0d7de;--crit:#a40e26;--high:#cf222e;--med:#9a6700;--low:#0969da;--info:#57606a;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9da7b3;--line:#30363d;--crit:#ff7b72;--high:#ff7b72;--med:#e3b341;--low:#79c0ff;--info:#8b949e;--ok:#56d364}}
body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px 16px 48px}
main{max-width:1100px;margin:0 auto}h1{font-size:22px}h2{font-size:17px;margin-top:28px}
table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
code{font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-all}
.sev{font-weight:600;text-transform:uppercase;font-size:12px}.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
.pass{color:var(--ok)}.fail{color:var(--high)}.mut{color:var(--mut)}
"""
_CSS_HASH = base64.b64encode(hashlib.sha256(_CSS.encode()).digest()).decode()


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _location(f: Finding) -> str:
    if f.file:
        return f"{f.file}:{f.line}" if f.line else f.file
    return f.artifact or "-"


def _row(f: Finding) -> str:
    dep = ""
    if f.dependency:
        d = f.dependency
        dep = f"{d.name} {d.installed_version or ''}"
        if d.fixed_version:
            dep += f" → {d.fixed_version}"
    ids = ", ".join([*f.cve, *f.cwe])
    status = f.status.value + (" (acceptance expired)" if f.suppression_expired else "")
    return (
        f"<tr><td class='sev {_e(f.severity.value)}'>{_e(f.severity.value)}</td>"
        f"<td>{_e(f.scanner)}</td><td><code>{_e(f.rule_id)}</code><br>{_e(f.title)}</td>"
        f"<td><code>{_e(_location(f))}</code></td><td>{_e(dep)}<br><span class='mut'>{_e(ids)}</span></td>"
        f"<td><code>{_e(f.evidence)}</code></td><td>{_e(f.remediation)}</td>"
        f"<td>{_e(status)}<br><span class='mut'>{_e(f.status_detail)}</span></td></tr>"
    )


def _table(findings: list[Finding]) -> str:
    if not findings:
        return "<p class='mut'>None.</p>"
    head = "".join(
        f"<th>{h}</th>"
        for h in (
            "Severity",
            "Scanner",
            "Rule",
            "Location",
            "Dependency / IDs",
            "Evidence (redacted)",
            "Remediation",
            "Status",
        )
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(_row(f) for f in findings)}</tbody></table>"


def render_html(result: ScanResult) -> str:
    meta, scope, policy = result.metadata, result.scope, result.policy
    new = [f for f in result.findings if f.status is FindingStatus.NEW]
    accepted = [f for f in result.findings if f.status is not FindingStatus.NEW]
    verdict = "PASS" if result.exit_code == 0 else "FAIL"
    cls = "pass" if result.exit_code == 0 else "fail"
    runs = "".join(
        f"<tr><td>{_e(r.name)}</td><td>{_e(r.status)}</td><td>{_e(r.version or '-')}</td>"
        f"<td>{_e(r.supported_versions or '-')}</td><td>{_e(r.finding_count)}</td>"
        f"<td>{_e(r.duration_seconds)}</td><td>{_e(r.error or '')}</td></tr>"
        for r in result.scanners
    )
    sev = "".join(
        f"<tr><td class='sev {_e(k)}'>{_e(k)}</td><td>{_e(v)}</td><td>{_e(result.summary.new_by_severity.get(k, 0))}</td></tr>"
        for k, v in result.summary.by_severity.items()
    )
    warns = "".join(f"<li>{_e(w)}</li>" for w in result.warnings) or "<li class='mut'>None</li>"
    exts = ", ".join(f"{k}: {v}" for k, v in scope.top_extensions.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{_CSS_HASH}'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>reposcan report</title><style>{_CSS}</style></head>
<body><main>
<h1>reposcan report <span class="{cls}">{verdict}</span></h1>
<p>{_e(result.exit_reason)} (exit code {_e(result.exit_code)})</p>
<h2>Scan summary</h2>
<p>Target <code>{_e(scope.target)}</code> · {_e(scope.file_count)} files · {_e(scope.total_bytes)} bytes ·
symlinks skipped: {_e(scope.symlinks_skipped)} · git repository: {_e(scope.is_git_repository)} ·
history scanned: {_e(scope.history_scanned)}{" · truncated file walk" if scope.truncated else ""}</p>
<p class="mut">File types: {_e(exts)}</p>
<p class="mut">reposcan {_e(meta.tool_version)} · schema {_e(meta.schema_version)} · started {_e(meta.started_at.isoformat())} ·
finished {_e(meta.finished_at.isoformat())} · offline mode: {_e(meta.offline)} · Python {_e(meta.python_version)} · {_e(meta.platform)}</p>
<h2>Policy</h2>
<p>Threshold: <strong>{_e(policy.fail_on)}</strong> · baseline findings count: {_e(policy.fail_on_baseline)} ·
violations: {_e(policy.violating_findings)}</p>
<ul>{"".join(f"<li>{_e(r)}</li>" for r in policy.reasons) or '<li class="mut">No violations.</li>'}</ul>
<h2>Severity counts</h2>
<table><thead><tr><th>Severity</th><th>All</th><th>New</th></tr></thead><tbody>{sev}</tbody></table>
<h2>Scanners</h2>
<table><thead><tr><th>Scanner</th><th>Status</th><th>Version</th><th>Supported</th><th>Findings</th><th>Seconds</th><th>Error</th></tr></thead><tbody>{runs}</tbody></table>
<h2>Warnings</h2><ul>{warns}</ul>
<h2>New findings ({len(new)})</h2>{_table(new)}
<h2>Accepted findings: baseline and suppressions ({len(accepted)})</h2>{_table(accepted)}
</main></body></html>
"""
