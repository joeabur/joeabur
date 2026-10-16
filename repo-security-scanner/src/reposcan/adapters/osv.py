"""OSV-Scanner adapter (dependency vulnerabilities). Targets OSV-Scanner v2 (`scan source`)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..paths import relative_to_root
from ..redaction import sanitize
from ..schemas import Dependency, Finding, FindingKind, Severity, make_fingerprint
from .base import ScanContext, ScannerAdapter, as_dict, as_list, as_str


def _score_to_severity(score: str | None) -> Severity | None:
    try:
        value = float(score) if score is not None else None
    except ValueError:
        return None
    if value is None:
        return None
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if value > 0 else Severity.INFO


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    fixed: list[str] = []
    for aff in as_list(vuln.get("affected")):
        aff = as_dict(aff)
        pkg = aff.get("package")
        if isinstance(pkg, dict) and pkg.get("name") not in (None, package):
            continue
        for rng in as_list(aff.get("ranges")):
            for event in as_list(as_dict(rng).get("events")):
                value = as_dict(event).get("fixed")
                if isinstance(value, str):
                    fixed.append(value)
    return sorted(set(fixed))


class OsvAdapter(ScannerAdapter):
    name = "osv-scanner"
    executable = "osv-scanner"
    version_args = ("--version",)
    supported = ">=2.0,<3"
    tested = "2.7.0"
    # 0 = nothing found, 1 = vulnerabilities found. 127 (error, e.g. API unreachable)
    # and 128 (no packages) are NOT success; --allow-no-lockfiles maps "no packages" to 0.
    ok_exit_codes = frozenset({0, 1})

    def build_argv(self, ctx: ScanContext, exe: str, report: Path) -> list[str]:
        empty_config = ctx.workdir / "osv-empty.toml"
        empty_config.write_text("", encoding="utf-8")
        argv = [
            exe,
            "scan",
            "source",
            "--recursive",
            "--no-ignore",
            "--allow-no-lockfiles",
            "--format",
            "json",
            "--output-file",
            str(report),
            "--verbosity",
            "error",
            "--config",
            str(empty_config),
        ]
        if not ctx.config.scanners.osv.allow_network_resolution:
            argv.append("--no-resolve")
        if ctx.offline or ctx.config.scanners.osv.mode == "local-db":
            argv.append("--offline-vulnerabilities")
            if not ctx.offline:
                argv.append("--download-offline-databases")
        argv.append(str(ctx.target))
        return argv

    def parse(self, data: Any, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for result in as_list(as_dict(data).get("results")):
            result = as_dict(result)
            source = as_dict(result.get("source"))
            file = relative_to_root(as_str(source.get("path")) or "", ctx.target)
            for entry in as_list(result.get("packages")):
                entry = as_dict(entry)
                pkg = as_dict(entry.get("package"))
                name = as_str(pkg.get("name")) or "unknown"
                version = as_str(pkg.get("version"))
                ecosystem = as_str(pkg.get("ecosystem"))
                group_scores = {
                    gid: as_str(as_dict(g).get("max_severity"))
                    for g in as_list(entry.get("groups"))
                    for gid in as_list(as_dict(g).get("ids"))
                }
                emitted: set[str] = set()
                for vuln in sorted(
                    (as_dict(v) for v in as_list(entry.get("vulnerabilities"))),
                    key=lambda v: str(v.get("id")),
                ):
                    original_id = as_str(vuln.get("id")) or "unknown"
                    aliases = [a for a in as_list(vuln.get("aliases")) if isinstance(a, str)]
                    all_ids = {original_id, *aliases}
                    if all_ids & emitted:  # same advisory under another ID (PYSEC/GHSA/CVE)
                        continue
                    emitted |= all_ids
                    cves = sorted(i for i in all_ids if i.startswith("CVE-"))
                    vid = cves[0] if cves else original_id
                    score = next((group_scores[i] for i in sorted(all_ids) if group_scores.get(i)), None)
                    db = vuln.get("database_specific")
                    db = db if isinstance(db, dict) else {}
                    severity = _score_to_severity(score) or Severity.parse(
                        as_str(db.get("severity")), ctx.unknown_severity
                    )
                    cwes = sorted({str(c) for c in as_list(db.get("cwe_ids")) if str(c).startswith("CWE-")})
                    fixed = _fixed_versions(vuln, name)
                    summary = sanitize(as_str(vuln.get("summary")) or vid, limit=300)
                    refs = [
                        sanitize(str(as_dict(r).get("url")), limit=300)
                        for r in as_list(vuln.get("references"))[:5]
                        if isinstance(r, dict) and r.get("url")
                    ]
                    findings.append(
                        Finding(
                            fingerprint=make_fingerprint(self.name, vid, file or "", f"{name}@{version}"),
                            scanner=self.name,
                            kind=FindingKind.DEPENDENCY,
                            rule_id=sanitize(vid, limit=100),
                            title=summary,
                            severity=severity,
                            original_severity=sanitize(score or "", limit=20) or None,
                            file=file,
                            dependency=Dependency(
                                name=sanitize(name, limit=200),
                                installed_version=sanitize(version, limit=100) if version else None,
                                fixed_version=sanitize(fixed[0], limit=100) if fixed else None,
                                ecosystem=sanitize(ecosystem, limit=50) if ecosystem else None,
                            ),
                            cve=cves,
                            cwe=cwes,
                            references=refs,
                            remediation=(
                                f"Upgrade {sanitize(name, limit=100)} to "
                                f"{sanitize(fixed[0], limit=60)} or later."
                                if fixed
                                else "No fixed version is listed; review the advisory for mitigations."
                            ),
                        )
                    )
        return findings
