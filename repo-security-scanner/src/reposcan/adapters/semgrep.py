"""Semgrep adapter (SAST). Verified against Semgrep 1.181.0 JSON output."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from ..config import data_path
from ..errors import ScannerError
from ..paths import read_source_line, relative_to_root
from ..redaction import sanitize, sanitize_evidence
from ..schemas import Finding, FindingKind, Severity, make_fingerprint
from .base import Occurrences, ScanContext, ScannerAdapter, as_dict, as_int, as_list, as_str

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_REMOTE_RE = re.compile(r"^(?:p/|r/|auto$|https?://|semgrep\.dev|registry)", re.IGNORECASE)
_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    executable = "semgrep"
    supported = ">=1.70,<2"
    tested = "1.181.0"
    ok_exit_codes = frozenset({0})
    # `semgrep --version` otherwise blocks for ~100s when semgrep.dev is unreachable.
    extra_env = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}  # noqa: RUF012

    def _rule_files(self, ctx: ScanContext) -> list[Path]:
        settings = ctx.config.scanners.semgrep
        if not settings.rules:
            return [data_path("semgrep-rules.yml")]
        files: list[Path] = []
        for entry in settings.rules:
            if _REMOTE_RE.match(entry) and not settings.allow_remote_rules:
                raise ScannerError(
                    f"semgrep rule source {sanitize(entry, limit=80)!r} is a remote registry "
                    "reference; fetching it contacts semgrep.dev. Use a local rules file or set "
                    "scanners.semgrep.allow_remote_rules = true."
                )
            if _REMOTE_RE.match(entry):
                continue
            base = ctx.config.base_dir or Path.cwd()
            path = (base / entry).resolve()
            if not path.is_file():
                raise ScannerError(f"semgrep rules file not found: {sanitize(entry, limit=120)}")
            files.append(path)
        return files

    def preflight(self, ctx: ScanContext) -> list[str]:
        self._rule_files(ctx)
        return []

    def build_argv(self, ctx: ScanContext, exe: str, report: Path) -> list[str]:
        settings = ctx.config.scanners.semgrep
        argv = [exe, "scan"]
        # Copy local rule files into the private workdir and run from there: avoids
        # path-derived rule-id prefixes and rules changing between check and use.
        for index, src in enumerate(self._rule_files(ctx)):
            dest = ctx.workdir / f"rules-{index}.yml"
            shutil.copyfile(src, dest)
            argv += ["--config", dest.name]
        if settings.allow_remote_rules:
            for entry in settings.rules:
                if _REMOTE_RE.match(entry):
                    argv += ["--config", entry]
        argv += [
            "--json-output",
            str(report),
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            "--disable-nosem",
            "--timeout",
            "30",
            "--max-target-bytes",
            "2000000",
        ]
        argv += ["--metrics", "off"]
        argv.append(str(ctx.target))
        return argv

    def parse(self, data: Any, ctx: ScanContext) -> list[Finding]:
        root = as_dict(data)
        errors = [as_dict(e) for e in as_list(root.get("errors"))]
        fatal = [e for e in errors if e.get("level") == "error" and e.get("type") != "Syntax error"]
        if fatal:
            kinds = sorted({sanitize(str(e.get("type", "error")), limit=40) for e in fatal})
            raise ScannerError("semgrep reported errors while scanning: " + ", ".join(kinds))
        findings: list[Finding] = []
        occurrences = Occurrences()
        rows = sorted(
            (as_dict(i) for i in as_list(root.get("results"))),
            key=lambda r: (
                str(r.get("path")),
                as_dict(r.get("start")).get("offset") or 0,
                str(r.get("check_id")),
            ),
        )
        for row in rows:
            extra = as_dict(row.get("extra"))
            meta: dict[str, Any] = as_dict(extra.get("metadata") or {})
            rule = as_str(row.get("check_id")) or "unknown-rule"
            file = relative_to_root(as_str(row.get("path")) or "", ctx.target)
            start = as_dict(row.get("start"))
            end = as_dict(row.get("end"))
            line = as_int(start.get("line"))
            raw_sev = as_str(extra.get("severity"))
            severity = _SEVERITY.get((raw_sev or "").upper(), ctx.unknown_severity)
            cwe_raw = meta.get("cwe")
            cwe_items = cwe_raw if isinstance(cwe_raw, list) else [cwe_raw] if cwe_raw else []
            cwes = sorted({m.upper() for c in cwe_items for m in _CWE_RE.findall(str(c))})
            refs = meta.get("references")
            references = [sanitize(str(r), limit=300) for r in refs[:5]] if isinstance(refs, list) else []
            snippet = None
            raw_lines = as_str(extra.get("lines"))
            if raw_lines and raw_lines != "requires login":
                snippet = raw_lines
            elif file and line:
                snippet = read_source_line(ctx.target, file, line)
            evidence = sanitize_evidence(snippet) if snippet else None
            message = sanitize(as_str(extra.get("message")) or rule, limit=400)
            fix = as_str(extra.get("fix")) or as_str(meta.get("fix")) or message
            findings.append(
                Finding(
                    fingerprint=make_fingerprint(
                        self.name,
                        rule,
                        file or "",
                        f"{evidence or f'line:{line}'}#{occurrences.next(rule, file or '', evidence or '')}",
                    ),
                    scanner=self.name,
                    kind=FindingKind.SAST,
                    rule_id=sanitize(rule, limit=200),
                    title=message,
                    severity=severity,
                    original_severity=sanitize(raw_sev, limit=20) if raw_sev else None,
                    file=file,
                    line=line,
                    end_line=as_int(end.get("line")),
                    cwe=cwes,
                    references=references,
                    evidence=evidence,
                    remediation=sanitize(fix, limit=400),
                )
            )
        return findings
