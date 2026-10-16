"""Gitleaks adapter (secret detection). Verified against Gitleaks 8.30.1 `dir`/`git` output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import data_path
from ..errors import ScannerError
from ..paths import relative_to_root
from ..redaction import sanitize, sanitize_evidence
from ..schemas import Finding, FindingKind, Severity, make_fingerprint
from .base import Occurrences, ScanContext, ScannerAdapter, as_dict, as_int, as_list, as_str

LEAK_EXIT_CODE = 10  # distinct from 1, which Gitleaks uses for its own errors
ALL_CWE = "CWE-798"


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    executable = "gitleaks"
    version_args = ("version",)
    supported = ">=8.19,<9"
    tested = "8.30.1"
    ok_exit_codes = frozenset({0, LEAK_EXIT_CODE})

    def preflight(self, ctx: ScanContext) -> list[str]:
        base = ctx.target if ctx.target.is_dir() else ctx.target.parent
        if (base / ".gitleaksignore").exists() and not ctx.allow_repo_ignore_files:
            raise ScannerError(
                "the scanned repository contains a .gitleaksignore file, which Gitleaks always "
                "honours and which could hide findings. Review it, then re-run with "
                "--allow-repo-ignore-files to accept it (a warning is recorded)."
            )
        return []

    def _config_path(self, ctx: ScanContext) -> Path:
        configured = ctx.config.scanners.gitleaks.config
        if configured and ctx.config.base_dir is not None:
            return (ctx.config.base_dir / configured).resolve()
        return data_path("gitleaks.toml")

    def build_argv(self, ctx: ScanContext, exe: str, report: Path) -> list[str]:
        empty_dir = ctx.workdir / "empty-ignore"
        empty_dir.mkdir(exist_ok=True)
        mode = "git" if ctx.history else "dir"
        return [
            exe,
            mode,
            "--no-banner",
            "--log-level",
            "error",
            "--config",
            str(self._config_path(ctx)),
            "--redact=100",
            "--ignore-gitleaks-allow",
            "--exit-code",
            str(LEAK_EXIT_CODE),
            "--gitleaks-ignore-path",
            str(empty_dir),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            str(ctx.target),
        ]

    def parse(self, data: Any, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        occurrences = Occurrences()
        rows = sorted(
            (as_dict(i) for i in as_list(data)),
            key=lambda r: (str(r.get("File")), r.get("StartLine") or 0, str(r.get("RuleID"))),
        )
        for row in rows:
            rule = as_str(row.get("RuleID")) or "unknown-rule"
            file = relative_to_root(as_str(row.get("File")) or "", ctx.target)
            line = as_int(row.get("StartLine"))
            match = as_str(row.get("Match")) or ""
            evidence = sanitize_evidence(match) if match else None
            commit = as_str(row.get("Commit"))
            title = sanitize(as_str(row.get("Description")) or rule, limit=200)
            discriminator = (
                f"{evidence or 'secret'}#{occurrences.next(rule, file or '', evidence or '', commit or '')}"
            )
            if commit:
                discriminator += f"|{commit[:12]}"
            remediation = (
                "Revoke and rotate this credential, remove it from the repository history, "
                "and load it from a secret manager or CI secret store instead."
            )
            findings.append(
                Finding(
                    fingerprint=make_fingerprint(self.name, rule, file or "", discriminator),
                    scanner=self.name,
                    kind=FindingKind.SECRET,
                    rule_id=sanitize(rule, limit=120),
                    title=title,
                    severity=Severity.HIGH,
                    original_severity=None,
                    file=file,
                    line=line,
                    end_line=as_int(row.get("EndLine")),
                    cwe=[ALL_CWE],
                    evidence=evidence,
                    remediation=remediation
                    + (f" Found in commit {sanitize(commit[:12])}." if commit else ""),
                )
            )
        return findings
