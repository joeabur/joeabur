"""Trivy adapter: dependency, IaC/misconfiguration, optional secret and container-image scans."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..errors import ScannerError
from ..paths import find_text_directives, relative_to_root
from ..redaction import sanitize, sanitize_evidence
from ..schemas import Dependency, Finding, FindingKind, Severity, make_fingerprint
from .base import Occurrences, ScanContext, ScannerAdapter, as_dict, as_int, as_list, as_str


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    executable = "trivy"
    version_args = ("--version",)
    supported = ">=0.50,<1"
    tested = "0.76.0"
    ok_exit_codes = frozenset({0})
    # Trivy honours inline `#trivy:ignore:<id>` / `#tfsec:ignore:<id>` comments in IaC files and has no
    # switch to turn that off, so a pull request could hide its own misconfigurations with them.
    _INLINE_IGNORE = re.compile(r"(?:trivy|tfsec):ignore", re.IGNORECASE)
    _IAC_SUFFIXES = (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".template", ".tpl")

    def preflight(self, ctx: ScanContext) -> list[str]:
        if ctx.image or "misconfig" not in ctx.config.scanners.trivy.scanners:
            return []
        hits = find_text_directives(
            ctx.target,
            self._INLINE_IGNORE,
            suffixes=self._IAC_SUFFIXES,
            names=("dockerfile", "containerfile"),
        )
        if not hits:
            return []
        shown = ", ".join(hits[:5]) + (f" (+{len(hits) - 5} more)" if len(hits) > 5 else "")
        if not ctx.allow_repo_ignore_files:
            raise ScannerError(
                "the scanned repository contains inline `trivy:ignore`/`tfsec:ignore` directives "
                f"({shown}), which Trivy honours and which could hide misconfigurations. Review them, "
                "then re-run with --allow-repo-ignore-files to accept them (a warning is recorded)."
            )
        return [f"Trivy inline ignore directives are being honoured in: {shown}"]

    def build_argv(self, ctx: ScanContext, exe: str, report: Path) -> list[str]:
        settings = ctx.config.scanners.trivy
        mode = "image" if ctx.image else "fs"
        ignore = ctx.workdir / "trivy-empty.ignore"
        ignore.write_text("", encoding="utf-8")
        scanners = settings.scanners if mode == "fs" else [s for s in settings.scanners if s != "misconfig"]
        argv = [
            exe,
            mode,
            "--format",
            "json",
            "--output",
            str(report),
            "--quiet",
            "--no-progress",
            "--skip-version-check",
            "--disable-telemetry",
            "--scanners",
            ",".join(scanners),
            "--ignorefile",
            str(ignore),
            "--exit-code",
            "0",
        ]
        if ctx.offline:
            argv += [
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--skip-check-update",
            ]
        argv.append(ctx.image if ctx.image else str(ctx.target))
        return argv

    def parse(self, data: Any, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        occ = Occurrences()
        for result in as_list(as_dict(data).get("Results")):
            result = as_dict(result)
            target = as_str(result.get("Target")) or ""
            rtype = as_str(result.get("Type"))
            if ctx.image:
                file: str | None = None
                artifact: str | None = sanitize(target, limit=200)
            else:
                file = relative_to_root(target, ctx.target)
                artifact = None
            where = file or artifact or ""
            for vuln in as_list(result.get("Vulnerabilities")):
                findings.append(self._vulnerability(as_dict(vuln), file, artifact, where, rtype, ctx))
            for mis in as_list(result.get("Misconfigurations")):
                row = as_dict(mis)
                if (as_str(row.get("Status")) or "FAIL").upper() != "FAIL":
                    continue
                findings.append(self._misconfig(row, file, artifact, where, ctx, occ))
            for sec in as_list(result.get("Secrets")):
                findings.append(self._secret(as_dict(sec), file, artifact, where, ctx, occ))
        return findings

    def _vulnerability(
        self,
        v: dict[str, Any],
        file: str | None,
        artifact: str | None,
        where: str,
        rtype: str | None,
        ctx: ScanContext,
    ) -> Finding:
        vid = as_str(v.get("VulnerabilityID")) or "unknown"
        name = as_str(v.get("PkgName")) or "unknown"
        installed = as_str(v.get("InstalledVersion"))
        fixed = as_str(v.get("FixedVersion"))
        raw_sev = as_str(v.get("Severity"))
        cves = sorted(
            {
                i
                for i in [vid, *[x for x in as_list(v.get("VendorIDs")) if isinstance(x, str)]]
                if i.startswith("CVE-")
            }
        )
        refs = [as_str(v.get("PrimaryURL"))] + [r for r in as_list(v.get("References")) if isinstance(r, str)]
        references = [sanitize(r, limit=300) for r in refs if r][:5]
        title = as_str(v.get("Title")) or (as_str(v.get("Description")) or vid).split("\n")[0]
        if fixed:
            fix = (
                f"Upgrade {sanitize(name, limit=100)} to {sanitize(fixed, limit=100)} "
                f"(installed: {sanitize(installed or '?', limit=60)})."
            )
        else:
            fix = "No fixed version is available yet; monitor the advisory or apply compensating controls."
        return Finding(
            fingerprint=make_fingerprint(self.name, vid, where, f"{name}@{installed}"),
            scanner=self.name,
            kind=FindingKind.DEPENDENCY,
            rule_id=sanitize(vid, limit=100),
            title=sanitize(title, limit=300),
            severity=Severity.parse(raw_sev, ctx.unknown_severity),
            original_severity=sanitize(raw_sev, limit=20) if raw_sev else None,
            file=file,
            artifact=artifact,
            dependency=Dependency(
                name=sanitize(name, limit=200),
                installed_version=sanitize(installed, limit=100) if installed else None,
                fixed_version=sanitize(fixed, limit=100) if fixed else None,
                ecosystem=sanitize(rtype, limit=50) if rtype else None,
            ),
            cve=cves,
            cwe=sorted({str(c) for c in as_list(v.get("CweIDs"))}),
            references=references,
            remediation=fix,
        )

    def _misconfig(
        self,
        m: dict[str, Any],
        file: str | None,
        artifact: str | None,
        where: str,
        ctx: ScanContext,
        occ: Occurrences,
    ) -> Finding:
        rule = as_str(m.get("AVDID")) or as_str(m.get("ID")) or "unknown"
        raw_sev = as_str(m.get("Severity"))
        cause = as_dict(m.get("CauseMetadata")) if isinstance(m.get("CauseMetadata"), dict) else {}
        line = as_int(cause.get("StartLine"))
        code = as_dict(cause.get("Code")) if isinstance(cause.get("Code"), dict) else {}
        lines = [as_dict(x) for x in as_list(code.get("Lines"))]
        cause_text = " ".join(as_str(x.get("Content")) or "" for x in lines if x.get("IsCause"))
        evidence = sanitize_evidence(cause_text) if cause_text.strip() else None
        title = as_str(m.get("Title")) or as_str(m.get("Message")) or rule
        basis = evidence or as_str(m.get("Message")) or "misconfig"
        return Finding(
            fingerprint=make_fingerprint(self.name, rule, where, f"{basis}#{occ.next(rule, where, basis)}"),
            scanner=self.name,
            kind=FindingKind.MISCONFIGURATION,
            rule_id=sanitize(rule, limit=100),
            title=sanitize(title, limit=300),
            severity=Severity.parse(raw_sev, ctx.unknown_severity),
            original_severity=sanitize(raw_sev, limit=20) if raw_sev else None,
            file=file,
            artifact=artifact,
            line=line,
            end_line=as_int(cause.get("EndLine")),
            references=[
                sanitize(r, limit=300) for r in as_list(m.get("References"))[:5] if isinstance(r, str)
            ],
            evidence=evidence,
            remediation=sanitize(
                as_str(m.get("Resolution")) or as_str(m.get("Message")) or "See the rule documentation.",
                limit=400,
            ),
        )

    def _secret(
        self,
        s: dict[str, Any],
        file: str | None,
        artifact: str | None,
        where: str,
        ctx: ScanContext,
        occ: Occurrences,
    ) -> Finding:
        rule = as_str(s.get("RuleID")) or "unknown"
        raw_sev = as_str(s.get("Severity"))
        line = as_int(s.get("StartLine"))
        match = as_str(s.get("Match"))
        evidence = sanitize_evidence(match) if match else None
        return Finding(
            fingerprint=make_fingerprint(
                self.name,
                rule,
                where,
                f"{evidence or 'secret'}#{occ.next(rule, where, evidence or '')}",
            ),
            scanner=self.name,
            kind=FindingKind.SECRET,
            rule_id=sanitize(rule, limit=100),
            title=sanitize(as_str(s.get("Title")) or rule, limit=300),
            severity=Severity.parse(raw_sev, Severity.HIGH),
            original_severity=sanitize(raw_sev, limit=20) if raw_sev else None,
            file=file,
            artifact=artifact,
            line=line,
            end_line=as_int(s.get("EndLine")),
            cwe=["CWE-798"],
            evidence=evidence,
            remediation="Revoke and rotate this credential and remove it from the repository.",
        )
