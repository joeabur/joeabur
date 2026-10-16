from __future__ import annotations

from datetime import UTC, datetime

from reposcan.schemas import (
    Dependency,
    Finding,
    FindingKind,
    PolicyResult,
    ScanMetadata,
    ScannerRun,
    ScanResult,
    ScanScope,
    Severity,
    make_fingerprint,
    summarize,
)

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def finding(
    rule: str = "r1",
    severity: Severity = Severity.HIGH,
    *,
    scanner: str = "semgrep",
    kind: FindingKind = FindingKind.SAST,
    file: str | None = "app/a.py",
    line: int | None = 3,
    title: str = "Something is wrong",
    evidence: str | None = "x = 1",
    **extra: object,
) -> Finding:
    return Finding(
        fingerprint=make_fingerprint(scanner, rule, file or "", f"{evidence}#{line}"),
        scanner=scanner,
        kind=kind,
        rule_id=rule,
        title=title,
        severity=severity,
        file=file,
        line=line,
        evidence=evidence,
        remediation="Fix it.",
        **extra,  # type: ignore[arg-type]
    )


def dep_finding(**kw: object) -> Finding:
    return finding(
        "CVE-2024-0001",
        Severity.CRITICAL,
        scanner="trivy",
        kind=FindingKind.DEPENDENCY,
        file="requirements.txt",
        line=None,
        evidence=None,
        dependency=Dependency(name="lib", installed_version="1.0", fixed_version="1.1", ecosystem="pip"),
        cve=["CVE-2024-0001"],
        **kw,
    )


def result(
    findings: list[Finding], *, exit_code: int = 1, runs: list[ScannerRun] | None = None
) -> ScanResult:
    runs = runs or [
        ScannerRun(
            name=n,
            status="ok",
            version="1.0.0",
            supported_versions=">=1,<2",
            exit_code=0,
            finding_count=sum(1 for f in findings if f.scanner == n),
        )
        for n in sorted({f.scanner for f in findings} or {"semgrep"})
    ]
    return ScanResult(
        metadata=ScanMetadata(
            tool_version="0.1.0",
            started_at=FIXED,
            finished_at=FIXED,
            python_version="3.13.0",
            platform="Linux x86_64",
            offline=False,
            config_sources=["built-in defaults"],
        ),
        scope=ScanScope(
            target="repo",
            is_git_repository=False,
            file_count=3,
            total_bytes=100,
            symlinks_skipped=0,
            top_extensions={".py": 3},
        ),
        scanners=runs,
        findings=sorted(findings, key=lambda f: f.sort_key()),
        summary=summarize(findings),
        policy=PolicyResult(
            passed=exit_code == 0,
            fail_on="high",
            fail_on_baseline=False,
            violating_findings=len(findings),
            reasons=["demo"],
        ),
        warnings=[],
        exit_code=exit_code,
        exit_reason="demo",
    )
