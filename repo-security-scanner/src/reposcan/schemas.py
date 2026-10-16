"""Unified data model: findings, scanner runs, policy outcome and the full scan result."""

from __future__ import annotations

import hashlib
from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def parse(cls, raw: str | None, default: Severity) -> Severity:
        """Map scanner-specific labels to a Severity; unknown labels use ``default``."""
        if not raw:
            return default
        return _ALIASES.get(raw.strip().lower(), default)


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_ALIASES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
}


class FindingKind(StrEnum):
    SECRET = "secret"  # noqa: S105 - enum label, not a credential
    SAST = "sast"
    DEPENDENCY = "dependency"
    MISCONFIGURATION = "misconfiguration"


class FindingStatus(StrEnum):
    NEW = "new"
    BASELINE = "baseline"
    SUPPRESSED = "suppressed"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Dependency(Strict):
    name: str
    installed_version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None


class Finding(Strict):
    fingerprint: str
    scanner: str
    kind: FindingKind
    rule_id: str
    title: str
    severity: Severity
    original_severity: str | None = None
    file: str | None = None
    artifact: str | None = None  # e.g. a container image, when there is no file path
    line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    dependency: Dependency | None = None
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    evidence: str | None = None
    remediation: str | None = None
    status: FindingStatus = FindingStatus.NEW
    status_detail: str | None = None
    suppression_expired: bool = False

    def sort_key(self) -> tuple[int, str, str, int, str, str]:
        return (
            -self.severity.rank,
            self.file or "",
            self.scanner,
            self.line or 0,
            self.rule_id,
            self.fingerprint,
        )


def make_fingerprint(scanner: str, rule_id: str, location: str, discriminator: str) -> str:
    """Stable, line-independent identity for a finding (32 hex chars)."""
    payload = "\x1f".join((scanner, rule_id, location, discriminator))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:32]


ScannerStatus = Literal[
    "ok",
    "not_found",
    "version_mismatch",
    "failed",
    "timeout",
    "cancelled",
    "malformed_output",
    "skipped",
]


class ScannerRun(Strict):
    name: str
    status: ScannerStatus
    version: str | None = None
    supported_versions: str | None = None
    tested_version: str | None = None
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    duration_seconds: float = 0.0
    finding_count: int = 0
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.status == "ok"


class ScanScope(Strict):
    target: str
    is_git_repository: bool
    file_count: int
    total_bytes: int
    symlinks_skipped: int
    top_extensions: dict[str, int]
    truncated: bool = False
    history_scanned: bool = False
    trivy_image: str | None = None


class ScanMetadata(Strict):
    tool: str = "reposcan"
    tool_version: str
    schema_version: str = SCHEMA_VERSION
    started_at: datetime
    finished_at: datetime
    python_version: str
    platform: str
    offline: bool
    config_sources: list[str] = Field(default_factory=list)
    baseline_file: str | None = None


class PolicyResult(Strict):
    passed: bool
    fail_on: str
    fail_on_baseline: bool
    violating_findings: int
    reasons: list[str] = Field(default_factory=list)


class Summary(Strict):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_scanner: dict[str, int]
    by_kind: dict[str, int]
    new_by_severity: dict[str, int]


class ScanResult(Strict):
    metadata: ScanMetadata
    scope: ScanScope
    scanners: list[ScannerRun]
    findings: list[Finding]
    summary: Summary
    policy: PolicyResult
    warnings: list[str] = Field(default_factory=list)
    exit_code: int
    exit_reason: str

    @property
    def new_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status is FindingStatus.NEW]


def summarize(findings: list[Finding]) -> Summary:
    def count(keys: list[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for key in keys:
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items()))

    ordered = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]
    sev = dict.fromkeys(ordered, 0)
    new_sev = dict.fromkeys(ordered, 0)
    for f in findings:
        sev[f.severity.value] += 1
        if f.status is FindingStatus.NEW:
            new_sev[f.severity.value] += 1
    return Summary(
        total=len(findings),
        by_severity=sev,
        by_status={s.value: sum(1 for f in findings if f.status is s) for s in FindingStatus},
        by_scanner=count([f.scanner for f in findings]),
        by_kind=count([f.kind.value for f in findings]),
        new_by_severity=new_sev,
    )


class AcceptedEntry(Strict):
    """A baseline or suppression record: always owned, justified and reviewable."""

    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=1000)
    expires: date | None = None
