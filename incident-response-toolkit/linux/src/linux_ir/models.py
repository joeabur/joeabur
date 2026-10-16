"""Core data models shared by collectors, detections and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
ERROR_KINDS = (
    "not_found",
    "permission_denied",
    "timeout",
    "parse_error",
    "unavailable",
    "truncated",
    "other",
)
STATUSES = ("ok", "partial", "skipped", "failed", "unavailable")
CLASSIFICATIONS = ("heuristic", "ioc_match")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_VERIFY_FAILED = 3
EXIT_FINDINGS = 10


@dataclass
class CollectionError:
    collector: str
    source: str
    kind: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class CollectorResult:
    name: str
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    status: str = "ok"

    def error(self, source: str, kind: str, message: str) -> None:
        self.errors.append(CollectionError(self.name, source, kind, message))

    def finalize(self) -> None:
        if self.status in ("skipped", "unavailable"):
            return
        if self.errors and not self.records:
            self.status = "failed"
        elif self.errors:
            self.status = "partial"
        else:
            self.status = "ok"


@dataclass
class Finding:
    rule_id: str
    rule_version: int
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    classification: str
    artifact: str
    evidence_ref: str
    why: str
    evidence: dict[str, Any] = field(default_factory=dict)
    false_positives: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
