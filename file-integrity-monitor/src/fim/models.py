"""Typed data models shared by every FIM component (also the report output schema)."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

BASELINE_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class EventType(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"  # content (hash or size) differs
    DELETED = "deleted"
    PERMISSION_CHANGED = "permission_changed"  # mode bits differ
    OWNER_CHANGED = "owner_changed"  # uid/gid differ
    TYPE_CHANGED = "type_changed"  # e.g. file -> symlink
    SYMLINK_CHANGED = "symlink_changed"  # link target differs
    METADATA_CHANGED = "metadata_changed"  # only mtime differs; content identical


class IssueKind(StrEnum):
    """Reasons a scan could not fully verify something. Any issue => incomplete scan."""

    ROOT_MISSING = "root_missing"
    UNREADABLE = "unreadable"
    VANISHED = "vanished"  # disappeared between listing and reading
    CHANGED_DURING_HASH = "changed_during_hash"  # race: file mutated while hashing
    REPLACED_DURING_SCAN = "replaced_during_scan"  # inode swapped between lstat and open
    TOO_LARGE = "too_large"  # exceeds max_file_bytes, content NOT hashed
    WALK_ERROR = "walk_error"  # directory could not be listed
    SYMLINK_OUTSIDE_ROOT = "symlink_outside_root"
    SYMLINK_LOOP = "symlink_loop"
    MAX_DEPTH = "max_depth"
    LIMIT_REACHED = "limit_reached"  # max_files hit; scan aborted
    TIMEOUT = "timeout"  # scan_timeout hit; scan aborted
    NOT_HASHED = "not_hashed"  # baseline entry has no hash; content comparison skipped


class FileType(StrEnum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    SPECIAL = "special"  # fifo, socket, device: metadata only, never opened


class FileRecord(BaseModel):
    """What we know about one path at one moment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: FileType
    size: int = Field(ge=0)
    mode: str = Field(pattern=r"^[0-7]{4,6}$", description="Octal permission bits, e.g. 0644")
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mtime_ns: int
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    link_target: str | None = None


class ScanIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: IssueKind
    path: str
    detail: str = ""


class Baseline(BaseModel):
    """On-disk baseline body. ``content_sha256`` covers every other field (see baseline.py)."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["fim-baseline"] = "fim-baseline"
    schema_version: int = BASELINE_SCHEMA_VERSION
    version: int = Field(ge=1)
    created_at: str
    hostname: str
    tool_version: str
    roots: list[str]
    exclude: list[str]
    symlinks: str
    complete: bool
    issues: list[ScanIssue] = Field(default_factory=list)
    prev_sha256: str | None = None
    entries: dict[str, FileRecord]
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FieldChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    old: str | int | None
    new: str | int | None


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    scan_id: str
    event_type: EventType
    path: str
    severity: Severity
    rule: str
    baseline_version: int
    changes: list[FieldChange] = Field(default_factory=list)
    before: FileRecord | None = None
    after: FileRecord | None = None
    risk_flags: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    started_at: str
    finished_at: str
    hostname: str
    tool_version: str
    baseline_version: int
    baseline_sha256: str
    roots: list[str]
    mode: Literal["full", "partial"] = "full"
    complete: bool
    entries_scanned: int
    bytes_hashed: int
    event_count: int
    max_severity: Severity | None
    alert: bool
    counts_by_type: dict[str, int] = Field(default_factory=dict)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)


class Report(BaseModel):
    """The JSON export document. Its JSON schema is published in docs/schemas/."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["fim-report"] = "fim-report"
    schema_version: int = REPORT_SCHEMA_VERSION
    summary: ScanSummary
    events: list[Event]
    issues: list[ScanIssue]
