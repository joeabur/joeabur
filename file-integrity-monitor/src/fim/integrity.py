"""Integrity verification: compare a baseline with a fresh scan and produce events."""

from __future__ import annotations

import socket
import uuid
from collections import Counter
from datetime import UTC, datetime

from fim import __version__
from fim.config import Config
from fim.models import (
    Baseline,
    Event,
    EventType,
    FieldChange,
    FileRecord,
    FileType,
    IssueKind,
    Report,
    ScanIssue,
    ScanSummary,
    Severity,
)
from fim.pathutil import is_within, matches_any
from fim.rules import evaluate, is_alert, risk_flags
from fim.scanner import ScanResult

# Issues that make "absent from the scan" untrustworthy for a path or everything below it.
_UNVERIFIABLE = {
    IssueKind.UNREADABLE,
    IssueKind.WALK_ERROR,
    IssueKind.MAX_DEPTH,
    IssueKind.REPLACED_DURING_SCAN,
}


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def _has_content(rec: FileRecord) -> bool:
    return rec.type in (FileType.FILE, FileType.SYMLINK) and rec.sha256 is not None


def diff_record(path: str, old: FileRecord, new: FileRecord) -> list[tuple[EventType, list[FieldChange]]]:
    """Return the (event type, field changes) pairs describing how ``old`` became ``new``."""
    if old.type != new.type:
        return [(EventType.TYPE_CHANGED, [FieldChange(field="type", old=old.type, new=new.type)])]
    out: list[tuple[EventType, list[FieldChange]]] = []
    content_changed = False
    if old.type is FileType.SYMLINK and old.link_target != new.link_target:
        out.append(
            (
                EventType.SYMLINK_CHANGED,
                [FieldChange(field="link_target", old=old.link_target, new=new.link_target)],
            )
        )
    if old.type in (FileType.FILE, FileType.SYMLINK):
        changes: list[FieldChange] = []
        if old.type is FileType.FILE and old.size != new.size:
            changes.append(FieldChange(field="size", old=old.size, new=new.size))
        if _has_content(old) and _has_content(new) and old.sha256 != new.sha256:
            changes.append(FieldChange(field="sha256", old=old.sha256, new=new.sha256))
        if changes:
            content_changed = True
            out.append((EventType.MODIFIED, changes))
    if old.mode != new.mode:
        out.append((EventType.PERMISSION_CHANGED, [FieldChange(field="mode", old=old.mode, new=new.mode)]))
    owner = [
        FieldChange(field=f, old=getattr(old, f), new=getattr(new, f))
        for f in ("uid", "gid")
        if getattr(old, f) != getattr(new, f)
    ]
    if owner:
        out.append((EventType.OWNER_CHANGED, owner))
    if old.xattrs is not None and new.xattrs is not None and old.xattrs != new.xattrs:
        names = sorted(set(old.xattrs) | set(new.xattrs))
        out.append(
            (
                EventType.XATTR_CHANGED,
                [
                    FieldChange(field=f"xattr:{n}", old=old.xattrs.get(n), new=new.xattrs.get(n))
                    for n in names
                    if old.xattrs.get(n) != new.xattrs.get(n)
                ],
            )
        )
    if (
        not content_changed
        and old.type in (FileType.FILE, FileType.SYMLINK)
        and old.mtime_ns != new.mtime_ns
        and old.link_target == new.link_target
    ):
        out.append(
            (
                EventType.METADATA_CHANGED,
                [FieldChange(field="mtime_ns", old=old.mtime_ns, new=new.mtime_ns)],
            )
        )
    return out


def compare(
    cfg: Config,
    baseline: Baseline,
    scan: ScanResult,
    *,
    scan_id: str,
    scope: list[str] | None = None,
    detect_deletions: bool = True,
) -> list[Event]:
    """Compare ``scan`` against ``baseline``.

    ``scope`` limits deletion detection to those paths (full scan: the configured roots). An
    aborted scan never reports deletions: absence is meaningless when the walk did not finish.
    """
    scope = scope if scope is not None else list(cfg.scan.roots)
    ts = now_iso()
    events: list[Event] = []

    def emit(
        etype: EventType,
        path: str,
        before: FileRecord | None,
        after: FileRecord | None,
        changes: list[FieldChange],
    ) -> None:
        flags = risk_flags(before, after) if etype is not EventType.DELETED else []
        sev, rule = evaluate(cfg, etype, path, flags)
        events.append(
            Event(
                timestamp=ts,
                scan_id=scan_id,
                event_type=etype,
                path=path,
                severity=sev,
                rule=rule,
                baseline_version=baseline.version,
                changes=changes,
                before=before,
                after=after,
                risk_flags=flags,
            )
        )

    for path in sorted(scan.entries):
        new = scan.entries[path]
        old = baseline.entries.get(path)
        if old is None:
            emit(EventType.ADDED, path, None, new, [])
            continue
        for etype, changes in diff_record(path, old, new):
            emit(etype, path, old, new, changes)

    if detect_deletions and not scan.aborted:
        blocked = [i.path for i in scan.issues if i.kind in _UNVERIFIABLE]
        for path in sorted(baseline.entries):
            if path in scan.entries or not any(is_within(path, s) for s in scope):
                continue
            is_dir = baseline.entries[path].type is FileType.DIR
            if cfg.scan.exclude and matches_any(path, cfg.scan.exclude, is_dir=is_dir):
                continue  # exclusions changed since baseline: not a deletion
            if any(is_within(path, b) for b in blocked):
                continue  # could not look there: reported as an issue, not as "deleted"
            emit(EventType.DELETED, path, baseline.entries[path], None, [])

    sev_order = {s: s.rank for s in Severity}
    events.sort(key=lambda e: (-sev_order[e.severity], e.path, e.event_type.value))
    return events


def build_report(
    cfg: Config,
    baseline: Baseline,
    scan: ScanResult,
    events: list[Event],
    *,
    scan_id: str,
    mode: str = "full",
) -> Report:
    by_type = Counter(e.event_type.value for e in events)
    by_sev = Counter(e.severity.value for e in events)
    max_sev = max((e.severity for e in events), key=lambda s: s.rank, default=None)
    issues: list[ScanIssue] = list(scan.issues)
    summary = ScanSummary(
        scan_id=scan_id,
        started_at=datetime.fromtimestamp(scan.started_at, UTC).isoformat(timespec="seconds"),
        finished_at=datetime.fromtimestamp(scan.finished_at, UTC).isoformat(timespec="seconds"),
        hostname=socket.gethostname(),
        tool_version=__version__,
        baseline_version=baseline.version,
        baseline_sha256=baseline.content_sha256,
        roots=scan.roots,
        mode="full" if mode == "full" else "partial",
        complete=scan.complete,
        entries_scanned=scan.entries_scanned,
        bytes_hashed=scan.bytes_hashed,
        event_count=len(events),
        max_severity=max_sev,
        alert=any(is_alert(cfg, e.severity) for e in events),
        counts_by_type=dict(sorted(by_type.items())),
        counts_by_severity=dict(sorted(by_sev.items())),
    )
    return Report(summary=summary, events=events, issues=issues)
