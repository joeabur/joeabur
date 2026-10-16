"""Severity policy: maps a raw change to a severity, a rule name and risk flags."""

from __future__ import annotations

from fim.config import Config
from fim.models import EventType, FileRecord, Severity
from fim.pathutil import matches_any

SETUID = 0o4000
SETGID = 0o2000
WORLD_WRITABLE = 0o002


def risk_flags(before: FileRecord | None, after: FileRecord | None) -> list[str]:
    """Flags for *newly* risky permission bits on ``after`` (not present on ``before``)."""
    if after is None:
        return []
    new = int(after.mode, 8)
    old = int(before.mode, 8) if before is not None else 0
    flags = []
    if new & SETUID and not old & SETUID:
        flags.append("setuid_set")
    if new & SETGID and not old & SETGID:
        flags.append("setgid_set")
    if new & WORLD_WRITABLE and not old & WORLD_WRITABLE and after.type.value != "symlink":
        flags.append("world_writable")
    return flags


def evaluate(cfg: Config, event_type: EventType, path: str, flags: list[str]) -> tuple[Severity, str]:
    """Return ``(severity, rule_name)``. First matching ``[[policy.rules]]`` entry wins; risk flags
    can only raise the result (setuid/setgid => critical, world-writable => at least high)."""
    severity = cfg.severity_for(event_type)
    rule = f"default:{event_type.value}"
    for r in cfg.policy.rules:
        if event_type in r.events and matches_any(path, r.paths):
            severity, rule = r.severity, r.name
            break
    if ("setuid_set" in flags or "setgid_set" in flags) and severity.rank < Severity.CRITICAL.rank:
        severity, rule = Severity.CRITICAL, f"{rule}+risk"
    elif "world_writable" in flags and severity.rank < Severity.HIGH.rank:
        severity, rule = Severity.HIGH, f"{rule}+risk"
    return severity, rule


def is_alert(cfg: Config, severity: Severity) -> bool:
    return severity.rank >= cfg.policy.alert_threshold.rank
