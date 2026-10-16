"""UTC time helpers. All timestamps emitted by the toolkit are UTC ISO 8601."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_MONTHS = {
    m: i + 1 for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])
}
_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")
_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?")


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow_iso() -> str:
    return iso(utcnow())


def epoch_to_iso(value: float) -> str:
    return iso(datetime.fromtimestamp(value, UTC))


def parse_iso(text: str) -> datetime | None:
    """Parse an ISO-8601-like timestamp; naive values are assumed to be UTC."""
    m = _ISO_RE.match(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=UTC)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        from datetime import timedelta

        dt = dt - sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return dt


def parse_log_timestamp(line: str, ref: datetime, assume_utc: bool = True) -> datetime | None:
    """Parse the leading timestamp of a log line (ISO or classic syslog).

    Classic syslog omits the year and zone: the year is inferred from ``ref`` and the
    zone is assumed to be UTC unless the caller knows better (documented limitation).
    """
    dt = parse_iso(line)
    if dt:
        return dt
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    mon, day, h, mi, s = m.groups()
    if mon not in _MONTHS:
        return None
    try:
        cand = datetime(ref.year, _MONTHS[mon], int(day), int(h), int(mi), int(s), tzinfo=UTC)
    except ValueError:
        return None
    from datetime import timedelta

    if cand > ref + timedelta(days=1):
        try:
            cand = cand.replace(year=ref.year - 1)
        except ValueError:
            return None
    return cand
