"""Bounded authentication/security log collection and import."""

from __future__ import annotations

import gzip
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers.authlog import parse_line
from ..utils.timeutil import iso, parse_iso

NAME = "logs"
DESCRIPTION = "Authentication events (SSH, sudo, su) from journalctl and auth log files within a time window"
PRIVILEGE_NOTE = (
    "/var/log/auth.log, /var/log/secure and the full journal usually need root or membership of "
    "adm/systemd-journal. Without them this artifact is partial and says nothing about absence of activity."
)
LOG_FILES = ["/var/log/auth.log", "/var/log/secure"]
ROTATED = ["/var/log/auth.log.1", "/var/log/secure-1"]


def plan(ctx: Context) -> list[str]:
    steps = [
        f"run: journalctl --since -{ctx.log_window_hours}h -t sshd -t sudo -t su (bounded to "
        f"{ctx.limit('max_log_lines')} lines)",
        "tail (bounded) of " + ", ".join(LOG_FILES),
    ]
    if ctx.deep:
        steps.append("also: rotated logs " + ", ".join(ROTATED) + " and .gz variants (bounded decompression)")
    if ctx.import_logs:
        steps.append(
            "import user-supplied logs (copied verbatim into evidence/imported/): "
            + ", ".join(str(p) for p in ctx.import_logs)
        )
    return steps


def _read_tail(path: Path, limit: int) -> tuple[bytes, bool]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        if path.suffix == ".gz":
            data = fh.read(limit + 1)
            return data[:limit], len(data) > limit
        fh.seek(0, 2)
        size = fh.tell()
        start = max(0, size - limit)
        fh.seek(start)
        return fh.read(), start > 0


def _ingest(ctx: Context, res: CollectorResult, text: str, source: str, since: Any, stats: dict[str, int]) -> None:
    for line in text.splitlines()[-ctx.limit("max_log_lines") :]:
        if not line.strip():
            continue
        stats["lines"] += 1
        ev = parse_line(line, ctx.now, source)
        if ev is None:
            stats["unrecognized"] += 1
            continue
        if ev["ts"]:
            ts = parse_iso(ev["ts"])
            if ts and ts < since:
                stats["outside_window"] += 1
                continue
        else:
            ev["ts_unknown"] = True
        ev["message"] = ctx.redactor.text(ev["message"])
        if "command" in ev:
            ev["command"] = ctx.redactor.text(ev["command"])
        ev["kind"] = "auth_event"
        res.records.append(ev)


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    since = ctx.now - timedelta(hours=ctx.log_window_hours)
    stats = {"lines": 0, "unrecognized": 0, "outside_window": 0}
    jr = ctx.run(
        [
            "journalctl",
            "--no-pager",
            "--utc",
            "-o",
            "short-iso",
            "--since",
            iso(since).replace("T", " ").rstrip("Z"),
            "-n",
            str(ctx.limit("max_log_lines")),
            "-t",
            "sshd",
            "-t",
            "sudo",
            "-t",
            "su",
            "-t",
            "sshd-session",
        ]
    )
    if jr.error_kind:
        res.error("journalctl", jr.error_kind, jr.error or "journalctl failed")
    elif jr.returncode != 0:
        res.error(
            "journalctl",
            "permission_denied" if "permission" in jr.stderr.lower() else "other",
            jr.stderr.strip()[:200] or f"exit {jr.returncode}",
        )
    else:
        res.sources.append("journalctl")
        _ingest(ctx, res, jr.stdout, "journalctl", since, stats)
        if "No journal files were opened" in jr.stderr or "not seeing messages from other users" in jr.stderr:
            res.notes.append("journal access is limited for this user; messages from other users/system may be missing")
    paths = list(LOG_FILES)
    if ctx.deep:
        paths += ROTATED + [p + ".gz" for p in ("/var/log/auth.log.2", "/var/log/secure-2")]
    for lp in paths:
        p = ctx.path(lp)
        try:
            data, cut = _read_tail(p, ctx.limit("max_log_file_bytes"))
        except FileNotFoundError:
            continue
        except PermissionError:
            res.error(lp, "permission_denied", "log exists but is not readable by this user")
            continue
        except (OSError, EOFError) as exc:
            res.error(lp, "other", f"{type(exc).__name__}: {exc}")
            continue
        res.sources.append(lp)
        if cut:
            res.error(lp, "truncated", f"only the last {ctx.limit('max_log_file_bytes')} bytes were examined")
        _ingest(ctx, res, data.decode("utf-8", errors="replace"), lp, since, stats)
    for imp in ctx.import_logs:
        try:
            data, cut = _read_tail(imp, ctx.limit("max_log_file_bytes"))
        except OSError as exc:
            res.error(str(imp), "not_found" if isinstance(exc, FileNotFoundError) else "other", str(exc))
            continue
        res.sources.append(f"import:{imp}")
        if cut:
            res.error(str(imp), "truncated", "imported log truncated to size limit")
        _ingest(ctx, res, data.decode("utf-8", errors="replace"), f"import:{imp.name}", since, stats)
    res.records.append({"kind": "log_stats", "window_start": iso(since), "window_end": iso(ctx.now), **stats})
    if not res.sources:
        res.notes.append("no log source could be read: authentication telemetry is NOT available for this host")
    else:
        res.notes.append(
            "log coverage is limited to the readable sources and window listed; rotated or "
            "remote logs are not assumed to be complete"
        )
    res.finalize()
    return res


def copy_imports(ctx: Context, dest_dir: Path) -> list[dict[str, Any]]:
    """Copy user-supplied logs verbatim (preserving original evidence). Returns copy records."""
    out = []
    for imp in ctx.import_logs:
        if not imp.is_file():
            continue
        from ..utils.paths import safe_join

        target = safe_join(dest_dir, imp.name)
        shutil.copyfile(imp, target)
        target.chmod(0o600)
        out.append({"source": str(imp), "relpath": f"imported/{imp.name}"})
    return out
