"""Bounded unified-log collection using the native ``log`` utility, plus exported ndjson and .logarchive input."""

from __future__ import annotations

import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers.unified_log import parse_event
from ..utils.timeutil import iso, parse_iso

NAME = "logs"
DESCRIPTION = (
    "Unified-log authentication events (sshd, sudo, su, login) via `log show` with a predicate and time window"
)
PRIVILEGE_NOTE = (
    "`log show` for system processes normally requires an administrator; unprivileged runs may return only the user's "
    "own events or an error. macOS can also redact (<private>), expire or omit events: coverage is never complete."
)


def _argv(ctx: Context, extra: list[str]) -> list[str]:
    return ["log", "show", "--style", "ndjson", "--predicate", ctx.config["logs"]["predicate"], *extra]


def plan(ctx: Context) -> list[str]:
    steps = [
        f"run: log show --style ndjson --last {ctx.log_window_hours}h --predicate <logs.predicate>  "
        f"(output capped at {ctx.limit('max_command_output_bytes')} bytes)",
        "predicate: " + ctx.config["logs"]["predicate"],
        "never changes logging configuration or retention",
    ]
    for a in ctx.import_archives:
        steps.append(f"run: log show --archive {a} (supplied .logarchive, read-only)")
    for f in ctx.import_logs:
        steps.append(f"import exported ndjson {f} (verbatim copy kept in imported/)")
    return steps


def _ingest(ctx: Context, res: CollectorResult, text: str, source: str, since: Any, stats: dict[str, int]) -> None:
    for line in text.splitlines()[-ctx.limit("max_log_lines") :]:
        if not line.strip():
            continue
        stats["lines"] += 1
        ev, status = parse_event(line, source)
        if status == "malformed":
            stats["malformed"] += 1
            continue
        if ev is None:
            stats["ignored"] += 1
            continue
        if ev["ts"]:
            ts = parse_iso(ev["ts"])
            if ts and ts < since:
                stats["outside_window"] += 1
                continue
        else:
            ev["ts_unknown"] = True
        if ev["redacted"]:
            stats["redacted_events"] += 1
        ev["message"] = ctx.redactor.text(ev["message"])
        if "command" in ev:
            ev["command"] = ctx.redactor.text(ev["command"])
        ev["kind"] = "auth_event"
        res.records.append(ev)


def _show(ctx: Context, res: CollectorResult, argv: list[str], label: str, since: Any, stats: dict[str, int]) -> None:
    r = ctx.run(argv)
    if r.error_kind:
        res.error(label, r.error_kind, (r.error or "log failed") + " (administrator privileges are usually needed)")
        return
    if r.returncode != 0 and not r.stdout.strip():
        msg = r.stderr.strip()[:200] or f"exit {r.returncode}"
        kind = "permission_denied" if "permission" in msg.lower() or "privilege" in msg.lower() else "other"
        res.error(label, kind, msg)
        return
    res.sources.append(label)
    if r.truncated:
        res.error(label, "truncated", "log output truncated at size limit; the window is incomplete")
    _ingest(ctx, res, r.stdout, label, since, stats)


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    since = ctx.now - timedelta(hours=ctx.log_window_hours)
    stats = {"lines": 0, "malformed": 0, "ignored": 0, "outside_window": 0, "redacted_events": 0}
    _show(ctx, res, _argv(ctx, ["--last", f"{ctx.log_window_hours}h"]), "log show (live)", since, stats)
    for arc in ctx.import_archives:
        if not arc.is_dir() or arc.suffix != ".logarchive":
            res.error(str(arc), "other", "not a .logarchive directory")
            continue
        _show(ctx, res, _argv(ctx, ["--archive", str(arc)]), f"log show --archive {arc.name}", since, stats)
    for f in ctx.import_logs:
        try:
            with open(f, "rb") as fh:
                data = fh.read(ctx.limit("max_log_file_bytes") + 1)
        except OSError as exc:
            res.error(str(f), "not_found" if isinstance(exc, FileNotFoundError) else "other", str(exc))
            continue
        if len(data) > ctx.limit("max_log_file_bytes"):
            res.error(str(f), "truncated", "imported log truncated to size limit")
            data = data[: ctx.limit("max_log_file_bytes")]
        res.sources.append(f"import:{f.name}")
        _ingest(ctx, res, data.decode("utf-8", errors="replace"), f"import:{f.name}", since, stats)
    res.records.append(
        {
            "kind": "log_stats",
            "window_start": iso(since),
            "window_end": iso(ctx.now),
            "predicate": ctx.config["logs"]["predicate"],
            **stats,
        }
    )
    if not res.sources:
        res.notes.append("no log source could be read: authentication telemetry is NOT available for this host")
    else:
        res.notes.append(
            "unified logging may omit, expire or redact (<private>) events; this artifact is a bounded "
            "sample of the predicate and window shown, not a complete record"
        )
    if stats["redacted_events"]:
        res.notes.append(f"{stats['redacted_events']} event(s) contained <private> redactions")
    res.finalize()
    return res


def copy_imports(ctx: Context, dest_dir: Path) -> list[dict[str, Any]]:
    """Copy user-supplied exported logs verbatim (preserving original evidence)."""
    from ..utils.paths import safe_join

    out = []
    for imp in ctx.import_logs:
        if imp.is_file():
            target = safe_join(dest_dir, imp.name)
            shutil.copyfile(imp, target)
            target.chmod(0o600)
            out.append({"source": str(imp), "relpath": f"imported/{imp.name}"})
    return out
