"""Process collection from /proc (read-only; never signals or executes anything)."""

from __future__ import annotations

import os
import time
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers.procfs import parse_cmdline, parse_stat, parse_status_ids
from ..utils.timeutil import epoch_to_iso

NAME = "processes"
DESCRIPTION = "Process list with owner, executable, redacted command line, start time and executable hash"
PRIVILEGE_NOTE = (
    "Unprivileged users can usually read stat/cmdline of all processes but not exe links of other users' "
    "processes (hidepid, ptrace restrictions). Those records are marked visibility=limited."
)
TIME_BUDGET_SECONDS = 20


def plan(ctx: Context) -> list[str]:
    return [
        "enumerate /proc/<pid> (stat, status, cmdline, exe link)",
        f"hash process executables ≤ {ctx.limit('max_hash_bytes')} bytes (read via the path, never executed)",
        f"cap: {ctx.limit('max_processes')} processes, {TIME_BUDGET_SECONDS}s budget",
    ]


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    proc = ctx.path("/proc")
    try:
        entries = sorted((e for e in os.listdir(proc) if e.isdigit()), key=int)
    except OSError as exc:
        res.error("/proc", "unavailable", f"cannot enumerate /proc: {exc}")
        res.finalize()
        return res
    res.sources.append("/proc")
    btime = None
    clk = 100
    try:
        clk = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        pass
    try:
        for line in (proc / "stat").read_text().splitlines():
            if line.startswith("btime"):
                btime = int(line.split()[1])
    except (OSError, ValueError):
        res.error("/proc/stat", "other", "boot time unavailable; start times omitted")
    start = time.monotonic()
    vanished = limited = 0
    hashed: dict[str, tuple[str | None, str | None]] = {}
    for pid_s in entries:
        if len(res.records) >= ctx.limit("max_processes"):
            res.error("/proc", "truncated", f"stopped at max_processes={ctx.limit('max_processes')}")
            break
        if time.monotonic() - start > TIME_BUDGET_SECONDS:
            res.error("/proc", "timeout", f"time budget of {TIME_BUDGET_SECONDS}s exceeded; list incomplete")
            break
        pdir = proc / pid_s
        try:
            stat = parse_stat((pdir / "stat").read_text(errors="replace"))
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
            continue
        except PermissionError:
            limited += 1
            continue
        except OSError:
            vanished += 1
            continue
        if stat is None:
            res.error(f"/proc/{pid_s}/stat", "parse_error", "unrecognised stat format")
            continue
        rec: dict[str, Any] = {
            "pid": stat["pid"],
            "ppid": stat["ppid"],
            "name": stat["comm"],
            "state": stat["state"],
            "visibility": "full",
            "exe": None,
            "exe_deleted": False,
            "cmdline": None,
        }
        if btime is not None:
            rec["start_time"] = epoch_to_iso(btime + int(stat["starttime_ticks"]) / clk)
        try:
            rec.update(parse_status_ids((pdir / "status").read_text(errors="replace")))
        except OSError:
            rec["visibility"] = "limited"
        try:
            raw = (pdir / "cmdline").read_bytes()
            args = [ctx.redactor.text(a)[:512] for a in parse_cmdline(raw)]
            rec["cmdline"] = args
            rec["kernel_thread"] = not raw
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
            continue
        except OSError:
            rec["visibility"] = "limited"
        try:
            target = os.readlink(pdir / "exe")
            if target.endswith(" (deleted)"):
                rec["exe_deleted"] = True
                target = target[: -len(" (deleted)")]
            rec["exe"] = target
            if not rec["exe_deleted"]:
                key = target
                if key not in hashed:
                    hashed[key] = ctx.hash_file(pdir / "exe" if ctx.root == type(ctx.root)("/") else ctx.path(target))
                digest, err = hashed[key]
                rec["exe_sha256"] = digest
                if err:
                    rec["exe_hash_error"] = err
        except (FileNotFoundError, ProcessLookupError):
            if rec.get("kernel_thread") is not True and rec["visibility"] == "full":
                pass  # kernel threads have no exe; exited processes handled above
        except PermissionError:
            rec["visibility"] = "limited"
        except OSError:
            rec["visibility"] = "limited"
        if rec["visibility"] == "limited":
            limited += 1
        res.records.append(rec)
    if vanished:
        res.notes.append(f"{vanished} process(es) exited during collection and were skipped")
    if limited:
        res.notes.append(
            f"{limited} process(es) had limited visibility (permission or hidepid). "
            "Absence of data for them is not evidence of absence of activity."
        )
    res.finalize()
    return res
