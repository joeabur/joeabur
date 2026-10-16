"""Process collection via ``ps`` (read-only). Never signals, suspends or injects into processes."""

from __future__ import annotations

import os
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers.system import parse_ps, parse_ps_args

NAME = "processes"
DESCRIPTION = (
    "Process list: pid/ppid/owner/state/start time, executable path, redacted command line, executable SHA-256"
)
PRIVILEGE_NOTE = (
    "ps lists all processes for any user, but executable files in SIP/TCC-protected locations may be unreadable "
    "(hash omitted) and command-line visibility can be restricted. Sandboxed or privileged helper details may be absent."
)
PS_META = ["ps", "-axo", "pid=,ppid=,uid=,user=,stat=,lstart=,comm="]
PS_ARGS = ["ps", "-axww", "-o", "pid=,command="]


def plan(ctx: Context) -> list[str]:
    return [
        "run: " + " ".join(PS_META),
        "run: " + " ".join(PS_ARGS) + "  (command lines are redacted before storage)",
        f"hash up to {ctx.limit('max_process_hashes')} distinct executables ≤ {ctx.limit('max_hash_bytes')} bytes "
        "(read, never executed)",
    ]


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    meta = ctx.run(PS_META)
    if meta.error_kind or meta.returncode != 0:
        res.error("ps", meta.error_kind or "other", meta.error or meta.stderr.strip()[:200] or "ps failed")
        res.finalize()
        return res
    res.sources.append(" ".join(PS_META))
    rows, bad = parse_ps(meta.stdout)
    if bad:
        res.error("ps", "parse_error", f"{bad} unparseable line(s) skipped")
    if meta.truncated:
        res.error("ps", "truncated", "ps output truncated at size limit")
    args_map: dict[int, str] = {}
    argres = ctx.run(PS_ARGS)
    if argres.error_kind or argres.returncode != 0:
        res.error("ps -o command", argres.error_kind or "other", "command lines unavailable")
    else:
        res.sources.append(" ".join(PS_ARGS))
        args_map = parse_ps_args(argres.stdout)
    hashed: dict[str, tuple[str | None, str | None]] = {}
    for row in rows[: ctx.limit("max_processes")]:
        comm = row.pop("comm")
        rec: dict[str, Any] = {
            **row,
            "name": os.path.basename(comm),
            "exe": comm if comm.startswith("/") else None,
            "visibility": "full",
        }
        cmd = args_map.get(row["pid"])
        rec["cmdline"] = [ctx.redactor.text(cmd)[:1000]] if cmd is not None else None
        if cmd is None:
            rec["visibility"] = "limited"
        exe = rec["exe"]
        if exe:
            if exe not in hashed and len(hashed) < ctx.limit("max_process_hashes"):
                hashed[exe] = ctx.hash_file(ctx.path(exe))
            if exe in hashed:
                digest, err = hashed[exe]
                rec["exe_sha256"] = digest
                if err:
                    rec["exe_hash_error"] = err
        res.records.append(rec)
    if len(rows) > ctx.limit("max_processes"):
        res.error("ps", "truncated", f"stopped at max_processes={ctx.limit('max_processes')}")
    if len(hashed) >= ctx.limit("max_process_hashes"):
        res.notes.append("executable hashing stopped at max_process_hashes; later executables are unhashed")
    unhashed_errs = sum(1 for h in hashed.values() if h[1])
    if unhashed_errs:
        res.notes.append(f"{unhashed_errs} executable(s) could not be hashed (permissions, SIP/TCC or size limit)")
    limited = sum(1 for r in res.records if r["visibility"] == "limited")
    if limited:
        res.notes.append(f"{limited} process(es) had no command line available; they may have exited or be restricted")
    res.notes.append(
        "Processes that exited between ps calls may lack a command line. Absence of a process is not "
        "proof it never ran."
    )
    res.finalize()
    return res
