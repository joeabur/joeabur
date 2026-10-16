"""Collection orchestration: runs collectors, writes artifacts and the manifest."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from . import PLATFORM_LABEL
from .collectors import REGISTRY
from .collectors.logs import copy_imports
from .context import Context
from .evidence.manifest import artifact_document, build_manifest, write_artifact, write_manifest
from .models import CollectorResult
from .platform_info import detect_platform
from .utils.paths import create_unique_dir
from .utils.run import euid
from .utils.timeutil import iso, utcnow_iso


def plan_collection(ctx: Context, names: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "collector": n,
            "description": REGISTRY[n].DESCRIPTION,
            "privilege_note": REGISTRY[n].PRIVILEGE_NOTE,
            "operations": REGISTRY[n].plan(ctx),
        }
        for n in names
    ]


def run_collection(ctx: Context, profile: str, names: list[str], output: Path) -> tuple[Path, str, dict[str, Any]]:
    started = utcnow_iso()
    host = (ctx.hostname or socket.gethostname()).split(".")[0][:40] or "host"
    safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in host)
    evdir = create_unique_dir(output, f"{safe_host}-{ctx.now.strftime('%Y%m%dT%H%M%SZ')}")
    all_results: list[CollectorResult] = []
    for n in names:
        mod = REGISTRY[n]
        try:
            res = mod.collect(ctx)
        except Exception as exc:  # a failing collector must never stop the others
            res = CollectorResult(n)
            res.error(n, "other", f"collector crashed: {type(exc).__name__}: {exc}")
            res.status = "failed"
        all_results.append(res)
        write_artifact(evdir, artifact_document(res, utcnow_iso()))
    if "logs" in names and ctx.import_logs:
        (evdir / "imported").mkdir(mode=0o700, exist_ok=True)
        copy_imports(ctx, evdir / "imported")
    plat = detect_platform(ctx.root)
    plat.pop("tools", None)
    all_names = list(REGISTRY)
    meta: dict[str, Any] = {
        "platform": PLATFORM_LABEL,
        "profile": profile,
        "collectors_requested": names,
        "started_at": started,
        "finished_at": utcnow_iso(),
        "host": {"hostname": host, **plat},
        "euid": euid(),
        "privileged": euid() == 0,
        "log_window_hours": ctx.log_window_hours,
        "not_run": {n: "not selected by the chosen profile/collectors" for n in all_names if n not in names},
        "created_at": iso(ctx.now),
    }
    manifest = build_manifest(evdir, meta)
    _, digest = write_manifest(evdir, manifest)
    return evdir, digest, manifest
