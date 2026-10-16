"""Host inventory via documented macOS utilities (sw_vers, uname, who, uptime/sysctl, df) and read-only queries."""

from __future__ import annotations

import os
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers.system import parse_boottime, parse_df
from ..platform_info import detect_platform, parse_sw_vers
from ..utils.timeutil import epoch_to_iso, iso

NAME = "inventory"
DESCRIPTION = (
    "macOS version/build, architecture, uptime, sessions, disk space, SIP/Gatekeeper/FileVault/firewall status"
)
PRIVILEGE_NOTE = "No privileges required. Each security query is read-only; failures are recorded, not escalated."

SECURITY_QUERIES: list[tuple[str, list[str]]] = [
    ("sip", ["csrutil", "status"]),
    ("gatekeeper", ["spctl", "--status"]),
    ("filevault", ["fdesetup", "status"]),
    ("application_firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]),
]


def plan(ctx: Context) -> list[str]:
    return [
        "run: sw_vers, uname -m, hostname, sysctl -n kern.boottime, who, df -k",
        "run (read-only status queries): " + "; ".join(" ".join(q) for _, q in SECURITY_QUERIES),
    ]


def _run_text(ctx: Context, res: CollectorResult, argv: list[str]) -> str | None:
    r = ctx.run(argv)
    if r.error_kind:
        res.error(" ".join(argv), r.error_kind, r.error or "command failed")
        return None
    if r.returncode != 0 and not r.stdout.strip():
        res.error(" ".join(argv), "other", (r.stderr.strip() or f"exit {r.returncode}")[:200])
        return None
    res.sources.append(" ".join(argv))
    return r.stdout


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    info = detect_platform()
    rec: dict[str, Any] = {
        "kind": "host",
        **info,
        "collected_at": iso(ctx.now),
        "hostname": None,
        "build": None,
        "uptime_seconds": None,
        "boot_time": None,
    }
    rec.pop("tools", None)
    sw = _run_text(ctx, res, ["sw_vers"])
    if sw:
        v = parse_sw_vers(sw)
        rec.update(
            product_name=v.get("ProductName"), product_version=v.get("ProductVersion"), build=v.get("BuildVersion")
        )
        rec["pretty_name"] = f"{v.get('ProductName', 'macOS')} {v.get('ProductVersion', '')}".strip()
        try:
            major = int(str(v.get("ProductVersion", "")).split(".")[0])
            rec["major_version"], rec["version_supported"] = major, major >= 12
        except ValueError:
            res.error("sw_vers", "parse_error", "unexpected ProductVersion format")
    arch = _run_text(ctx, res, ["uname", "-m"])
    if arch:
        rec["architecture"] = arch.strip()
    ctx_translated = ctx.run(["sysctl", "-n", "sysctl.proc_translated"])
    rec["rosetta_translated"] = ctx_translated.ok and ctx_translated.stdout.strip() == "1"
    host = _run_text(ctx, res, ["hostname"])
    rec["hostname"] = host.strip() if host else os.uname().nodename if hasattr(os, "uname") else None
    bt = _run_text(ctx, res, ["sysctl", "-n", "kern.boottime"])
    if bt:
        sec = parse_boottime(bt)
        if sec is None:
            res.error("sysctl kern.boottime", "parse_error", "unexpected format")
        else:
            rec["boot_time"] = epoch_to_iso(sec)
            rec["uptime_seconds"] = max(0, int(ctx.now.timestamp() - sec))
    sec_settings: dict[str, str] = {}
    for name, argv in SECURITY_QUERIES:
        out = _run_text(ctx, res, argv)
        if out is not None:
            sec_settings[name] = out.strip().splitlines()[0][:200] if out.strip() else ""
    rec["security_settings"] = sec_settings
    res.records.append(rec)
    who = _run_text(ctx, res, ["who"])
    if who:
        for line in who.splitlines()[:200]:
            f = line.split()
            if len(f) >= 3:
                res.records.append(
                    {
                        "kind": "session",
                        "user": f[0],
                        "tty": f[1],
                        "login": " ".join(f[2:5]),
                        "from": f[-1].strip("()") if f[-1].startswith("(") else None,
                    }
                )
    df = _run_text(ctx, res, ["df", "-k"])
    if df:
        for row in parse_df(df)[:100]:
            if row["device"].startswith("/dev/"):
                res.records.append({"kind": "volume", **row})
    res.finalize()
    return res
