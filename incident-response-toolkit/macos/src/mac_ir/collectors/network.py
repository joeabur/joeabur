"""Network collection via lsof, netstat and ifconfig (read-only)."""

from __future__ import annotations

from ..context import Context
from ..models import CollectorResult
from ..parsers.system import parse_ifconfig, parse_lsof_f, parse_netstat_an, parse_netstat_routes

NAME = "network"
DESCRIPTION = "Listening/active sockets with owning process (lsof), interfaces (ifconfig), routes (netstat)"
PRIVILEGE_NOTE = (
    "Without root, lsof shows only sockets of the current user's processes. Sockets of other users appear only in the "
    "netstat fallback, without process names."
)
LSOF = ["lsof", "-nP", "-i", "-F", "pcLPnT"]


def plan(ctx: Context) -> list[str]:
    return ["run: " + " ".join(LSOF), "fallback: netstat -an -p tcp / -p udp", "run: ifconfig -a", "run: netstat -rn"]


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    lsof = ctx.run(LSOF)
    got_sockets = False
    if lsof.error_kind or (lsof.returncode not in (0, 1)):
        res.error("lsof", lsof.error_kind or "other", lsof.error or lsof.stderr.strip()[:200] or "lsof failed")
    else:
        # lsof exits 1 when it finds nothing to report; that is a valid (possibly partial) answer
        socks = parse_lsof_f(lsof.stdout)
        res.sources.append(" ".join(LSOF))
        for s in socks:
            res.records.append({"kind": "socket", "source": "lsof", **s})
        got_sockets = bool(socks)
        if lsof.truncated:
            res.error("lsof", "truncated", "lsof output truncated at size limit")
        if lsof.stderr.strip():
            res.notes.append("lsof reported warnings (typically inaccessible files of other users' processes)")
        res.notes.append(
            "lsof without root shows only the current user's processes; listening sockets of other users "
            "or system daemons may be missing."
        )
    if not got_sockets:
        res.notes.append("using netstat fallback: no process association available")
        for proto in ("tcp", "udp"):
            ns = ctx.run(["netstat", "-an", "-p", proto])
            if ns.error_kind or ns.returncode != 0:
                res.error(f"netstat -an -p {proto}", ns.error_kind or "other", ns.error or "netstat failed")
                continue
            res.sources.append(f"netstat -an -p {proto}")
            for s in parse_netstat_an(ns.stdout):
                res.records.append({"kind": "socket", "source": "netstat", **s})
    ifc = ctx.run(["ifconfig", "-a"])
    if ifc.error_kind:
        res.error("ifconfig", ifc.error_kind, ifc.error or "failed")
    else:
        res.sources.append("ifconfig -a")
        for i in parse_ifconfig(ifc.stdout):
            res.records.append({"kind": "interface", **i})
    rt = ctx.run(["netstat", "-rn"])
    if rt.error_kind:
        res.error("netstat -rn", rt.error_kind, rt.error or "failed")
    else:
        res.sources.append("netstat -rn")
        for r in parse_netstat_routes(rt.stdout):
            res.records.append({"kind": "route", **r})
    res.finalize()
    return res
