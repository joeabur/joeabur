"""Network collection: sockets (ss, /proc/net fallback), interfaces, routes, firewall metadata."""

from __future__ import annotations

from ..context import Context
from ..models import CollectorResult
from ..parsers.procfs import parse_proc_net
from ..parsers.ss import parse_ip_addr, parse_ip_route, parse_ss

NAME = "network"
DESCRIPTION = "Listening/active sockets, interfaces, routes and (extended) firewall rule metadata"
PRIVILEGE_NOTE = "ss shows process names only for the caller's own sockets without root; firewall listing needs root."


def plan(ctx: Context) -> list[str]:
    steps = ["run: ss -H -tunap (fallback: parse /proc/net/{tcp,tcp6,udp,udp6})", "run: ip -o addr", "run: ip route"]
    if ctx.deep:
        steps += ["run: nft list ruleset (read-only; usually needs root)", "run: iptables -S (read-only; needs root)"]
    return steps


def _proc_net_fallback(ctx: Context, res: CollectorResult) -> None:
    for fname in ("tcp", "tcp6", "udp", "udp6"):
        path = f"/proc/net/{fname}"
        try:
            text = ctx.path(path).read_text(errors="replace")
        except OSError as exc:
            res.error(path, "not_found" if isinstance(exc, FileNotFoundError) else "other", str(exc))
            continue
        res.sources.append(path)
        for row in parse_proc_net(text, fname):
            row.update(kind="socket", source="procfs", process=None, pid=None)
            res.records.append(row)


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    ss = ctx.run(["ss", "-H", "-tunap"])
    if ss.error_kind:
        res.error("ss", ss.error_kind, ss.error or "ss failed")
        res.notes.append("ss unavailable: using /proc/net without process association")
        _proc_net_fallback(ctx, res)
    else:
        rows, bad = parse_ss(ss.stdout)
        for r in rows:
            r.update(kind="socket", source="ss")
            res.records.append(r)
        res.sources.append("ss -H -tunap")
        if bad:
            res.error("ss", "parse_error", f"{bad} unparseable line(s) skipped")
        if ss.truncated:
            res.error("ss", "truncated", "ss output truncated at size limit")
        if rows and all(r["process"] is None for r in rows):
            res.notes.append("no process names in ss output: run with sufficient privileges for socket owners")
    for argv, parser, kind in (
        (["ip", "-o", "addr"], parse_ip_addr, "interface"),
        (["ip", "route"], parse_ip_route, "route"),
    ):
        cmd = ctx.run(argv)
        if cmd.error_kind:
            res.error(" ".join(argv), cmd.error_kind, cmd.error or "failed")
            continue
        res.sources.append(" ".join(argv))
        for item in parser(cmd.stdout):
            item["kind"] = kind
            res.records.append(item)
    if ctx.deep:
        for argv, label in ((["nft", "list", "ruleset"], "nftables"), (["iptables", "-S"], "iptables")):
            fw = ctx.run(argv)
            if fw.error_kind:
                res.error(
                    " ".join(argv),
                    fw.error_kind,
                    (fw.error or "failed") + " (root is typically required; re-run this collector as root if needed)",
                )
                continue
            lines = [ln for ln in fw.stdout.splitlines() if ln.strip()]
            res.sources.append(" ".join(argv))
            res.records.append(
                {
                    "kind": "firewall",
                    "backend": label,
                    "rule_lines": len(lines),
                    "sample": [ln[:200] for ln in lines[:50]],
                }
            )
    res.finalize()
    return res
