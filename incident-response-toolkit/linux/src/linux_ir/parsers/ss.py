"""Parser for ``ss -H -tunap`` output and ``ip`` output."""

from __future__ import annotations

import re
from typing import Any

_USERS_RE = re.compile(r'\("([^"]*)",pid=(\d+),fd=(\d+)\)')


def split_hostport(token: str) -> tuple[str, int | None]:
    token = token.strip()
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = token.rpartition(":")
    host = host.split("%")[0] or "*"
    if port in ("*", ""):
        return host, None
    try:
        return host, int(port)
    except ValueError:
        return host, None


def parse_ss(text: str) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    bad = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        f = line.split(None, 6)
        if len(f) < 6 or f[0] not in ("tcp", "udp"):
            bad += 1
            continue
        laddr, lport = split_hostport(f[4])
        raddr, rport = split_hostport(f[5])
        proc = None
        pid = None
        if len(f) == 7:
            m = _USERS_RE.search(f[6])
            if m:
                proc, pid = m.group(1), int(m.group(2))
        rows.append(
            {
                "proto": f[0],
                "state": f[1],
                "local_addr": laddr,
                "local_port": lport,
                "remote_addr": raddr,
                "remote_port": rport,
                "process": proc,
                "pid": pid,
            }
        )
    return rows, bad


def parse_ip_addr(text: str) -> list[dict[str, Any]]:
    """Parse ``ip -o addr`` lines."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[2] in ("inet", "inet6"):
            out.append({"interface": f[1].rstrip(":"), "family": f[2], "address": f[3]})
    return out


def parse_ip_route(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        rec: dict[str, Any] = {"destination": f[0], "raw": line.strip()[:200]}
        for key in ("via", "dev", "src", "metric"):
            if key in f and f.index(key) + 1 < len(f):
                rec[key] = f[f.index(key) + 1]
        out.append(rec)
    return out
