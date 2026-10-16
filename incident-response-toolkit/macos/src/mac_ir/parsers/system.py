"""Parsers for macOS command output: ps, lsof -F, netstat, ifconfig, df, sysctl, sw_vers helpers, codesign."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

_LSTART_FMT = "%a %b %d %H:%M:%S %Y"


def parse_lstart(tokens: list[str], tz: Any = UTC) -> str | None:
    """Parse ps ``lstart`` ("Thu Mar  5 10:00:01 2026", host-local time). Zone is assumed UTC unless supplied."""
    try:
        dt = datetime.strptime(" ".join(tokens), _LSTART_FMT).replace(tzinfo=tz)
    except ValueError:
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ps(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse ``ps -axo pid=,ppid=,uid=,user=,stat=,lstart=,comm=``. Returns (rows, malformed_count)."""
    rows: list[dict[str, Any]] = []
    bad = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        f = line.split(None, 10)
        if len(f) < 11:
            bad += 1
            continue
        try:
            pid, ppid, uid = int(f[0]), int(f[1]), int(f[2])
        except ValueError:
            bad += 1
            continue
        rows.append(
            {
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "user": f[3],
                "state": f[4],
                "start_time": parse_lstart(f[5:10]),
                "comm": f[10].strip(),
            }
        )
    return rows, bad


def parse_ps_args(text: str) -> dict[int, str]:
    """Parse ``ps -axww -o pid=,command=``."""
    out: dict[int, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if parts and parts[0].isdigit():
            out[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    return out


def split_endpoint(token: str) -> tuple[str, int | None]:
    """Split ``host:port`` / ``[v6]:port`` / ``*:port`` / ``host.port`` (netstat)."""
    token = token.strip()
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        port = rest.lstrip(":")
    elif ":" in token:
        host, _, port = token.rpartition(":")
    elif "." in token:
        host, _, port = token.rpartition(".")
    else:
        return token, None
    if port in ("*", ""):
        return host or "*", None
    try:
        return host or "*", int(port)
    except ValueError:
        return host or "*", None


def parse_lsof_f(text: str) -> list[dict[str, Any]]:
    """Parse ``lsof -nP -i -F pcLPnT`` field output into one record per network file."""
    rows: list[dict[str, Any]] = []
    proc: dict[str, Any] = {}
    cur: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal cur
        if cur and cur.get("name"):
            rows.append(cur)
        cur = None

    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            flush()
            proc = {"pid": int(val) if val.isdigit() else None}
        elif tag == "c":
            proc["process"] = val
        elif tag == "L":
            proc["user"] = val
        elif tag == "f":
            flush()
            cur = dict(proc)
        elif cur is not None:
            if tag == "P":
                cur["proto"] = val.lower()
            elif tag == "n":
                cur["name"] = val
            elif tag == "T" and val.startswith("ST="):
                cur["state"] = val[3:]
    flush()
    out = []
    for r in rows:
        name = r["name"]
        local, _, remote = name.partition("->")
        laddr, lport = split_endpoint(local)
        raddr, rport = split_endpoint(remote) if remote else ("*", None)
        state = r.get("state") or ("UNCONN" if r.get("proto") == "udp" else "UNKNOWN")
        out.append(
            {
                "proto": r.get("proto"),
                "state": state,
                "local_addr": laddr,
                "local_port": lport,
                "remote_addr": raddr,
                "remote_port": rport,
                "process": r.get("process"),
                "pid": r.get("pid"),
                "user": r.get("user"),
            }
        )
    return out


def parse_netstat_an(text: str) -> list[dict[str, Any]]:
    """Parse ``netstat -an -p tcp|udp`` rows (no process association)."""
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 5 or not f[0].startswith(("tcp", "udp")):
            continue
        laddr, lport = split_endpoint(f[3])
        raddr, rport = split_endpoint(f[4])
        state = f[5] if len(f) > 5 else ("UNCONN" if f[0].startswith("udp") else "UNKNOWN")
        state = "LISTEN" if state == "LISTEN" else state
        rows.append(
            {
                "proto": f[0][:3],
                "state": state,
                "local_addr": laddr,
                "local_port": lport,
                "remote_addr": raddr,
                "remote_port": rport,
                "process": None,
                "pid": None,
            }
        )
    return rows


def parse_netstat_routes(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] != "Destination" and not line.startswith(("Routing", "Internet")):
            rows.append({"destination": f[0], "gateway": f[1], "flags": f[2], "interface": f[3]})
    return rows


def parse_ifconfig(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    iface = None
    for line in text.splitlines():
        m = re.match(r"^([a-z0-9]+): flags=", line)
        if m:
            iface = m.group(1)
            continue
        m = re.match(r"^\s+(inet6?) (\S+)", line)
        if m and iface:
            out.append({"interface": iface, "family": m.group(1), "address": m.group(2).split("%")[0]})
    return out


def parse_boottime(text: str) -> int | None:
    """Parse ``sysctl -n kern.boottime``: ``{ sec = 1772900000, usec = 0 } ...``."""
    m = re.search(r"sec\s*=\s*(\d+)", text)
    return int(m.group(1)) if m else None


def parse_df(text: str) -> list[dict[str, Any]]:
    """Parse ``df -k`` (1024-byte blocks)."""
    rows = []
    for line in text.splitlines()[1:]:
        f = line.split(None, 8)
        if len(f) >= 9 and f[1].isdigit():
            rows.append(
                {
                    "device": f[0],
                    "total_bytes": int(f[1]) * 1024,
                    "free_bytes": int(f[3]) * 1024,
                    "mountpoint": f[8].strip(),
                }
            )
        elif len(f) >= 6 and f[1].isdigit():
            rows.append(
                {"device": f[0], "total_bytes": int(f[1]) * 1024, "free_bytes": int(f[3]) * 1024, "mountpoint": f[-1]}
            )
    return rows


def parse_codesign(stderr: str, returncode: int | None) -> dict[str, Any]:
    """Interpret ``codesign -dv --verbose=2`` output. Signing is context, not a verdict."""
    low = stderr.lower()
    if "not signed at all" in low:
        return {"signed": False, "team_id": None, "authority": None, "adhoc": False}
    if returncode not in (0, None) and "authority" not in low and "identifier=" not in low:
        return {"signed": None, "team_id": None, "authority": None, "adhoc": False, "error": stderr.strip()[:200]}
    team = re.search(r"TeamIdentifier=(\S+)", stderr)
    auth = re.search(r"Authority=(.+)", stderr)
    return {
        "signed": True,
        "team_id": None if not team or team.group(1) == "not" else team.group(1),
        "authority": auth.group(1).strip() if auth else None,
        "adhoc": "Signature=adhoc" in stderr,
    }
