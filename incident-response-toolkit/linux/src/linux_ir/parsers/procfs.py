"""Defensive parsers for /proc content."""

from __future__ import annotations

import ipaddress
import socket
import struct


def parse_stat(text: str) -> dict[str, int | str] | None:
    """Parse /proc/<pid>/stat; the comm field may contain spaces and parentheses."""
    lp, rp = text.find("("), text.rfind(")")
    if lp < 0 or rp < lp:
        return None
    rest = text[rp + 1 :].split()
    if len(rest) < 20:
        return None
    try:
        return {
            "pid": int(text[:lp].strip()),
            "comm": text[lp + 1 : rp],
            "state": rest[0],
            "ppid": int(rest[1]),
            "starttime_ticks": int(rest[19]),
        }
    except ValueError:
        return None


def parse_status_ids(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        if line.startswith(("Uid:", "Gid:")):
            parts = line.split()
            try:
                key = parts[0].rstrip(":").lower()
                out[f"{key}_real"] = int(parts[1])
                out[f"{key}_effective"] = int(parts[2])
            except (IndexError, ValueError):
                continue
    return out


def parse_cmdline(raw: bytes, max_bytes: int = 65536, max_args: int = 256) -> list[str]:
    parts = raw[:max_bytes].split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", errors="replace") for p in parts][:max_args]


def _hex_addr(h: str) -> str | None:
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return None
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    if len(raw) == 16:
        words = struct.unpack("<4I", raw)
        return str(ipaddress.IPv6Address(struct.pack(">4I", *words)))
    return None


TCP_STATES = {
    "01": "ESTAB",
    "02": "SYN-SENT",
    "03": "SYN-RECV",
    "04": "FIN-WAIT-1",
    "05": "FIN-WAIT-2",
    "06": "TIME-WAIT",
    "07": "CLOSE",
    "08": "CLOSE-WAIT",
    "09": "LAST-ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def parse_proc_net(text: str, proto: str) -> list[dict[str, object]]:
    """Parse /proc/net/{tcp,tcp6,udp,udp6}. Process association is unavailable here."""
    rows: list[dict[str, object]] = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 4 or ":" not in f[1] or ":" not in f[2]:
            continue
        la, _, lp = f[1].rpartition(":")
        ra, _, rp = f[2].rpartition(":")
        laddr, raddr = _hex_addr(la), _hex_addr(ra)
        if laddr is None or raddr is None:
            continue
        try:
            lport, rport = int(lp, 16), int(rp, 16)
        except ValueError:
            continue
        state = (
            TCP_STATES.get(f[3].upper(), f[3])
            if proto.startswith("tcp")
            else ("UNCONN" if f[3].upper() == "07" else f[3])
        )
        rows.append(
            {
                "proto": proto[:3],
                "state": state,
                "local_addr": laddr,
                "local_port": lport,
                "remote_addr": raddr,
                "remote_port": rport,
                "inode": f[9] if len(f) > 9 else None,
            }
        )
    return rows


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%")[0])
        return True
    except ValueError:
        return False


_ = socket  # keep import for platforms that extend address handling
