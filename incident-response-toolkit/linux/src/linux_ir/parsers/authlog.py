"""Authentication log parsing (journalctl short-iso and classic syslog formats)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..utils.timeutil import iso, parse_log_timestamp

MAX_LINE = 2000
_HDR_RE = re.compile(
    r"^(?P<ts>(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)|"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+(?P<host>\S+)\s+"
    r"(?P<prog>[A-Za-z0-9_.@/-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)
_INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
_SUDO_CMD_RE = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
_SUDO_FAIL_RE = re.compile(r"(?:authentication failure|incorrect password attempts?)")
_PAM_USER_RE = re.compile(r"\buser=(?P<user>\S+)")
_PAM_RHOST_RE = re.compile(r"rhost=(?P<ip>[0-9a-fA-F:.]+)")


def parse_line(line: str, ref: datetime, source: str) -> dict[str, Any] | None:
    """Return a structured event for a recognised authentication line, else None.

    Malformed or unrecognised lines return None (callers count them)."""
    line = line.rstrip("\n")[:MAX_LINE]
    m = _HDR_RE.match(line)
    if not m:
        return None
    ts = parse_log_timestamp(m["ts"], ref)
    prog, msg = m["prog"], m["msg"]
    ev: dict[str, Any] = {
        "ts": iso(ts) if ts else None,
        "host": m["host"],
        "program": prog,
        "pid": int(m["pid"]) if m["pid"] else None,
        "source": source,
    }
    base = prog.split("/")[-1]
    if base.startswith("sshd"):
        if fm := _FAILED_RE.search(msg):
            ev.update(event_type="ssh_failed_login", user=fm["user"], src_ip=fm["ip"], method=fm["method"])
        elif am := _ACCEPTED_RE.search(msg):
            ev.update(event_type="ssh_accepted", user=am["user"], src_ip=am["ip"], method=am["method"])
        elif im := _INVALID_RE.search(msg):
            ev.update(event_type="ssh_invalid_user", user=im["user"], src_ip=im["ip"])
        else:
            return None
    elif base == "sudo":
        if sm := _SUDO_CMD_RE.match(msg):
            ev.update(event_type="sudo_command", user=sm["user"], command=sm["cmd"][:300])
        elif _SUDO_FAIL_RE.search(msg):
            u = _PAM_USER_RE.search(msg)
            ev.update(event_type="sudo_auth_failure", user=u["user"] if u else None)
        else:
            return None
    elif base in ("su", "su-l", "login"):
        if "authentication failure" in msg:
            u = _PAM_USER_RE.search(msg)
            r = _PAM_RHOST_RE.search(msg)
            ev.update(event_type="su_auth_failure", user=u["user"] if u else None, src_ip=r["ip"] if r else None)
        else:
            return None
    else:
        return None
    ev["message"] = msg[:500]
    return ev
