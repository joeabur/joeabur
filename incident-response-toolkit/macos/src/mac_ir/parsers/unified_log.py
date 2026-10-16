"""Parser for ``log show --style ndjson`` output and event classification."""

from __future__ import annotations

import json
import re
from typing import Any

from ..utils.timeutil import iso, parse_iso

_FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)
_INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
_SUDO_CMD_RE = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
_SUDO_FAIL_RE = re.compile(r"(?:authentication failure|incorrect password attempts?|auth.*fail)", re.I)
MAX_MESSAGE = 500


def parse_event(line: str, source: str) -> tuple[dict[str, Any] | None, str]:
    """Return (event, status). status: ``event`` | ``ignored`` | ``malformed``."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None, "malformed"
    try:
        obj = json.loads(line)
    except ValueError:
        return None, "malformed"
    if not isinstance(obj, dict) or "eventMessage" not in obj:
        return None, "malformed"
    msg = str(obj.get("eventMessage", ""))[:2000]
    image = str(obj.get("processImagePath", ""))
    proc = image.rsplit("/", 1)[-1] if image else str(obj.get("process", ""))
    ts_raw = str(obj.get("timestamp", ""))
    ts = parse_iso(ts_raw.replace("+0000", "Z")) if ts_raw else None
    ev: dict[str, Any] = {
        "ts": iso(ts) if ts else None,
        "program": proc,
        "pid": obj.get("processID"),
        "subsystem": obj.get("subsystem") or None,
        "source": source,
        "redacted": "<private>" in msg,
    }
    if proc == "sshd":
        if m := _FAILED_RE.search(msg):
            ev.update(event_type="ssh_failed_login", user=m["user"], src_ip=m["ip"], method=m["method"])
        elif m := _ACCEPTED_RE.search(msg):
            ev.update(event_type="ssh_accepted", user=m["user"], src_ip=m["ip"], method=m["method"])
        elif m := _INVALID_RE.search(msg):
            ev.update(event_type="ssh_invalid_user", user=m["user"], src_ip=m["ip"])
        else:
            return None, "ignored"
    elif proc == "sudo":
        if m := _SUDO_CMD_RE.match(msg):
            ev.update(event_type="sudo_command", user=m["user"], command=m["cmd"][:300])
        elif _SUDO_FAIL_RE.search(msg):
            u = re.search(r"\buser=(\S+)", msg) or re.search(r"^\s*(\S+) : ", msg)
            ev.update(event_type="sudo_auth_failure", user=u.group(1) if u else None)
        else:
            return None, "ignored"
    elif proc in ("su", "login", "screensharingd"):
        if "fail" in msg.lower():
            ev.update(event_type="login_failure", user=None)
        else:
            return None, "ignored"
    else:
        return None, "ignored"
    ev["message"] = msg[:MAX_MESSAGE]
    return ev, "event"
