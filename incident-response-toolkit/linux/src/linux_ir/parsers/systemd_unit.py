"""Static parser for systemd unit files. Unit content is untrusted and never executed."""

from __future__ import annotations

from typing import Any

MAX_LINES = 2000


def parse_unit(text: str) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: str | None = None
    pending = ""
    for n, raw in enumerate(text.splitlines()):
        if n >= MAX_LINES:
            break
        line = raw.rstrip()
        if pending:
            line = pending + line.lstrip()
            pending = ""
        if line.endswith("\\"):
            pending = line[:-1].rstrip() + " "
            continue
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            current = s[1:-1]
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in s:
            continue
        k, _, v = s.partition("=")
        sections[current].setdefault(k.strip(), []).append(v.strip())
    return sections


def exec_binary(command: str) -> str | None:
    """First token of an Exec* line with systemd prefix modifiers (@ - : + !) removed."""
    command = command.strip()
    while command and command[0] in "@-:+!":
        command = command[1:]
    if not command:
        return None
    tok = command.split(None, 1)[0].strip("\"'")
    return tok or None


def _first(d: dict[str, list[str]], key: str) -> str | None:
    vals = d.get(key)
    return vals[0] if vals else None


def summarize(sections: dict[str, dict[str, list[str]]]) -> dict[str, Any]:
    svc = sections.get("Service", {})
    timer = sections.get("Timer", {})
    install = sections.get("Install", {})
    execs: list[str] = []
    for key in ("ExecStartPre", "ExecStart", "ExecStartPost", "ExecStop", "ExecReload"):
        execs.extend(f"{key}={v}" for v in svc.get(key, []))
    starts = svc.get("ExecStart", [])
    return {
        "description": _first(sections.get("Unit", {}), "Description"),
        "exec_start": starts,
        "exec_all": execs,
        "exec_binary": exec_binary(starts[0]) if starts else None,
        "user": _first(svc, "User"),
        "type": _first(svc, "Type"),
        "restart": _first(svc, "Restart"),
        "wanted_by": install.get("WantedBy", []),
        "timer_schedule": timer.get("OnCalendar", []) + timer.get("OnBootSec", []) + timer.get("OnUnitActiveSec", []),
        "timer_unit": _first(timer, "Unit"),
    }
