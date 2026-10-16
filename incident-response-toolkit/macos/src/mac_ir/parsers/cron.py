"""Parser for crontab-format content (never executed)."""

from __future__ import annotations

from typing import Any

SPECIALS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
MAX_LINES = 2000


def exec_token(command: str) -> str | None:
    toks = command.split()
    # skip leading VAR=value words
    for t in toks:
        if "=" in t and not t.startswith("/"):
            continue
        return t.strip("\"'")
    return None


def parse_crontab(text: str, system: bool) -> list[dict[str, Any]]:
    """Parse crontab lines. ``system`` crontabs carry a user column."""
    out: list[dict[str, Any]] = []
    for n, raw in enumerate(text.splitlines(), start=1):
        if n > MAX_LINES:
            break
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        # environment assignment such as MAILTO=root or PATH=/usr/bin
        if "=" in f[0] and not f[0].startswith(("/", "@", "*")) and f[0].split("=")[0].isidentifier():
            continue
        if f[0] in SPECIALS:
            sched, rest = f[0], f[1:]
        elif len(f) >= 6:
            sched, rest = " ".join(f[:5]), f[5:]
        else:
            out.append({"line_no": n, "parse_error": True, "raw": line[:200]})
            continue
        user = None
        if system:
            if not rest:
                out.append({"line_no": n, "parse_error": True, "raw": line[:200]})
                continue
            user, rest = rest[0], rest[1:]
        command = " ".join(rest)
        if not command:
            out.append({"line_no": n, "parse_error": True, "raw": line[:200]})
            continue
        out.append(
            {"line_no": n, "schedule": sched, "user": user, "command": command, "exec_binary": exec_token(command)}
        )
    return out
