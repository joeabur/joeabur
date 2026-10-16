"""Static parsing of launchd property lists. Plists are untrusted data and are never executed."""

from __future__ import annotations

import plistlib
from typing import Any

MAX_PLIST_BYTES = 1_048_576


class PlistError(ValueError):
    pass


def parse_plist(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_PLIST_BYTES:
        raise PlistError(f"plist larger than {MAX_PLIST_BYTES} bytes")
    try:
        doc = plistlib.loads(data)  # safe: pure data, no object instantiation
    except (plistlib.InvalidFileException, ValueError, OverflowError, TypeError, EOFError) as exc:
        raise PlistError(f"not a valid property list: {exc}") from exc
    except Exception as exc:  # expat errors etc.
        raise PlistError(f"unparseable property list: {type(exc).__name__}") from exc
    if not isinstance(doc, dict):
        raise PlistError("plist root is not a dictionary")
    return doc


def summarize_launchd(doc: dict[str, Any]) -> dict[str, Any]:
    prog = doc.get("Program") if isinstance(doc.get("Program"), str) else None
    args_raw = doc.get("ProgramArguments")
    args = [str(a)[:500] for a in args_raw][:64] if isinstance(args_raw, list) else []
    keep = doc.get("KeepAlive")
    return {
        "label": doc.get("Label") if isinstance(doc.get("Label"), str) else None,
        "program": prog,
        "program_arguments": args,
        "exec_binary": prog or (args[0] if args else None),
        "run_at_load": bool(doc.get("RunAtLoad", False)),
        "keep_alive": bool(keep) if not isinstance(keep, dict) else True,
        "start_interval": doc.get("StartInterval") if isinstance(doc.get("StartInterval"), int) else None,
        "has_calendar_interval": "StartCalendarInterval" in doc,
        "watch_paths": [str(p) for p in doc.get("WatchPaths", [])][:20]
        if isinstance(doc.get("WatchPaths"), list)
        else [],
        "user_name": doc.get("UserName") if isinstance(doc.get("UserName"), str) else None,
        "disabled": bool(doc.get("Disabled", False)),
    }
