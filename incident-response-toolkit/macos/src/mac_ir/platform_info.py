"""Platform detection and readiness checks (``info`` / ``doctor``) for macOS."""

from __future__ import annotations

import os
import platform
import shutil
from typing import Any

from .utils.run import euid
from .utils.timeutil import utcnow_iso

SUPPORTED_ARCH = {"arm64", "x86_64"}
MIN_MAJOR = 12  # macOS 12 Monterey; documented support matrix: 12–15
NATIVE_TOOLS = (
    "sw_vers",
    "ps",
    "lsof",
    "netstat",
    "ifconfig",
    "log",
    "who",
    "df",
    "sysctl",
    "csrutil",
    "spctl",
    "fdesetup",
    "codesign",
    "crontab",
)


def parse_sw_vers(text: str) -> dict[str, str]:
    """Parse ``sw_vers`` output (``Key:\tValue`` lines)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip():
            out[k.strip()] = v.strip()
    return out


def detect_platform() -> dict[str, Any]:
    """Pure-Python detection (no subprocesses). Build number comes from ``sw_vers`` in the inventory collector."""
    uname = platform.uname()
    ver, _, machine = platform.mac_ver()
    major = None
    if ver:
        try:
            major = int(ver.split(".")[0])
        except ValueError:
            major = None
    arch = machine or uname.machine
    e = euid()
    return {
        "system": uname.system,
        "is_macos": uname.system == "Darwin",
        "product_version": ver or None,
        "major_version": major,
        "version_supported": bool(major and major >= MIN_MAJOR),
        "pretty_name": f"macOS {ver}" if ver else None,
        "kernel": uname.release,
        "architecture": arch,
        "architecture_supported": arch in SUPPORTED_ARCH,
        "python": platform.python_version(),
        "euid": e,
        "is_root": e == 0,
        "tools": {t: shutil.which(t) for t in NATIVE_TOOLS},
        "timestamp_utc": utcnow_iso(),
    }


def doctor_checks(info: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (status, check, detail) tuples. Status: OK | WARN | FAIL."""
    out: list[tuple[str, str, str]] = []
    if not info["is_macos"]:
        out.append(
            (
                "FAIL",
                "operating system",
                f"{info['system']} is not macOS: live collection is unsupported here (analysis, reporting and "
                "manifest verification still work on any OS)",
            )
        )
    else:
        out.append(("OK", "operating system", info["pretty_name"] or "macOS (version unknown)"))
        out.append(
            (
                "OK" if info["version_supported"] else "WARN",
                "macOS version",
                f"{info['product_version']} (supported: {MIN_MAJOR}+; older versions are untested)",
            )
        )
    out.append(("OK" if info["architecture_supported"] else "WARN", "architecture", info["architecture"]))
    out.append(
        (
            "WARN" if info["is_root"] else "OK",
            "privileges",
            "running as root: more visibility, but the evidence is more sensitive"
            if info["is_root"]
            else "unprivileged: other users' sockets, system logs and protected paths may be partial",
        )
    )
    for tool, path in info["tools"].items():
        out.append(("OK" if path else "WARN", f"tool:{tool}", path or "not found (related data will be partial)"))
    out.append(
        (
            "OK" if os.access("/Library", os.R_OK) else "WARN",
            "read:/Library",
            "readable" if os.access("/Library", os.R_OK) else "not readable",
        )
    )
    out.append(
        (
            "OK",
            "full disk access",
            "not required: protected (TCC) locations are reported as inaccessible, never bypassed",
        )
    )
    return out
