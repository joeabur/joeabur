"""Platform detection and readiness checks (``info`` / ``doctor``)."""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any

from .utils.timeutil import utcnow_iso

SUPPORTED_ARCH = {"x86_64", "amd64", "aarch64", "arm64"}
NATIVE_TOOLS = ("ss", "ip", "lsof", "journalctl", "systemctl", "who", "uptime", "findmnt", "nft", "iptables")


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def detect_init(root: Path = Path("/")) -> dict[str, Any]:
    comm = None
    try:
        comm = (root / "proc/1/comm").read_text().strip()
    except OSError:
        pass
    systemd_dir = (root / "run/systemd/system").is_dir()
    if systemd_dir or comm == "systemd":
        name = "systemd"
    elif comm:
        name = comm
    else:
        name = "unknown"
    return {"name": name, "systemd": name == "systemd", "pid1_comm": comm}


def detect_container(root: Path = Path("/")) -> str | None:
    if (root / ".dockerenv").exists():
        return "docker"
    try:
        cg = (root / "proc/1/cgroup").read_text()
    except OSError:
        return None
    for marker in ("docker", "kubepods", "containerd", "lxc", "podman"):
        if marker in cg:
            return marker
    return None


def detect_platform(root: Path = Path("/")) -> dict[str, Any]:
    uname = platform.uname()
    osr: dict[str, str] = {}
    for rel in ("etc/os-release", "usr/lib/os-release"):
        try:
            osr = parse_os_release((root / rel).read_text(encoding="utf-8", errors="replace"))
            break
        except OSError:
            continue
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    arch = uname.machine
    return {
        "system": uname.system,
        "is_linux": uname.system == "Linux",
        "distribution": osr.get("NAME"),
        "distribution_id": osr.get("ID"),
        "version": osr.get("VERSION_ID"),
        "pretty_name": osr.get("PRETTY_NAME"),
        "kernel": uname.release,
        "architecture": arch,
        "architecture_supported": arch.lower() in SUPPORTED_ARCH,
        "init": detect_init(root),
        "container": detect_container(root),
        "python": platform.python_version(),
        "euid": euid,
        "is_root": euid == 0,
        "tools": {t: shutil.which(t) for t in NATIVE_TOOLS},
        "timestamp_utc": utcnow_iso(),
    }


def doctor_checks(info: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (status, check, detail) tuples. Status: OK | WARN | FAIL."""
    out: list[tuple[str, str, str]] = []
    out.append(
        (
            "OK" if info["is_linux"] else "FAIL",
            "operating system",
            f"{info['system']} ({info['pretty_name'] or 'unknown distribution'})",
        )
    )
    out.append(("OK" if info["architecture_supported"] else "WARN", "architecture", info["architecture"]))
    out.append(
        (
            "OK" if info["init"]["systemd"] else "WARN",
            "init system",
            info["init"]["name"]
            + ("" if info["init"]["systemd"] else " (systemd-specific collection will be skipped)"),
        )
    )
    out.append(
        (
            "OK" if not info["is_root"] else "WARN",
            "privileges",
            "running as root: collection will see more, but also touches more data"
            if info["is_root"]
            else "unprivileged: some sources (other users' /proc data, auth logs, firewall) may be partial",
        )
    )
    if info["container"]:
        out.append(("WARN", "container", f"inside {info['container']}: /proc and logs reflect the container"))
    for tool, path in info["tools"].items():
        out.append(("OK" if path else "WARN", f"tool:{tool}", path or "not found (related data will be partial)"))
    for p in ("/proc", "/etc/os-release"):
        out.append(
            (
                "OK" if os.access(p, os.R_OK) else "WARN",
                f"read:{p}",
                "readable" if os.access(p, os.R_OK) else "not readable",
            )
        )
    return out
