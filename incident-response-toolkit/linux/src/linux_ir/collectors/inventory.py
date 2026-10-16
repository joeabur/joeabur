"""Host inventory: OS, kernel, uptime, sessions, mounts, disk, selected security settings."""

from __future__ import annotations

import os
import shutil
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..platform_info import detect_platform
from ..utils.timeutil import epoch_to_iso, iso

NAME = "inventory"
DESCRIPTION = "Host/OS metadata, uptime, sessions, mounts, disk space, selected security settings"
PRIVILEGE_NOTE = "No privileges required."

_PSEUDO_FS = {
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "autofs",
    "binfmt_misc",
    "overlay",
}
_SECURITY_FILES = {
    "kernel.randomize_va_space": "/proc/sys/kernel/randomize_va_space",
    "kernel.yama.ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
    "kernel.kptr_restrict": "/proc/sys/kernel/kptr_restrict",
    "kernel.dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
    "selinux.enforce": "/sys/fs/selinux/enforce",
    "apparmor.enabled": "/sys/module/apparmor/parameters/enabled",
}


def plan(ctx: Context) -> list[str]:
    return [
        "read /etc/os-release, /proc/uptime, /proc/stat, /proc/self/mounts, /proc/1/comm",
        "read selected /proc/sys and /sys security parameters (read-only)",
        "run: who (bounded)",
        "run: findmnt --json (bounded, optional)",
    ]


def _read(ctx: Context, res: CollectorResult, path: str) -> str | None:
    try:
        text = ctx.path(path).read_text(encoding="utf-8", errors="replace")
        res.sources.append(path)
        return text
    except FileNotFoundError:
        res.error(path, "not_found", "source not present on this system")
    except PermissionError:
        res.error(path, "permission_denied", "cannot read")
    except OSError as exc:
        res.error(path, "other", str(exc))
    return None


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    info = detect_platform(ctx.root)
    info["tools"] = {k: v for k, v in info["tools"].items()}
    rec: dict[str, Any] = {"kind": "host", **info, "hostname": None, "uptime_seconds": None, "boot_time": None}
    rec["collected_at"] = iso(ctx.now)
    host = _read(ctx, res, "/proc/sys/kernel/hostname")
    rec["hostname"] = host.strip() if host else os.uname().nodename
    up = _read(ctx, res, "/proc/uptime")
    if up:
        try:
            secs = float(up.split()[0])
            rec["uptime_seconds"] = int(secs)
            rec["boot_time"] = epoch_to_iso(ctx.now.timestamp() - secs)
        except (ValueError, IndexError):
            res.error("/proc/uptime", "parse_error", "unexpected format")
    sec: dict[str, str] = {}
    for key, path in _SECURITY_FILES.items():
        try:
            sec[key] = ctx.path(path).read_text().strip()[:100]
        except OSError:
            pass  # absence is normal for features the kernel does not provide
    rec["security_settings"] = sec
    res.records.append(rec)

    mounts = _read(ctx, res, "/proc/self/mounts")
    count = 0
    if mounts:
        for line in mounts.splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            fstype = f[2]
            real = fstype not in _PSEUDO_FS and fstype != "tmpfs" or f[1] in ("/tmp", "/dev/shm", "/run")
            mrec: dict[str, Any] = {
                "kind": "mount",
                "device": f[0],
                "mountpoint": f[1],
                "fstype": fstype,
                "options": f[3].split(","),
                "noexec": "noexec" in f[3].split(","),
            }
            if real and ctx.root == type(ctx.root)("/"):
                try:
                    u = shutil.disk_usage(f[1])
                    mrec.update(total_bytes=u.total, free_bytes=u.free)
                except OSError:
                    pass
            if real or mrec["mountpoint"] in ("/tmp", "/dev/shm", "/var/tmp"):
                res.records.append(mrec)
                count += 1
            if count >= 300:
                res.notes.append("mount list truncated at 300 entries")
                break

    who = ctx.run(["who"])
    if who.error_kind:
        res.error("who", who.error_kind, who.error or "who failed")
    else:
        for line in who.stdout.splitlines()[:200]:
            f = line.split()
            if len(f) >= 3:
                res.records.append(
                    {
                        "kind": "session",
                        "user": f[0],
                        "tty": f[1],
                        "login": " ".join(f[2:4]),
                        "from": f[-1].strip("()") if f[-1].startswith("(") else None,
                    }
                )
        res.sources.append("who")
    fm = ctx.run(["findmnt", "--json"])
    if fm.error_kind == "not_found":
        res.notes.append("findmnt unavailable; mounts taken from /proc/self/mounts only")
    elif fm.error_kind:
        res.error("findmnt", fm.error_kind, fm.error or "findmnt failed")
    res.finalize()
    return res
