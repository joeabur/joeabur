"""Bounded, shell-free subprocess execution (read-only helpers only)."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    error_kind: str | None = None  # not_found | permission_denied | timeout | other
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error_kind is None and self.returncode == 0


def run_command(argv: list[str], timeout: float = 15.0, max_bytes: int = 2_000_000) -> CommandResult:
    """Run ``argv`` without a shell, with a timeout and an output cap.

    The executable is resolved with ``shutil.which``; nothing is ever installed.
    Output beyond ``max_bytes`` is discarded and the child is terminated.
    """
    res = CommandResult(argv=list(argv))
    exe = shutil.which(argv[0])
    if exe is None:
        res.error_kind, res.error = "not_found", f"{argv[0]}: command not found"
        return res
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
    try:
        proc = subprocess.Popen(
            [exe, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            shell=False,
        )
    except PermissionError as exc:
        res.error_kind, res.error = "permission_denied", str(exc)
        return res
    except OSError as exc:
        res.error_kind, res.error = "other", str(exc)
        return res

    chunks: list[bytes] = []
    state = {"size": 0, "truncated": False}

    def reader() -> None:
        if proc.stdout is None:
            return
        while True:
            data = proc.stdout.read(65536)
            if not data:
                return
            room = max_bytes - state["size"]
            if room <= 0:
                state["truncated"] = True
                proc.kill()
                return
            chunks.append(data[:room])
            state["size"] += min(len(data), room)
            if len(data) > room:
                state["truncated"] = True
                proc.kill()
                return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        proc.kill()
        res.timed_out = True
        res.error_kind, res.error = "timeout", f"{argv[0]} exceeded {timeout}s"
        t.join(2)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    res.returncode = proc.returncode
    err = b""
    try:
        if proc.stderr:
            err = proc.stderr.read(8192)
    except (OSError, ValueError):
        pass
    res.stdout = b"".join(chunks).decode("utf-8", errors="replace")
    res.stderr = err.decode("utf-8", errors="replace")
    res.truncated = bool(state["truncated"])
    if res.truncated:
        res.notes.append(f"output truncated at {max_bytes} bytes")
    if res.error_kind is None and res.returncode not in (0, None) and not res.truncated:
        low = res.stderr.lower()
        if "permission denied" in low or "operation not permitted" in low or "not permitted" in low:
            res.error_kind, res.error = "permission_denied", res.stderr.strip()[:300]
    return res


def euid() -> int:
    """Effective uid, or -1 on platforms without POSIX ids."""
    return os.geteuid() if hasattr(os, "geteuid") else -1
