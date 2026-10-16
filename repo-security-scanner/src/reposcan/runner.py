"""Safe subprocess execution.

Rules enforced here for every external tool:

* ``shell=False`` with an argument *list*; no string interpolation anywhere.
* A minimal, allow-listed environment (no inherited tokens or CI secrets).
* A private working directory that is never the scanned repository.
* Wall-clock timeout, bounded stdout/stderr capture, and cooperative cancellation.
* The whole process group is killed on timeout, overflow or cancellation.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import (
    CommandCancelledError,
    CommandTimeoutError,
    ExecutableNotFoundError,
    OutputLimitExceededError,
)
from .redaction import sanitize

log = logging.getLogger("reposcan.runner")

# Variables copied from the parent environment. Everything else is dropped.
_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "USER",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "TRIVY_CACHE_DIR",
    "SEMGREP_USER_HOME",
)
_POLL_SECONDS = 0.05


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


def build_env(
    passthrough: Sequence[str] = (),
    overrides: Mapping[str, str] | None = None,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the child environment from an allow-list plus explicit pass-through."""
    parent = os.environ if source is None else source
    env = {k: parent[k] for k in (*_ENV_ALLOWLIST, *passthrough) if k in parent}
    env.update(
        {
            "NO_COLOR": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    if overrides:
        env.update(overrides)
    return env


def resolve_executable(name: str, env: Mapping[str, str], *, forbidden_root: Path | None = None) -> str:
    """Find ``name`` on the child PATH; refuse binaries living inside the scan target."""
    if os.sep in name:
        raise ExecutableNotFoundError(f"executable names must not contain path separators: {name}")
    found = shutil.which(name, path=env.get("PATH", os.defpath))
    if not found:
        raise ExecutableNotFoundError(f"{name} is not installed or not on PATH")
    resolved = Path(found).resolve()
    if forbidden_root is not None:
        base = forbidden_root.resolve()
        if base == resolved or base in resolved.parents:
            raise ExecutableNotFoundError(
                f"refusing to run {name} from inside the scan target ({sanitize(str(resolved))})"
            )
    return str(resolved)


class _Collector(threading.Thread):
    """Drain a pipe into a bounded buffer; flag overflow instead of growing."""

    def __init__(self, pipe: object, limit: int, overflow: threading.Event) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._limit = limit
        self._overflow = overflow
        self.data = bytearray()

    def run(self) -> None:
        read = self._pipe.read1 if hasattr(self._pipe, "read1") else self._pipe.read  # type: ignore[attr-defined]
        while True:
            try:
                chunk = read(65536)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            room = self._limit - len(self.data)
            if len(chunk) > room:
                self.data.extend(chunk[: max(room, 0)])
                self._overflow.set()
                return
            self.data.extend(chunk)


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        proc.kill()


def run_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    max_output_bytes: int,
    cancel: threading.Event | None = None,
) -> CommandResult:
    """Run ``argv`` and return its result. Raises typed errors on abnormal ends.

    A non-zero exit status is *not* an error here; callers interpret it per tool.
    """
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty sequence of strings")
    if any("\x00" in a for a in argv):
        raise ValueError("argv elements must not contain NUL bytes")
    display = " ".join(sanitize(a, limit=120) for a in argv[:6])
    log.debug("exec: %s", display)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=dict(env),
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        raise ExecutableNotFoundError(f"executable not found: {sanitize(argv[0], limit=80)}") from None
    except PermissionError:
        raise ExecutableNotFoundError(f"executable is not runnable: {sanitize(argv[0], limit=80)}") from None

    overflow = threading.Event()
    out = _Collector(proc.stdout, max_output_bytes, overflow)
    err = _Collector(proc.stderr, max_output_bytes, overflow)
    out.start()
    err.start()
    deadline = started + timeout
    try:
        while True:
            try:
                proc.wait(timeout=_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                pass
            if cancel is not None and cancel.is_set():
                _kill_group(proc)
                proc.wait()
                raise CommandCancelledError("scan cancelled")
            if overflow.is_set():
                _kill_group(proc)
                proc.wait()
                raise OutputLimitExceededError(
                    f"{sanitize(argv[0], limit=40)} produced more than {max_output_bytes} bytes of output"
                )
            if time.monotonic() > deadline:
                _kill_group(proc)
                proc.wait()
                raise CommandTimeoutError(
                    f"{sanitize(os.path.basename(argv[0]), limit=40)} exceeded the {timeout:g}s timeout"
                )
    except BaseException:
        _kill_group(proc)
        raise
    finally:
        out.join(timeout=2)
        err.join(timeout=2)
        for pipe in (proc.stdout, proc.stderr):
            with contextlib.suppress(Exception):
                if pipe is not None:
                    pipe.close()
    if overflow.is_set():
        raise OutputLimitExceededError(
            f"{sanitize(os.path.basename(argv[0]), limit=40)} produced more than "
            f"{max_output_bytes} bytes of output"
        )
    return CommandResult(
        argv=tuple(argv),
        returncode=proc.returncode,
        stdout=out.data.decode("utf-8", "replace"),
        stderr=err.data.decode("utf-8", "replace"),
        duration_seconds=round(time.monotonic() - started, 3),
    )


def read_bounded_file(path: Path, max_bytes: int) -> bytes:
    """Read a scanner report file, refusing symlinks and oversized files."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise FileNotFoundError(path.name) from None
    try:
        size = os.fstat(fd).st_size
        if size > max_bytes:
            raise OutputLimitExceededError(
                f"report {sanitize(path.name, limit=60)} is {size} bytes (limit {max_bytes})"
            )
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise OutputLimitExceededError(f"report exceeded {max_bytes} bytes")
    return data
