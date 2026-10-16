"""Path safety, hashing and exclusive file creation."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path
from typing import Any

try:  # pwd is POSIX-only; analysis code stays importable on other systems
    import pwd
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]

from .timeutil import epoch_to_iso


class UnsafePathError(ValueError):
    pass


def safe_join(base: Path, rel: str) -> Path:
    """Join ``rel`` to ``base`` refusing absolute paths and traversal."""
    if not rel or os.path.isabs(rel) or "\x00" in rel:
        raise UnsafePathError(f"unsafe relative path: {rel!r}")
    parts = Path(rel).parts
    if ".." in parts:
        raise UnsafePathError(f"path traversal rejected: {rel!r}")
    target = base.joinpath(*parts)
    resolved_base = base.resolve()
    if not target.resolve().is_relative_to(resolved_base):
        raise UnsafePathError(f"path escapes base directory: {rel!r}")
    return target


def sha256_file(path: Path, max_bytes: int | None = None) -> str:
    """Stream a SHA-256. Raises ValueError if the file exceeds ``max_bytes``."""
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"file larger than hash limit ({max_bytes} bytes)")
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def create_unique_dir(parent: Path, prefix: str) -> Path:
    """Create a new 0700 directory under ``parent``; never reuses an existing one."""
    create_private_dir(parent)
    for _ in range(20):
        candidate = parent / f"{prefix}-{secrets.token_hex(3)}"
        try:
            os.mkdir(candidate, 0o700)
            return candidate
        except FileExistsError:
            continue
    raise FileExistsError("could not allocate a unique output directory")


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create ``path`` with O_EXCL (never overwrites, never follows a final symlink)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _owner(uid: int) -> str | None:
    if pwd is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def file_metadata(path: Path, display: str | None = None) -> dict[str, Any]:
    """lstat-based metadata that never follows symlinks."""
    st = os.lstat(path)
    mode = st.st_mode
    meta: dict[str, Any] = {
        "path": display or str(path),
        "type": "symlink"
        if stat.S_ISLNK(mode)
        else "dir"
        if stat.S_ISDIR(mode)
        else "file"
        if stat.S_ISREG(mode)
        else "other",
        "mode": format(stat.S_IMODE(mode), "04o"),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "owner": _owner(st.st_uid),
        "size": st.st_size,
        "mtime": epoch_to_iso(st.st_mtime),
        "world_writable": bool(mode & stat.S_IWOTH),
        "world_readable": bool(mode & stat.S_IROTH),
    }
    if stat.S_ISLNK(mode):
        try:
            meta["symlink_target"] = os.readlink(path)
        except OSError:
            meta["symlink_target"] = None
    return meta
