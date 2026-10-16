"""Streaming SHA-256 over an already-open file descriptor.

The caller opens the file (so it can apply O_NOFOLLOW and compare inodes); this module only
reads. Files are never loaded into memory and are never opened for writing.
"""

from __future__ import annotations

import hashlib
import os


class HashAborted(Exception):
    """Raised when more bytes are read than the caller allowed (file grew while hashing)."""


def hash_fd(fd: int, *, chunk_size: int, byte_limit: int | None = None) -> tuple[str, int]:
    """Return ``(hex sha256, bytes_read)`` reading ``fd`` to EOF in ``chunk_size`` pieces."""
    h = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if byte_limit is not None and total > byte_limit:
            raise HashAborted(f"read more than {byte_limit} bytes")
        h.update(chunk)
    return h.hexdigest(), total


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
