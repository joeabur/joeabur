"""Path validation and glob matching. Pure functions, no filesystem writes."""

from __future__ import annotations

import os
import re
from functools import lru_cache

from fim.errors import ConfigError


def validate_abs_path(value: str, *, what: str = "path") -> str:
    """Return a normalised absolute path or raise ConfigError.

    Rejects relative paths, NUL bytes and any ``..`` segment (before normalisation, so
    ``/etc/../root`` is an error rather than silently becoming ``/root``).
    """
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{what} must be a non-empty string")
    if "\x00" in value:
        raise ConfigError(f"{what} contains a NUL byte")
    if not value.startswith("/"):
        raise ConfigError(f"{what} must be absolute: {value!r}")
    if ".." in value.split("/"):
        raise ConfigError(f"{what} must not contain '..' segments: {value!r}")
    return os.path.normpath(value) if value != "/" else "/"


def is_within(path: str, parent: str) -> bool:
    """True if ``path`` equals ``parent`` or is below it (lexical, on normalised paths)."""
    if parent == "/":
        return True
    return path == parent or path.startswith(parent + "/")


def real_within(path: str, parent: str) -> bool:
    """Like is_within but after resolving symlinks on both sides."""
    return is_within(os.path.realpath(path), os.path.realpath(parent))


@lru_cache(maxsize=1024)
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate an absolute glob to a regex.

    ``*`` and ``?`` never cross ``/``; ``**`` crosses it; ``**/`` may match nothing.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                if pattern.startswith("**/", i):
                    out.append("(?:.*/)?")
                    i += 3
                else:
                    out.append(".*")
                    i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out), re.DOTALL)


def validate_glob(pattern: str) -> str:
    if "\x00" in pattern:
        raise ConfigError("glob contains a NUL byte")
    if not pattern.startswith("/"):
        raise ConfigError(f"glob must be absolute (start with '/'): {pattern!r}")
    if ".." in pattern.split("/"):
        raise ConfigError(f"glob must not contain '..' segments: {pattern!r}")
    return pattern


def matches_any(path: str, patterns: list[str], *, is_dir: bool = False) -> bool:
    """Match ``path`` against absolute globs. Directories also match with a trailing slash so
    that ``/var/log/**`` prunes ``/var/log`` itself."""
    for pat in patterns:
        rx = glob_to_regex(pat)
        if rx.fullmatch(path) or (is_dir and rx.fullmatch(path + "/")):
            return True
    return False
