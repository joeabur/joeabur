"""Validation of untrusted paths, output locations and image references."""

from __future__ import annotations

import os
import re
import stat
from collections import Counter
from pathlib import Path, PurePosixPath

from .errors import ConfigError
from .redaction import sanitize
from .schemas import ScanScope

MAX_PATH_CHARS = 4096
MAX_FILES_WALKED = 200_000
MAX_CONFIG_BYTES = 1_048_576
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,254}$")


def _check_raw(raw: str, what: str) -> None:
    if not raw or not raw.strip():
        raise ConfigError(f"{what} must not be empty")
    if "\x00" in raw:
        raise ConfigError(f"{what} must not contain NUL bytes")
    if len(raw) > MAX_PATH_CHARS:
        raise ConfigError(f"{what} is longer than {MAX_PATH_CHARS} characters")


def validate_target(raw: str) -> Path:
    """Resolve and validate the scan target (a directory, or a single file)."""
    _check_raw(raw, "scan path")
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        raise ConfigError(f"scan path does not exist: {sanitize(raw, limit=200)}") from None
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"scan path cannot be resolved: {sanitize(str(exc), limit=200)}") from None
    if resolved == Path(resolved.anchor):
        raise ConfigError("refusing to scan the filesystem root; pass a repository directory")
    if not (resolved.is_dir() or resolved.is_file()):
        raise ConfigError("scan path must be a regular file or directory")
    if not os.access(resolved, os.R_OK):
        raise ConfigError("scan path is not readable")
    return resolved


def validate_output_dir(raw: str, *, target: Path) -> tuple[Path, list[str]]:
    """Validate (without creating) the report directory; returns warnings."""
    _check_raw(raw, "output directory")
    out = Path(raw).expanduser()
    if out.is_symlink():
        raise ConfigError("output directory must not be a symbolic link")
    resolved = out.resolve()
    if resolved.exists() and not resolved.is_dir():
        raise ConfigError("output path exists and is not a directory")
    warnings: list[str] = []
    base = target if target.is_dir() else target.parent
    if resolved == base or base in resolved.parents:
        warnings.append(
            "output directory is inside the scan target; reports may be rescanned or committed. "
            "Write reports outside the repository when possible."
        )
    return resolved, warnings


def validate_file_arg(raw: str, what: str, *, max_bytes: int = MAX_CONFIG_BYTES) -> Path:
    """Validate an input file (config, baseline, report) before opening it."""
    _check_raw(raw, what)
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve(strict=True)
        st = resolved.stat()
    except OSError:
        raise ConfigError(f"{what} not found: {sanitize(raw, limit=200)}") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{what} must be a regular file")
    if st.st_size > max_bytes:
        raise ConfigError(f"{what} is larger than {max_bytes} bytes")
    return resolved


def validate_image_ref(raw: str) -> str:
    """Accept only conservative container image references (no option injection)."""
    _check_raw(raw, "image reference")
    if not _IMAGE_RE.match(raw) or ".." in raw:
        raise ConfigError(f"invalid container image reference: {sanitize(raw, limit=100)}")
    return raw


def relative_to_root(raw: str, root: Path) -> str | None:
    """Return a sanitised POSIX path relative to ``root`` or ``None`` if outside it."""
    base = root if root.is_dir() else root.parent
    try:
        candidate = Path(raw)
        rel = candidate.relative_to(base) if candidate.is_absolute() else candidate
        parts = PurePosixPath(rel.as_posix()).parts
    except ValueError:
        return None
    if ".." in parts:
        return None
    text = "/".join(p for p in parts if p not in ("", "."))
    return sanitize(text, limit=500) if text else root.name


def read_source_line(root: Path, rel: str, line: int, *, max_bytes: int = 2_000_000) -> str | None:
    """Read one line of a file under ``root`` without following symlinks out of it."""
    base = root if root.is_dir() else root.parent
    target = base / rel
    try:
        real = target.resolve(strict=True)
        if base.resolve() not in (real, *real.parents):
            return None
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            for number, raw_line in enumerate(fh, start=1):
                if number == line:
                    return raw_line.decode("utf-8", "replace").rstrip("\r\n")
    finally:
        os.close(fd)
    return None


def find_text_directives(
    root: Path,
    pattern: re.Pattern[str],
    *,
    suffixes: tuple[str, ...],
    names: tuple[str, ...] = (),
    max_files: int = 50_000,
    max_file_bytes: int = 1_048_576,
) -> list[str]:
    """Relative paths of files under ``root`` whose text matches ``pattern`` (bounded, no symlinks)."""
    base = root if root.is_dir() else root.parent
    stack = [root] if root.is_dir() else []
    candidates = [root] if root.is_file() else []
    seen = 0
    while stack and seen < max_files:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name != ".git":
                            stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        seen += 1
                        lower = entry.name.lower()
                        if lower.endswith(suffixes) or any(lower.startswith(n) for n in names):
                            candidates.append(Path(entry.path))
        except OSError:
            continue
    hits: list[str] = []
    for path in sorted(candidates):
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if pattern.search(text):
            rel = relative_to_root(str(path), root if root.is_dir() else base)
            hits.append(rel or path.name)
    return hits


def summarize_scope(target: Path, *, is_git: bool | None = None) -> ScanScope:
    """Walk the target (never following symlinks) to describe what will be scanned."""
    files = 0
    size = 0
    links = 0
    truncated = False
    exts: Counter[str] = Counter()
    if target.is_file():
        files, size = 1, target.stat().st_size
        exts[target.suffix.lower() or "(none)"] += 1
        base = target.parent
    else:
        base = target
        stack = [target]
        while stack and not truncated:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if entry.is_symlink():
                            links += 1
                        elif entry.is_dir(follow_symlinks=False):
                            if entry.name != ".git":
                                stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            size += entry.stat(follow_symlinks=False).st_size
                            exts[Path(entry.name).suffix.lower() or "(none)"] += 1
                            if files >= MAX_FILES_WALKED:
                                truncated = True
                                break
            except OSError:
                continue
    return ScanScope(
        target=sanitize(target.name or str(target), limit=200),
        is_git_repository=(base / ".git").exists() if is_git is None else is_git,
        file_count=files,
        total_bytes=size,
        symlinks_skipped=links,
        top_extensions=dict(sorted(exts.most_common(8), key=lambda kv: (-kv[1], kv[0]))),
        truncated=truncated,
    )
