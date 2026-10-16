"""Safe report file output."""

from __future__ import annotations

import os
from pathlib import Path

from ..errors import ConfigError
from ..schemas import ScanResult
from .html_report import render_html
from .json_report import render_json
from .markdown import render_codequality, render_github_annotations, render_markdown
from .sarif import render_sarif

FORMATS = {
    "json": ("reposcan-report.json", render_json),
    "html": ("reposcan-report.html", render_html),
    "sarif": ("reposcan.sarif", render_sarif),
    "md": ("reposcan-summary.md", render_markdown),
    "codequality": ("gl-code-quality-report.json", render_codequality),
}


def write_text_safely(directory: Path, name: str, text: str) -> Path:
    """Write ``text`` to ``directory/name`` (0600), refusing symlinks, replacing atomically."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination = directory / name
    if destination.is_symlink():
        raise ConfigError(f"refusing to write through a symbolic link: {name}")
    tmp = directory / f".{name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, destination)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return destination


def write_reports(result: ScanResult, directory: Path, formats: list[str]) -> list[Path]:
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ConfigError(
            f"unknown report format(s): {', '.join(sorted(unknown))}; choose from {', '.join(FORMATS)}"
        )
    written = []
    for fmt in formats:
        name, render = FORMATS[fmt]
        written.append(write_text_safely(directory, name, render(result)))
    return written


__all__ = ["FORMATS", "render_github_annotations", "write_reports", "write_text_safely"]
