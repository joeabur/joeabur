"""Collection context: injectable filesystem root and command runner for testability."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .utils.paths import sha256_file
from .utils.redact import Redactor
from .utils.run import CommandResult, run_command
from .utils.timeutil import utcnow

Runner = Callable[[list[str], float, int], CommandResult]


@dataclass
class Context:
    config: dict[str, Any]
    redactor: Redactor
    deep: bool = False
    root: Path = Path("/")
    runner: Runner = run_command
    now: datetime = field(default_factory=utcnow)
    home: Path | None = None
    import_logs: list[Path] = field(default_factory=list)  # exported ndjson files
    import_archives: list[Path] = field(default_factory=list)  # .logarchive bundles
    log_window_hours: int = 24
    hostname: str | None = None

    def path(self, absolute: str) -> Path:
        """Map an absolute system path under the (possibly fake) filesystem root."""
        return self.root / absolute.lstrip("/")

    def display(self, p: Path) -> str:
        try:
            return "/" + p.relative_to(self.root).as_posix()
        except ValueError:
            return str(p)

    @property
    def user_home(self) -> Path:
        return self.home if self.home is not None else Path(os.path.expanduser("~"))

    def limit(self, name: str) -> int:
        return int(self.config["limits"][name])

    def run(self, argv: list[str]) -> CommandResult:
        return self.runner(argv, float(self.limit("command_timeout_seconds")), self.limit("max_command_output_bytes"))

    def hash_file(self, p: Path) -> tuple[str | None, str | None]:
        """Return (sha256, error_message). Never executes the file."""
        try:
            return sha256_file(p, self.limit("max_hash_bytes")), None
        except PermissionError:
            return None, "permission denied"
        except FileNotFoundError:
            return None, "not found"
        except (OSError, ValueError) as exc:
            return None, str(exc)
