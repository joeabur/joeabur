"""Common adapter machinery: discovery, version gating, execution, report parsing."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..config import Config
from ..errors import (
    CommandCancelledError,
    CommandTimeoutError,
    ExecutableNotFoundError,
    MalformedOutputError,
    OutputLimitExceededError,
    ScannerError,
)
from ..redaction import sanitize
from ..runner import (
    CommandResult,
    build_env,
    read_bounded_file,
    resolve_executable,
    run_command,
)
from ..schemas import Finding, ScannerRun, ScannerStatus, Severity

log = logging.getLogger("reposcan.adapters")
_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
VERSION_TIMEOUT = 30.0


@dataclass
class ScanContext:
    """Everything an adapter needs for one scan; built by the orchestrator."""

    target: Path
    workdir: Path
    config: Config
    offline: bool
    timeout: float
    max_output_bytes: int
    history: bool = False
    image: str | None = None
    cancel: threading.Event | None = None
    allow_repo_ignore_files: bool = False
    env_overrides: dict[str, str] = field(default_factory=dict)

    @property
    def unknown_severity(self) -> Severity:
        return self.config.scan.unknown_severity

    def env(self) -> dict[str, str]:
        overrides = {"TMPDIR": str(self.workdir), **self.env_overrides}
        return build_env(self.config.scan.env_passthrough, overrides)


@dataclass
class AdapterOutcome:
    run: ScannerRun
    findings: list[Finding]


def display_arg(arg: str, ctx: ScanContext) -> str:
    """Render one argv element for reports: stable across runs, without local path details."""
    workdir, target = str(ctx.workdir), str(ctx.target)
    if arg == target:
        return "<target>"
    if arg.startswith(workdir):
        return "<workdir>" + arg[len(workdir) :]
    if arg.startswith(target + os.sep):
        return "<target>" + arg[len(target) :]
    if os.path.isabs(arg):
        return "<path>/" + os.path.basename(arg)
    return sanitize(arg, limit=160)


def parse_version(text: str) -> str | None:
    match = _SEMVER_RE.search(text)
    return match.group(0) if match else None


class ScannerAdapter(ABC):
    """Base class. Subclasses only describe the CLI and translate the report."""

    name: str
    executable: str
    version_args: Sequence[str] = ("--version",)
    supported: str  # PEP 440 specifier, e.g. ">=8.18,<9"
    tested: str  # newest version this project's tests were run against
    ok_exit_codes: frozenset[int] = frozenset({0})
    report_filename = "report.json"
    # Environment pinned for this tool (for example to switch off update checks and telemetry).
    extra_env: dict[str, str] = {}  # noqa: RUF012 - read-only class constant

    # ---- hooks -------------------------------------------------------------------
    @abstractmethod
    def build_argv(self, ctx: ScanContext, exe: str, report: Path) -> list[str]:
        """Return the full argv (list form, never a shell string)."""

    @abstractmethod
    def parse(self, data: Any, ctx: ScanContext) -> list[Finding]:
        """Translate the decoded JSON report into unified findings."""

    def preflight(self, ctx: ScanContext) -> list[str]:
        """Raise ScannerError when the scan must not proceed; return warnings otherwise."""
        return []

    def classify_exit(self, result: CommandResult) -> str | None:
        """Return an error message when the exit code means failure, else None."""
        if result.returncode in self.ok_exit_codes:
            return None
        return f"{self.name} exited with unexpected status {result.returncode}"

    # ---- discovery -----------------------------------------------------------------
    def discover(self, ctx: ScanContext | None = None, *, forbidden: Path | None = None) -> tuple[str, str]:
        """Return (absolute executable, detected version) or raise ScannerError."""
        env = self._env(ctx)
        exe = resolve_executable(self.executable, env, forbidden_root=forbidden)
        workdir = ctx.workdir if ctx else Path("/")
        result = run_command(
            [exe, *self.version_args],
            cwd=workdir,
            env=env,
            timeout=VERSION_TIMEOUT,
            max_output_bytes=65536,
        )
        version = parse_version(result.stdout + "\n" + result.stderr)
        if result.returncode != 0 or version is None:
            raise ScannerError(f"could not determine the {self.name} version")
        return exe, version

    def _env(self, ctx: ScanContext | None) -> dict[str, str]:
        env = ctx.env() if ctx else build_env()
        env.update(self.extra_env)
        return env

    def version_supported(self, version: str) -> bool:
        try:
            return Version(version) in SpecifierSet(self.supported)
        except (InvalidVersion, InvalidSpecifier):
            return False

    # ---- execution -----------------------------------------------------------------
    def run(self, ctx: ScanContext) -> AdapterOutcome:
        base = ScannerRun(
            name=self.name,
            status="failed",
            supported_versions=self.supported,
            tested_version=self.tested,
        )

        def fail(status: ScannerStatus, message: str, **extra: Any) -> AdapterOutcome:
            data = base.model_copy(update={"status": status, "error": sanitize(message, limit=600), **extra})
            return AdapterOutcome(data, [])

        try:
            exe, version = self.discover(ctx, forbidden=ctx.target)
        except ExecutableNotFoundError as exc:
            return fail("not_found", str(exc))
        except CommandCancelledError:
            return fail("cancelled", "scan cancelled")
        except CommandTimeoutError as exc:
            return fail("timeout", str(exc))
        except ScannerError as exc:
            return fail("failed", str(exc))
        base = base.model_copy(update={"version": version})
        if not self.version_supported(version):
            message = (
                f"{self.name} {version} is outside the supported range {self.supported} "
                f"(tested with {self.tested})"
            )
            if ctx.config.scan.version_policy == "enforce":
                return fail("version_mismatch", message, version=version)
            base.warnings.append(message)
        try:
            base.warnings.extend(self.preflight(ctx))
        except ScannerError as exc:
            return fail("failed", str(exc), version=version)

        report = ctx.workdir / f"{self.name}-{self.report_filename}"
        argv = self.build_argv(ctx, exe, report)
        shown = [Path(argv[0]).name, *[display_arg(a, ctx) for a in argv[1:]]]
        base = base.model_copy(update={"command": shown})
        try:
            result = run_command(
                argv,
                cwd=ctx.workdir,
                env=self._env(ctx),
                timeout=ctx.timeout,
                max_output_bytes=ctx.max_output_bytes,
                cancel=ctx.cancel,
            )
        except CommandCancelledError:
            return fail("cancelled", "scan cancelled", version=version, command=shown)
        except CommandTimeoutError as exc:
            return fail("timeout", str(exc), version=version, command=shown)
        except (OutputLimitExceededError, ExecutableNotFoundError) as exc:
            return fail("failed", str(exc), version=version, command=shown)

        base = base.model_copy(
            update={"exit_code": result.returncode, "duration_seconds": result.duration_seconds}
        )
        problem = self.classify_exit(result)
        if problem:
            tail = sanitize(result.stderr.strip()[-500:], limit=500)
            detail = f"{problem}: {tail}" if tail else problem
            return AdapterOutcome(
                base.model_copy(update={"status": "failed", "error": sanitize(detail, limit=700)}),
                [],
            )
        try:
            raw = read_bounded_file(report, ctx.max_output_bytes)
        except FileNotFoundError:
            return AdapterOutcome(
                base.model_copy(
                    update={
                        "status": "failed",
                        "error": f"{self.name} did not produce a report file",
                    }
                ),
                [],
            )
        except OutputLimitExceededError as exc:
            return AdapterOutcome(base.model_copy(update={"status": "failed", "error": str(exc)}), [])
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return AdapterOutcome(
                base.model_copy(
                    update={
                        "status": "malformed_output",
                        "error": f"{self.name} report is not valid JSON",
                    }
                ),
                [],
            )
        try:
            findings = self.parse(data, ctx)
        except MalformedOutputError as exc:
            return AdapterOutcome(
                base.model_copy(
                    update={
                        "status": "malformed_output",
                        "error": sanitize(
                            f"{self.name} report has an unexpected structure: {exc}", limit=300
                        ),
                    }
                ),
                [],
            )
        except ScannerError as exc:
            return AdapterOutcome(
                base.model_copy(update={"status": "failed", "error": sanitize(str(exc), limit=400)}),
                [],
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return AdapterOutcome(
                base.model_copy(
                    update={
                        "status": "malformed_output",
                        "error": sanitize(
                            f"{self.name} report has an unexpected structure: {type(exc).__name__}",
                            limit=300,
                        ),
                    }
                ),
                [],
            )
        return AdapterOutcome(
            base.model_copy(update={"status": "ok", "finding_count": len(findings)}), findings
        )


# ---- small helpers shared by adapters -------------------------------------------------


class Occurrences:
    """Numbers repeated (rule, file, evidence) hits so identical lines stay distinct."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, ...], int] = {}

    def next(self, *key: str) -> int:
        n = self._seen.get(key, 0)
        self._seen[key] = n + 1
        return n


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise MalformedOutputError("expected a list")
    return value


def as_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedOutputError("expected an object")
    return value


def as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
