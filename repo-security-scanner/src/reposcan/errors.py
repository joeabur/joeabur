"""Exit codes and exception types shared across reposcan."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes. Precedence when several apply: 130 > 2 > 4 > 3 > 1 > 0."""

    OK = 0
    POLICY_FAILED = 1
    CONFIG_ERROR = 2
    SCANNER_ERROR = 3
    INTERNAL_ERROR = 4
    CANCELLED = 130


class ReposcanError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code: ExitCode = ExitCode.INTERNAL_ERROR


class ConfigError(ReposcanError):
    """Invalid configuration, path, option or input file."""

    exit_code = ExitCode.CONFIG_ERROR


class ScannerError(ReposcanError):
    """A scanner could not be run or its result could not be trusted."""

    exit_code = ExitCode.SCANNER_ERROR


class CommandError(ScannerError):
    """Base class for subprocess-level failures."""


class ExecutableNotFoundError(CommandError):
    """The executable is not installed or not resolvable."""


class CommandTimeoutError(CommandError):
    """The subprocess exceeded its time limit and was killed."""


class OutputLimitExceededError(CommandError):
    """The subprocess (or its report file) exceeded the output size limit."""


class CommandCancelledError(CommandError):
    """The run was cancelled while the subprocess was active."""

    exit_code = ExitCode.CANCELLED


class MalformedOutputError(ScannerError):
    """Scanner output was not valid JSON or did not match the expected shape."""
