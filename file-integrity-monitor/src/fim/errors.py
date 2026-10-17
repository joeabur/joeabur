"""Exception hierarchy. The CLI maps these to documented exit codes."""

from __future__ import annotations


class FimError(Exception):
    """Base class for all expected, user-reportable failures."""


class ConfigError(FimError):
    """Configuration is malformed or unsafe."""


class BaselineError(FimError):
    """Baseline is missing, corrupt, or cannot be written safely."""


class TrustError(FimError):
    """Baseline integrity or signature verification failed: do not trust the baseline."""


class LockError(FimError):
    """Another FIM operation holds the baseline lock."""


class DependencyError(FimError):
    """An optional dependency is not installed."""


class WatcherError(FimError):
    """The filesystem watcher could not be started (e.g. inotify limits)."""
