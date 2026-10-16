"""Scanner adapters."""

from __future__ import annotations

from ..config import Config
from .base import ScanContext, ScannerAdapter
from .gitleaks import GitleaksAdapter
from .osv import OsvAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter

ALL_ADAPTERS: tuple[type[ScannerAdapter], ...] = (
    GitleaksAdapter,
    SemgrepAdapter,
    TrivyAdapter,
    OsvAdapter,
)


def adapter_names() -> list[str]:
    return [a.name for a in ALL_ADAPTERS]


def enabled_adapters(config: Config, only: list[str] | None = None) -> list[ScannerAdapter]:
    """Instantiate adapters selected by config (or by an explicit ``only`` list)."""
    flags = {
        "gitleaks": config.scanners.gitleaks.enabled,
        "semgrep": config.scanners.semgrep.enabled,
        "trivy": config.scanners.trivy.enabled,
        "osv-scanner": config.scanners.osv.enabled,
    }
    return [a() for a in ALL_ADAPTERS if (a.name in only if only else flags[a.name])]


__all__ = ["ALL_ADAPTERS", "ScanContext", "ScannerAdapter", "adapter_names", "enabled_adapters"]
