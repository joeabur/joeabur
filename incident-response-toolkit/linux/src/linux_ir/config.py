"""Configuration defaults and strict validation."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

COLLECTOR_NAMES = ("inventory", "processes", "network", "persistence", "logs", "files")

DEFAULT_REDACTION_PATTERNS: list[dict[str, str]] = [
    {
        "name": "authorization-header",
        "pattern": r"(?i)\b(authorization)(\s*[=:]\s*)(?:(?:bearer|basic|token|negotiate)\s+)?\S+",
        "replacement": r"\1\2[REDACTED]",
    },
    {
        "name": "keyword-assignment",
        "pattern": r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)(\s*[=:]\s*|\s+)(\S+)",
        "replacement": r"\1\2[REDACTED]",
    },
    {
        "name": "cli-secret-flag",
        "pattern": r"(?i)(--?(?:password|passwd|token|secret|api-key|apikey))(=|\s+)\S+",
        "replacement": r"\1\2[REDACTED]",
    },
    {"name": "url-credentials", "pattern": r"://[^/\s:@]+:[^/\s@]+@", "replacement": "://[REDACTED]@"},
    {"name": "bearer", "pattern": r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", "replacement": "Bearer [REDACTED]"},
    {"name": "aws-access-key", "pattern": r"\bAKIA[0-9A-Z]{16}\b", "replacement": "[REDACTED-AWS-KEY]"},
]

DEFAULTS: dict[str, Any] = {
    "limits": {
        "command_timeout_seconds": 15,
        "max_command_output_bytes": 2_000_000,
        "max_processes": 5000,
        "max_hash_bytes": 104_857_600,
        "max_log_lines": 5000,
        "max_log_file_bytes": 5_000_000,
        "max_records_per_artifact": 20000,
        "max_walk_entries": 500,
    },
    "profiles": {
        "basic": {
            "collectors": ["inventory", "processes", "network", "persistence", "logs"],
            "deep": False,
        },
        "extended": {
            "collectors": list(COLLECTOR_NAMES),
            "deep": True,
        },
    },
    "logs": {"window_hours": 24},
    "redaction": {"enabled": True, "patterns": DEFAULT_REDACTION_PATTERNS, "extra_patterns": []},
    "detection": {"max_findings_per_rule": 200, "max_regex_input_chars": 2048, "max_records": 200000},
    "ioc": {"match_subdomains": False, "case_insensitive_paths": False},
}


class ConfigError(ValueError):
    pass


def _merge(base: dict[str, Any], over: dict[str, Any], path: str = "") -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, val in over.items():
        here = f"{path}.{key}" if path else key
        if key not in base:
            raise ConfigError(f"unknown configuration key: {here}")
        if isinstance(base[key], dict) and key != "profiles":
            if not isinstance(val, dict):
                raise ConfigError(f"{here} must be a mapping")
            out[key] = _merge(base[key], val, here)
        else:
            if key == "profiles":
                if not isinstance(val, dict):
                    raise ConfigError("profiles must be a mapping")
                out[key] = {**base[key], **val}
                continue
            exp = type(base[key])
            if exp is int and (isinstance(val, bool) or not isinstance(val, int)):
                raise ConfigError(f"{here} must be an integer")
            if exp is not int and not isinstance(val, exp):
                raise ConfigError(f"{here} must be of type {exp.__name__}")
            out[key] = val
    return out


def validate(cfg: dict[str, Any]) -> None:
    for k, v in cfg["limits"].items():
        if v <= 0:
            raise ConfigError(f"limits.{k} must be a positive integer")
    if not 1 <= cfg["logs"]["window_hours"] <= 24 * 90:
        raise ConfigError("logs.window_hours must be between 1 and 2160")
    for name, prof in cfg["profiles"].items():
        if not isinstance(prof, dict) or set(prof) - {"collectors", "deep"}:
            raise ConfigError(f"profile {name!r} may only contain 'collectors' and 'deep'")
        cols = prof.get("collectors")
        if not isinstance(cols, list) or not cols:
            raise ConfigError(f"profile {name!r}: collectors must be a non-empty list")
        bad = [c for c in cols if c not in COLLECTOR_NAMES]
        if bad:
            raise ConfigError(f"profile {name!r}: unknown collectors {bad}")
        if not isinstance(prof.get("deep", False), bool):
            raise ConfigError(f"profile {name!r}: deep must be boolean")
    import re

    for p in cfg["redaction"]["patterns"] + cfg["redaction"]["extra_patterns"]:
        if not isinstance(p, dict) or "pattern" not in p:
            raise ConfigError("redaction patterns must be mappings with a 'pattern' key")
        if len(p["pattern"]) > 500:
            raise ConfigError("redaction pattern too long (max 500 chars)")
        try:
            re.compile(p["pattern"])
        except re.error as exc:
            raise ConfigError(f"invalid redaction regex {p['pattern']!r}: {exc}") from exc


def load_config(path: Path | None = None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    if path is not None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ConfigError("configuration root must be a mapping")
        cfg = _merge(cfg, raw)
    validate(cfg)
    return cfg


def redaction_patterns(cfg: dict[str, Any]) -> list[dict[str, str]]:
    return list(cfg["redaction"]["patterns"]) + list(cfg["redaction"]["extra_patterns"])
