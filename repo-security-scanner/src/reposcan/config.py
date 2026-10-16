"""Configuration models and TOML loading.

Configuration is **never** discovered inside the scanned repository: the scanned
content is untrusted and must not be able to weaken its own scan.
"""

from __future__ import annotations

import tomllib
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .errors import ConfigError
from .paths import validate_file_arg
from .redaction import sanitize
from .schemas import AcceptedEntry, Severity


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanSettings(Strict):
    timeout_seconds: int = Field(default=600, ge=1, le=7200)
    max_output_bytes: int = Field(default=64 * 1024 * 1024, ge=1024, le=1024**3)
    offline: bool = False
    version_policy: Literal["enforce", "warn"] = "enforce"
    history: bool = False
    unknown_severity: Severity = Severity.MEDIUM
    env_passthrough: list[str] = Field(default_factory=list)

    @field_validator("env_passthrough")
    @classmethod
    def _env_names(cls, names: list[str]) -> list[str]:
        for name in names:
            if not name.replace("_", "").isalnum() or name.startswith("-"):
                raise ValueError(f"invalid environment variable name: {name!r}")
        return names


class PolicySettings(Strict):
    fail_on: Literal["critical", "high", "medium", "low", "info", "none"] = "high"
    fail_on_baseline: bool = False
    require_expiry_at_or_above: Literal["critical", "high", "medium", "low", "info", "none"] = "critical"
    max_accept_days: int = Field(default=365, ge=1, le=3650)


class GitleaksSettings(Strict):
    enabled: bool = True
    config: str | None = None


class SemgrepSettings(Strict):
    enabled: bool = True
    rules: list[str] = Field(default_factory=list)
    allow_remote_rules: bool = False


class TrivySettings(Strict):
    enabled: bool = True
    scanners: list[Literal["vuln", "misconfig", "secret"]] = Field(default=["vuln", "misconfig"])


class OsvSettings(Strict):
    enabled: bool = False
    # "api": package names/versions are sent to api.osv.dev.
    # "local-db": advisory archives are downloaded and queried locally (nothing is sent).
    mode: Literal["api", "local-db"] = "api"
    allow_network_resolution: bool = False


class ScannerSettings(Strict):
    gitleaks: GitleaksSettings = Field(default_factory=GitleaksSettings)
    semgrep: SemgrepSettings = Field(default_factory=SemgrepSettings)
    trivy: TrivySettings = Field(default_factory=TrivySettings)
    osv: OsvSettings = Field(default_factory=OsvSettings)


class Suppression(AcceptedEntry):
    """Rule-level suppression. Match by ``fingerprint`` or by ``rule_id`` (+ ``path``)."""

    fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    rule_id: str | None = Field(default=None, max_length=300)
    scanner: str | None = Field(default=None, max_length=50)
    path: str | None = Field(default=None, max_length=500)

    def model_post_init(self, _ctx: object) -> None:
        if not self.fingerprint and not self.rule_id:
            raise ValueError("a suppression needs a fingerprint or a rule_id")


class Config(Strict):
    scan: ScanSettings = Field(default_factory=ScanSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    scanners: ScannerSettings = Field(default_factory=ScannerSettings)
    suppressions: list[Suppression] = Field(default_factory=list)
    # Filled in by load_config; not part of the file format.
    base_dir: Path | None = Field(default=None, exclude=True)
    source: str = Field(default="built-in defaults", exclude=True)


def data_path(name: str) -> Path:
    """Path of a bundled data file (scanner configs and rule packs)."""
    return Path(str(resources.files("reposcan") / "data" / name))


def load_config(path: str | None) -> Config:
    """Load a TOML config (or built-in defaults when ``path`` is None)."""
    if path is None:
        return Config()
    file = validate_file_arg(path, "config file")
    try:
        raw = tomllib.loads(file.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"config file is not valid TOML: {sanitize(str(exc), limit=300)}") from None
    try:
        config = Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration: {format_validation_error(exc)}") from None
    config.base_dir = file.parent
    config.source = str(file.name)
    return config


def format_validation_error(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:8]:
        loc = ".".join(str(p) for p in err["loc"])
        parts.append(f"{loc}: {sanitize(str(err['msg']), limit=160)}")
    return "; ".join(parts)


def is_expired(expires: date | None, today: date) -> bool:
    return expires is not None and expires < today
