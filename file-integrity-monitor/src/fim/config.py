"""Configuration models (TOML) with strict validation. Unknown keys are rejected."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from fim.errors import ConfigError
from fim.models import EventType, Severity
from fim.pathutil import is_within, validate_abs_path, validate_glob

DEFAULT_SEVERITIES: dict[EventType, Severity] = {
    EventType.ADDED: Severity.MEDIUM,
    EventType.MODIFIED: Severity.HIGH,
    EventType.DELETED: Severity.HIGH,
    EventType.PERMISSION_CHANGED: Severity.HIGH,
    EventType.OWNER_CHANGED: Severity.HIGH,
    EventType.TYPE_CHANGED: Severity.HIGH,
    EventType.SYMLINK_CHANGED: Severity.HIGH,
    EventType.METADATA_CHANGED: Severity.INFO,
    EventType.XATTR_CHANGED: Severity.HIGH,
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BaselineConfig(_Strict):
    dir: str
    keep_versions: int = Field(default=10, ge=2, le=1000)
    public_key: str | None = None
    max_baseline_bytes: int = Field(default=512 * 1024 * 1024, ge=1024)

    @field_validator("dir")
    @classmethod
    def _dir(cls, v: str) -> str:
        return validate_abs_path(v, what="baseline.dir")

    @field_validator("public_key")
    @classmethod
    def _pub(cls, v: str | None) -> str | None:
        return None if v is None else validate_abs_path(v, what="baseline.public_key")


class ScanConfig(_Strict):
    roots: list[str] = Field(min_length=1)
    exclude: list[str] = Field(default_factory=list)
    symlinks: Literal["record", "skip", "follow"] = "record"
    follow_outside_roots: bool = False
    one_file_system: bool = True
    xattrs: bool = True  # record extended attributes (POSIX ACLs, SELinux label, file capabilities)
    max_files: int = Field(default=2_000_000, ge=1)
    max_file_bytes: int = Field(default=1024**3, ge=0, description="0 = unlimited")
    max_depth: int = Field(default=64, ge=1, le=4096)
    timeout_seconds: int = Field(default=3600, ge=0, description="0 = unlimited")
    chunk_size: int = Field(default=1024 * 1024, ge=4096, le=64 * 1024 * 1024)

    @field_validator("roots")
    @classmethod
    def _roots(cls, v: list[str]) -> list[str]:
        out = [validate_abs_path(r, what="scan.roots entry") for r in v]
        return list(dict.fromkeys(out))

    @field_validator("exclude")
    @classmethod
    def _exclude(cls, v: list[str]) -> list[str]:
        return [validate_glob(p) for p in v]


class PolicyRule(_Strict):
    name: str = Field(min_length=1, max_length=100)
    paths: list[str] = Field(min_length=1)
    events: list[EventType] = Field(default_factory=lambda: list(EventType))
    severity: Severity

    @field_validator("paths")
    @classmethod
    def _paths(cls, v: list[str]) -> list[str]:
        return [validate_glob(p) for p in v]


class PolicyConfig(_Strict):
    alert_threshold: Severity = Severity.MEDIUM
    severities: dict[EventType, Severity] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)


class SyslogConfig(_Strict):
    address: str = "/dev/log"  # unix socket path, udp://host:port or tcp://host:port
    format: Literal["rfc5424", "cef"] = "rfc5424"
    facility: int = Field(default=13, ge=0, le=23)  # 13 = log audit
    app_name: str = Field(default="fim", pattern=r"^[A-Za-z0-9._-]{1,48}$")
    min_severity: Severity = Severity.LOW

    @field_validator("address")
    @classmethod
    def _addr(cls, v: str) -> str:
        if v.startswith("/"):
            return validate_abs_path(v, what="export.syslog.address")
        if v.startswith(("udp://", "tcp://")) and v.rsplit(":", 1)[-1].isdigit():
            return v
        raise ValueError("address must be an absolute socket path, udp://host:port or tcp://host:port")


class ExportConfig(_Strict):
    syslog: SyslogConfig | None = None


class WatchConfig(_Strict):
    debounce_seconds: float = Field(default=1.0, ge=0.1, le=60)
    full_scan_interval_seconds: int = Field(default=3600, ge=0, description="0 = never")


class Config(_Strict):
    baseline: BaselineConfig
    scan: ScanConfig
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)
    watch: WatchConfig = Field(default_factory=WatchConfig)

    def severity_for(self, event_type: EventType) -> Severity:
        return self.policy.severities.get(event_type, DEFAULT_SEVERITIES[event_type])

    def check_baseline_location(self) -> None:
        """Baselines must live outside every monitored root (compared after symlink resolution)."""
        bdir = os.path.realpath(self.baseline.dir)
        for root in self.scan.roots:
            rroot = os.path.realpath(root)
            if is_within(bdir, rroot) or is_within(rroot, bdir):
                raise ConfigError(
                    f"baseline.dir {self.baseline.dir!r} overlaps monitored root {root!r}; "
                    "store baselines outside monitored directories"
                )
        if self.baseline.public_key:
            pk = os.path.realpath(self.baseline.public_key)
            if is_within(pk, bdir):
                raise ConfigError("baseline.public_key must not be stored inside baseline.dir")


def parse_config(data: dict[str, object]) -> Config:
    try:
        cfg = Config.model_validate(data)
    except ValidationError as exc:
        lines = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"])
            lines.append(f"  {loc}: {err['msg']}")
        raise ConfigError("invalid configuration:\n" + "\n".join(lines)) from exc
    cfg.check_baseline_location()
    return cfg


def load_config(path: str | Path) -> Config:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {p}: {exc.strerror or exc}") from exc
    if len(raw) > 1024 * 1024:
        raise ConfigError("configuration file is larger than 1 MiB")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"configuration is not valid TOML: {exc}") from exc
    return parse_config(data)
