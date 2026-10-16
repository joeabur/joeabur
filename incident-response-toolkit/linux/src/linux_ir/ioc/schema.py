"""IOC file loading, validation and normalisation (JSON or YAML)."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..models import SEVERITIES

IOC_TYPES = ("sha256", "process_name", "file_path", "ip", "domain")
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_INDICATORS = 100_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$")


class IocError(ValueError):
    pass


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str
    severity: str
    description: str
    source: str


def normalize(ioc_type: str, value: str, case_insensitive_paths: bool = False) -> str:
    v = value.strip()
    if ioc_type == "sha256":
        v = v.lower()
        if not _SHA256.match(v):
            raise IocError(f"invalid SHA-256: {value!r}")
    elif ioc_type == "ip":
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise IocError(f"invalid IP address: {value!r}") from exc
    elif ioc_type == "domain":
        v = v.lower().rstrip(".")
        if not _DOMAIN.match(v):
            raise IocError(f"invalid domain: {value!r}")
    elif ioc_type == "file_path":
        if not v.startswith("/") or "\x00" in v or "/../" in v + "/":
            raise IocError(f"file_path must be absolute without traversal: {value!r}")
        v = re.sub(r"/+", "/", v)
        if len(v) > 1:
            v = v.rstrip("/")
        if case_insensitive_paths:
            v = v.lower()
    elif ioc_type == "process_name":
        if not v or "/" in v or "\x00" in v or len(v) > 255:
            raise IocError(f"process_name must be a bare name without '/': {value!r}")
    else:
        raise IocError(f"unknown indicator type {ioc_type!r} (allowed: {', '.join(IOC_TYPES)})")
    return v


def load_iocs(path: Path, case_insensitive_paths: bool = False) -> tuple[dict[str, Any], list[Indicator], list[str]]:
    """Return (metadata, indicators, warnings). Raises IocError on any invalid entry."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise IocError(f"IOC file larger than {MAX_FILE_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IocError(f"cannot read IOC file {path}: {exc}") from exc
    try:
        doc = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise IocError(f"IOC file is not valid {'JSON' if path.suffix == '.json' else 'YAML'}: {exc}") from exc
    if not isinstance(doc, dict):
        raise IocError("IOC file root must be an object")
    if doc.get("schema_version") != 1:
        raise IocError("schema_version must be 1")
    items = doc.get("indicators")
    if not isinstance(items, list):
        raise IocError("'indicators' must be a list")
    if len(items) > MAX_INDICATORS:
        raise IocError(f"too many indicators (max {MAX_INDICATORS})")
    unknown_root = set(doc) - {"schema_version", "name", "description", "indicators", "synthetic"}
    if unknown_root:
        raise IocError(f"unknown top-level keys: {sorted(unknown_root)}")
    out: list[Indicator] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise IocError(f"indicators[{i}] must be an object")
        extra = set(it) - {"type", "value", "severity", "description", "source"}
        if extra:
            raise IocError(f"indicators[{i}] has unknown keys {sorted(extra)}")
        t, v = it.get("type"), it.get("value")
        if not isinstance(t, str) or not isinstance(v, str):
            raise IocError(f"indicators[{i}] needs string 'type' and 'value'")
        sev = it.get("severity", "medium")
        if sev not in SEVERITIES:
            raise IocError(f"indicators[{i}] severity must be one of {SEVERITIES}")
        try:
            nv = normalize(t, v, case_insensitive_paths)
        except IocError as exc:
            raise IocError(f"indicators[{i}]: {exc}") from exc
        key = (t, nv)
        if key in seen:
            warnings.append(f"duplicate indicator ignored: {t} {nv}")
            continue
        seen.add(key)
        out.append(Indicator(t, nv, sev, str(it.get("description", ""))[:500], str(it.get("source", ""))[:300]))
    meta = {
        "name": doc.get("name"),
        "description": doc.get("description"),
        "synthetic": bool(doc.get("synthetic", False)),
        "indicator_count": len(out),
    }
    return meta, out, warnings
