"""Exact-match IOC matching against collected evidence, with evidence references."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..models import Finding
from .schema import Indicator, normalize

# Which record fields feed each indicator type, per artifact.
FIELDS: dict[str, dict[str, list[str]]] = {
    "processes": {"sha256": ["exe_sha256"], "process_name": ["name"], "file_path": ["exe"], "text": ["cmdline"]},
    "network": {"ip": ["remote_addr", "local_addr"], "process_name": ["process"]},
    "persistence": {
        "sha256": ["sha256", "exec_sha256"],
        "file_path": ["path", "exec_binary"],
        "text": ["exec_start", "command", "commands"],
    },
    "files": {"sha256": ["sha256"], "file_path": ["path"]},
    "logs": {"ip": ["src_ip"], "text": ["message", "command"]},
}
_IP_RE = re.compile(r"(?<![0-9A-Za-z.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z])")
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?![A-Za-z0-9-])"
)
MAX_TEXT = 4096

NEXT_STEPS = [
    "Treat this as a lead, not a verdict: an IOC match is not confirmation of compromise.",
    "Review the referenced evidence record and surrounding context (parent process, timeline, other artifacts).",
    "Validate the indicator's source/provenance and age before escalating.",
]


def _flatten(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            out.extend(_flatten(v))
        return out
    return [str(value)]


def _extract(text: str, case_domains: bool = True) -> tuple[set[str], set[str]]:
    text = text[:MAX_TEXT]
    ips = set()
    for cand in _IP_RE.findall(text):
        try:
            ips.add(str(ipaddress.ip_address(cand)))
        except ValueError:
            pass
    domains = set(_DOMAIN_RE.findall(text.lower())) if case_domains else set()
    return ips, domains


def match_iocs(
    artifacts: dict[str, dict[str, Any]],
    indicators: list[Indicator],
    match_subdomains: bool = False,
    case_insensitive_paths: bool = False,
    max_findings: int = 500,
) -> list[Finding]:
    by_type: dict[str, dict[str, Indicator]] = {}
    for ind in indicators:
        by_type.setdefault(ind.type, {})[ind.value] = ind
    findings: list[Finding] = []

    def emit(art: str, idx: int, ind: Indicator, field: str, observed: str, rec: dict[str, Any]) -> None:
        if len(findings) >= max_findings:
            return
        ev = {
            k: rec.get(k)
            for k in (
                "pid",
                "name",
                "exe",
                "path",
                "unit",
                "proto",
                "local_port",
                "remote_addr",
                "remote_port",
                "ts",
                "event_type",
                "user",
                "sha256",
                "exe_sha256",
            )
            if k in rec
        }
        findings.append(
            Finding(
                rule_id=f"IOC-MATCH-{ind.type.upper()}",
                rule_version=1,
                title=f"IOC match: {ind.type} {ind.value}",
                description=ind.description or f"Evidence value equals a supplied {ind.type} indicator.",
                category="ioc",
                severity=ind.severity,
                confidence="medium",
                classification="ioc_match",
                artifact=art,
                evidence_ref=f"artifacts/{art}.json#records[{idx}]",
                why=f"Field '{field}' = {observed!r} exactly matches indicator {ind.type}={ind.value!r} "
                f"(indicator source: {ind.source or 'unspecified'}).",
                evidence=ev,
                false_positives=[
                    "Indicator may be stale, too generic, or from an unreliable source.",
                    "Benign software or analyst activity can legitimately touch the same value.",
                ],
                next_steps=NEXT_STEPS,
                attack=[],
            )
        )

    for art, doc in artifacts.items():
        spec = FIELDS.get(art)
        if not spec:
            continue
        for idx, rec in enumerate(doc["records"]):
            for itype in ("sha256", "process_name", "file_path", "ip"):
                table = by_type.get(itype)
                if not table:
                    continue
                for field in spec.get(itype, []):
                    for val in _flatten(rec.get(field)):
                        try:
                            nv = normalize(itype, val, case_insensitive_paths) if itype != "process_name" else val
                        except ValueError:
                            continue
                        if nv in table:
                            emit(art, idx, table[nv], field, val, rec)
            ips_t, dom_t = by_type.get("ip"), by_type.get("domain")
            if (ips_t or dom_t) and spec.get("text"):
                for field in spec["text"]:
                    for val in _flatten(rec.get(field)):
                        ips, domains = _extract(val)
                        if ips_t:
                            for ip in ips & ips_t.keys():
                                emit(art, idx, ips_t[ip], field, ip, rec)
                        if dom_t:
                            for d in domains:
                                if d in dom_t:
                                    emit(art, idx, dom_t[d], field, d, rec)
                                elif match_subdomains:
                                    for base, ind in dom_t.items():
                                        if d.endswith("." + base):
                                            emit(art, idx, ind, field, d, rec)
    seen = set()
    unique = []
    for f in findings:  # de-duplicate identical (rule, ref, why)
        key = (f.rule_id, f.evidence_ref, f.title)  # one match per indicator per evidence record
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
