"""Declarative, validated detection rules. Rule files are data: no code is ever executed."""

from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .. import RULE_ID_PREFIX
from ..models import CONFIDENCES, SEVERITIES, Finding
from ..utils.timeutil import parse_iso

RULE_TYPES = ("match", "threshold", "baseline")
OPS = (
    "eq",
    "ne",
    "in",
    "not_in",
    "startswith_any",
    "endswith_any",
    "contains_any",
    "regex",
    "exists",
    "gte",
    "lte",
    "truthy",
    "falsy",
)
MAX_RULE_FILE_BYTES = 1_000_000
MAX_REGEX_LEN = 256
_NESTED_QUANT = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")
_TEMPLATE = re.compile(r"\{([A-Za-z0-9_.]+)\}")
RULE_KEYS = {
    "id",
    "version",
    "title",
    "description",
    "category",
    "severity",
    "confidence",
    "artifact",
    "type",
    "when",
    "why",
    "false_positives",
    "next_steps",
    "attack",
    "group_by",
    "threshold",
    "window_seconds",
    "key_fields",
    "mode",
    "compare_fields",
    "enabled",
}


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    raw: dict[str, Any]
    compiled: list[tuple[str, str, Any]] = field(default_factory=list)  # (field, op, operand)
    regexes: dict[str, re.Pattern[str]] = field(default_factory=dict)

    def __getattr__(self, item: str) -> Any:
        try:
            return self.raw[item]
        except KeyError as exc:
            raise AttributeError(item) from exc


def _validate_condition(c: Any, where: str) -> tuple[str, str, Any]:
    if not isinstance(c, dict) or set(c) - {"field", "op", "value"}:
        raise RuleError(f"{where}: condition must have only field/op/value")
    f, op = c.get("field"), c.get("op")
    if not isinstance(f, str) or not re.fullmatch(r"[A-Za-z0-9_.]+", f):
        raise RuleError(f"{where}: invalid field name {f!r}")
    if op not in OPS:
        raise RuleError(f"{where}: unknown op {op!r}; allowed: {', '.join(OPS)}")
    val = c.get("value")
    if op in ("in", "not_in", "startswith_any", "endswith_any", "contains_any") and not isinstance(val, list):
        raise RuleError(f"{where}: op {op} needs a list value")
    if op == "regex":
        if not isinstance(val, str) or len(val) > MAX_REGEX_LEN or _NESTED_QUANT.search(val):
            raise RuleError(f"{where}: regex too long (>{MAX_REGEX_LEN}) or has nested quantifiers (ReDoS risk)")
        try:
            re.compile(val)
        except re.error as exc:
            raise RuleError(f"{where}: invalid regex: {exc}") from exc
    return f, op, val


def validate_rule(raw: Any, source: str) -> Rule:
    where = f"{source}"
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: rule must be a mapping")
    rid = raw.get("id")
    where = f"{source}:{rid}"
    unknown = set(raw) - RULE_KEYS
    if unknown:
        raise RuleError(f"{where}: unknown keys {sorted(unknown)}")
    if not isinstance(rid, str) or not re.fullmatch(rf"{RULE_ID_PREFIX}-[A-Z]+-[0-9]{{3}}", rid):
        raise RuleError(f"{where}: id must look like {RULE_ID_PREFIX}-CATEGORY-001")
    if not isinstance(raw.get("version"), int) or raw["version"] < 1:
        raise RuleError(f"{where}: version must be a positive integer")
    for k in ("title", "description", "category", "artifact", "why"):
        if not isinstance(raw.get(k), str) or not raw[k].strip():
            raise RuleError(f"{where}: '{k}' is required (non-empty string)")
    if raw.get("severity") not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {SEVERITIES}")
    if raw.get("confidence") not in CONFIDENCES:
        raise RuleError(f"{where}: confidence must be one of {CONFIDENCES}")
    if raw.get("type", "match") not in RULE_TYPES:
        raise RuleError(f"{where}: type must be one of {RULE_TYPES}")
    for k in ("false_positives", "next_steps"):
        v = raw.get(k)
        if not isinstance(v, list) or not v or not all(isinstance(i, str) for i in v):
            raise RuleError(f"{where}: '{k}' must be a non-empty list of strings")
    if not isinstance(raw.get("attack", []), list):
        raise RuleError(f"{where}: attack must be a list")
    for t in raw.get("attack", []):
        if not re.fullmatch(r"T[0-9]{4}(\.[0-9]{3})?", str(t)):
            raise RuleError(f"{where}: invalid ATT&CK id {t!r}")
    when = raw.get("when", [])
    if not isinstance(when, list):
        raise RuleError(f"{where}: 'when' must be a list of conditions")
    rule = Rule(raw)
    rule.compiled = [_validate_condition(c, where) for c in when]
    typ = raw.get("type", "match")
    if typ == "threshold":
        if (
            not isinstance(raw.get("group_by"), str)
            or not isinstance(raw.get("threshold"), int)
            or raw["threshold"] < 1
        ):
            raise RuleError(f"{where}: threshold rules need group_by (string) and threshold (positive int)")
        if not isinstance(raw.get("window_seconds"), int) or raw["window_seconds"] < 1:
            raise RuleError(f"{where}: threshold rules need window_seconds")
    if typ == "baseline":
        if not isinstance(raw.get("key_fields"), list) or not raw["key_fields"]:
            raise RuleError(f"{where}: baseline rules need key_fields")
        if raw.get("mode", "new") not in ("new", "changed"):
            raise RuleError(f"{where}: baseline mode must be 'new' or 'changed'")
        if raw.get("mode") == "changed" and not raw.get("compare_fields"):
            raise RuleError(f"{where}: baseline mode 'changed' needs compare_fields")
    if typ != "baseline" and not rule.compiled and typ == "match":
        raise RuleError(f"{where}: match rules need at least one condition")
    return rule


def load_rules(directory: Path) -> list[Rule]:
    if not directory.is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    rules: list[Rule] = []
    ids: set[str] = set()
    for p in sorted(directory.glob("*.yaml")):
        if p.stat().st_size > MAX_RULE_FILE_BYTES:
            raise RuleError(f"{p.name}: rule file too large")
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleError(f"{p.name}: cannot parse: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            raise RuleError(f"{p.name}: top level must be a mapping with a 'rules' list")
        for raw in doc["rules"]:
            rule = validate_rule(raw, p.name)
            if rule.id in ids:
                raise RuleError(f"{p.name}: duplicate rule id {rule.id}")
            ids.add(rule.id)
            rules.append(rule)
    return rules


def find_rules_dir(explicit: Path | None) -> Path:
    if explicit:
        return explicit
    env = os.environ.get("IR_TOOLKIT_RULES")
    candidates = [Path(env)] if env else []
    here = Path(__file__).resolve()
    candidates += [Path.cwd() / "rules", here.parents[3] / "rules"]
    for c in candidates:
        if c.is_dir():
            return c
    raise RuleError("rules directory not found; pass --rules DIR or set IR_TOOLKIT_RULES")


def _get(rec: dict[str, Any], dotted: str) -> Any:
    cur: Any = rec
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _cond_ok(rec: dict[str, Any], rule: Rule, cond: tuple[str, str, Any], max_chars: int) -> bool:
    f, op, operand = cond
    val = _get(rec, f)
    if op == "exists":
        return (val is not None) == bool(operand if operand is not None else True)
    if op == "truthy":
        return bool(val)
    if op == "falsy":
        return val is not None and not val
    if val is None:
        return False
    items = val if isinstance(val, list) else [val]
    for item in items:
        if op in ("gte", "lte"):
            try:
                if (float(item) >= float(operand)) if op == "gte" else (float(item) <= float(operand)):
                    return True
            except (TypeError, ValueError):
                continue
            continue
        s = str(item)[:max_chars]
        if op == "eq" and (item == operand or s == str(operand)):
            return True
        if op == "ne" and not (item == operand or s == str(operand)):
            return True
        if op == "in" and (item in operand or s in [str(o) for o in operand]):
            return True
        if op == "not_in" and not (item in operand or s in [str(o) for o in operand]):
            return True
        if op == "startswith_any" and any(s.startswith(str(o)) for o in operand):
            return True
        if op == "endswith_any" and any(s.endswith(str(o)) for o in operand):
            return True
        if op == "contains_any" and any(str(o) in s for o in operand):
            return True
        if op == "regex":
            rx = rule.regexes.get(operand)
            if rx is None:
                rx = rule.regexes[operand] = re.compile(operand)
            if rx.search(s):
                return True
    return False


def _matches(rec: dict[str, Any], rule: Rule, max_chars: int) -> bool:
    return all(_cond_ok(rec, rule, c, max_chars) for c in rule.compiled)


def _render(template: str, rec: dict[str, Any]) -> str:
    def sub(m: re.Match[str]) -> str:
        v = _get(rec, m.group(1))
        if isinstance(v, list):
            v = ", ".join(str(i) for i in v[:5])
        return "<unavailable>" if v is None else str(v)[:300]

    return _TEMPLATE.sub(sub, template)


EVIDENCE_KEYS = (
    "pid",
    "ppid",
    "name",
    "exe",
    "cmdline",
    "path",
    "unit",
    "scope",
    "exec_start",
    "exec_binary",
    "exec_exists",
    "command",
    "user",
    "owner",
    "mode",
    "proto",
    "local_addr",
    "local_port",
    "remote_addr",
    "remote_port",
    "process",
    "ts",
    "event_type",
    "src_ip",
    "sha256",
    "exe_sha256",
    "schedule",
    "mtime",
    "staging_dir",
    "settings",
    "label",
    "program",
    "program_arguments",
)


def _finding(rule: Rule, rec: dict[str, Any], idx: int, why: str, extra: dict[str, Any] | None = None) -> Finding:
    ev = {k: rec[k] for k in EVIDENCE_KEYS if k in rec}
    ev.update(extra or {})
    return Finding(
        rule_id=rule.id,
        rule_version=rule.version,
        title=rule.title,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        classification="heuristic",
        artifact=rule.artifact,
        evidence_ref=f"artifacts/{rule.artifact}.json#records[{idx}]",
        why=why,
        evidence=ev,
        false_positives=list(rule.false_positives),
        next_steps=list(rule.next_steps),
        attack=list(rule.raw.get("attack", [])),
    )


def evaluate(
    rules: list[Rule],
    artifacts: dict[str, dict[str, Any]],
    baseline: dict[str, dict[str, Any]] | None,
    max_per_rule: int = 200,
    max_chars: int = 2048,
    max_records: int = 200_000,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    for rule in rules:
        if rule.raw.get("enabled", True) is False:
            continue
        doc = artifacts.get(rule.artifact)
        if doc is None:
            notes.append(f"{rule.id}: artifact '{rule.artifact}' not present in evidence; rule not evaluated")
            continue
        if doc.get("status") in ("failed", "skipped", "unavailable"):
            notes.append(f"{rule.id}: artifact '{rule.artifact}' status is {doc['status']}; rule not evaluated")
            continue
        recs = doc["records"][:max_records]
        if len(doc["records"]) > max_records:
            notes.append(f"{rule.id}: only first {max_records} records evaluated")
        typ = rule.raw.get("type", "match")
        count = 0
        if typ == "match":
            for i, rec in enumerate(recs):
                if _matches(rec, rule, max_chars):
                    findings.append(_finding(rule, rec, i, _render(rule.why, rec)))
                    count += 1
                    if count >= max_per_rule:
                        notes.append(f"{rule.id}: finding cap {max_per_rule} reached")
                        break
        elif typ == "threshold":
            groups: dict[str, list[tuple[int, Any]]] = defaultdict(list)
            for i, rec in enumerate(recs):
                if _matches(rec, rule, max_chars):
                    key = _get(rec, rule.group_by)
                    ts = parse_iso(rec["ts"]) if isinstance(rec.get("ts"), str) else None
                    if key is not None and ts is not None:
                        groups[str(key)].append((i, ts))
            window = timedelta(seconds=rule.window_seconds)
            for key, evs in groups.items():
                evs.sort(key=lambda x: x[1])
                lo = 0
                for hi in range(len(evs)):
                    while evs[hi][1] - evs[lo][1] > window:
                        lo += 1
                    if hi - lo + 1 >= rule.threshold:
                        idx = evs[lo][0]
                        n = hi - lo + 1
                        rec = recs[idx]
                        why = _render(rule.why, {**rec, "group": key, "count": n})
                        findings.append(
                            _finding(
                                rule,
                                rec,
                                idx,
                                why,
                                {
                                    "group": key,
                                    "count": n,
                                    "first_seen": evs[lo][1].isoformat(),
                                    "last_seen": evs[hi][1].isoformat(),
                                    "event_refs": [
                                        f"artifacts/{rule.artifact}.json#records[{e[0]}]" for e in evs[lo : hi + 1]
                                    ][:20],
                                },
                            )
                        )
                        count += 1
                        break
                if count >= max_per_rule:
                    break
        else:  # baseline
            if baseline is None or rule.artifact not in baseline:
                notes.append(f"{rule.id}: no baseline supplied for '{rule.artifact}'; rule not evaluated")
                continue
            keys = rule.key_fields
            base_idx: dict[tuple[Any, ...], dict[str, Any]] = {}
            for rec in baseline[rule.artifact]["records"][:max_records]:
                if _matches(rec, rule, max_chars):
                    base_idx[tuple(str(_get(rec, k)) for k in keys)] = rec
            mode = rule.raw.get("mode", "new")
            for i, rec in enumerate(recs):
                if not _matches(rec, rule, max_chars):
                    continue
                k = tuple(str(_get(rec, f)) for f in keys)
                old = base_idx.get(k)
                if mode == "new" and old is None:
                    findings.append(_finding(rule, rec, i, _render(rule.why, rec)))
                elif mode == "changed" and old is not None:
                    diff = [f for f in rule.compare_fields if _get(old, f) != _get(rec, f)]
                    if diff:
                        findings.append(
                            _finding(
                                rule,
                                rec,
                                i,
                                _render(rule.why, rec),
                                {"changed_fields": diff, "baseline": {f: _get(old, f) for f in diff}},
                            )
                        )
                    else:
                        continue
                else:
                    continue
                count += 1
                if count >= max_per_rule:
                    notes.append(f"{rule.id}: finding cap {max_per_rule} reached")
                    break
    return findings, notes
