"""Baseline comparison and suppression.

Principles:

* Every accepted finding has an owner and a reason, and may have an expiry.
* An expired acceptance stops applying: the finding becomes **new** again.
* Accepted findings stay visible in every report; nothing is dropped.
* Baselines are plain JSON validated by Pydantic (no pickle/YAML/eval).
"""

from __future__ import annotations

import fnmatch
import json
import os
import tempfile
from datetime import date, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import Config, Suppression, format_validation_error, is_expired
from .errors import ConfigError
from .paths import validate_file_arg
from .redaction import sanitize
from .schemas import AcceptedEntry, Finding, FindingStatus, Severity

BASELINE_SCHEMA = 1
MAX_BASELINE_BYTES = 10 * 1024 * 1024


class BaselineEntry(AcceptedEntry):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{32}$")
    scanner: str
    rule_id: str
    file: str | None = None
    severity: Severity
    title: str = Field(max_length=300)
    created: date


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = BASELINE_SCHEMA
    entries: list[BaselineEntry] = Field(default_factory=list)

    def by_fingerprint(self) -> dict[str, BaselineEntry]:
        return {e.fingerprint: e for e in self.entries}


def load_baseline(path: str) -> Baseline:
    file = validate_file_arg(path, "baseline file", max_bytes=MAX_BASELINE_BYTES)
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
        baseline = Baseline.model_validate(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ConfigError("baseline file is not valid JSON") from None
    except ValidationError as exc:
        raise ConfigError(f"baseline file is invalid: {format_validation_error(exc)}") from None
    if baseline.schema_version != BASELINE_SCHEMA:
        raise ConfigError(f"unsupported baseline schema_version {baseline.schema_version}")
    return baseline


def save_baseline(baseline: Baseline, path: Path) -> None:
    """Atomically write the baseline in a stable, diff-friendly order."""
    ordered = sorted(baseline.entries, key=lambda e: (e.file or "", e.scanner, e.rule_id, e.fingerprint))
    payload = Baseline(schema_version=baseline.schema_version, entries=ordered)
    text = json.dumps(payload.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".baseline-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def validate_acceptance(*, severity: Severity, expires: date | None, today: date, config: Config) -> None:
    """Enforce expiry policy for accepting a finding."""
    required = config.policy.require_expiry_at_or_above
    if required != "none" and expires is None and severity.rank >= Severity(required).rank:
        raise ConfigError(
            f"{severity.value} findings require an expiry date (policy "
            f"require_expiry_at_or_above = {required!r})"
        )
    if expires is not None:
        if expires < today:
            raise ConfigError("expiry date is in the past")
        if expires > today + timedelta(days=config.policy.max_accept_days):
            raise ConfigError(
                f"expiry is more than {config.policy.max_accept_days} days away (policy max_accept_days)"
            )


def add_to_baseline(
    existing: Baseline | None,
    findings: list[Finding],
    *,
    owner: str,
    reason: str,
    expires: date | None,
    today: date,
    config: Config,
) -> tuple[Baseline, list[Finding]]:
    """Add new findings to a baseline. Returns the baseline and the findings added."""
    baseline = existing.model_copy(deep=True) if existing else Baseline()
    known = baseline.by_fingerprint()
    added: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in known and not is_expired(known[finding.fingerprint].expires, today):
            continue
        validate_acceptance(severity=finding.severity, expires=expires, today=today, config=config)
        entry = BaselineEntry(
            fingerprint=finding.fingerprint,
            scanner=finding.scanner,
            rule_id=finding.rule_id,
            file=finding.file,
            severity=finding.severity,
            title=sanitize(finding.title, limit=300),
            owner=owner,
            reason=reason,
            expires=expires,
            created=today,
        )
        baseline.entries = [e for e in baseline.entries if e.fingerprint != finding.fingerprint]
        baseline.entries.append(entry)
        added.append(finding)
    return baseline, added


def _matches(supp: Suppression, finding: Finding) -> bool:
    if supp.fingerprint:
        return supp.fingerprint == finding.fingerprint
    if supp.rule_id != finding.rule_id:
        return False
    if supp.scanner and supp.scanner != finding.scanner:
        return False
    if supp.path:
        return finding.file is not None and fnmatch.fnmatchcase(finding.file, supp.path)
    return True


def apply_acceptance(
    findings: list[Finding],
    baseline: Baseline | None,
    suppressions: list[Suppression],
    today: date,
) -> tuple[list[Finding], list[str]]:
    """Annotate findings with their status. Returns (findings, warnings)."""
    warnings: list[str] = []
    by_fp = baseline.by_fingerprint() if baseline else {}
    seen: set[str] = set()
    result: list[Finding] = []
    expired_notes: set[str] = set()
    for finding in findings:
        update: dict[str, object] = {}
        entry = by_fp.get(finding.fingerprint)
        matched_supp = next((s for s in suppressions if _matches(s, finding)), None)
        chosen: tuple[FindingStatus, AcceptedEntry, str] | None = None
        if entry is not None:
            seen.add(finding.fingerprint)
            chosen = (FindingStatus.BASELINE, entry, "baseline")
        if matched_supp is not None and (chosen is None or is_expired(chosen[1].expires, today)):
            chosen = (FindingStatus.SUPPRESSED, matched_supp, "suppression")
        if chosen is not None:
            status, accepted, kind = chosen
            if is_expired(accepted.expires, today):
                update = {
                    "suppression_expired": True,
                    "status_detail": sanitize(
                        f"{kind} by {accepted.owner} expired on {accepted.expires}", limit=300
                    ),
                }
                expired_notes.add(
                    f"{kind} owned by {sanitize(accepted.owner, limit=60)} expired on {accepted.expires}"
                )
            else:
                until = f", expires {accepted.expires}" if accepted.expires else ""
                update = {
                    "status": status,
                    "status_detail": sanitize(
                        f"{kind}: {accepted.owner}: {accepted.reason}{until}", limit=400
                    ),
                }
        result.append(finding.model_copy(update=update))
    if expired_notes:
        warnings.append(
            f"{sum(1 for f in result if f.suppression_expired)} finding(s) are reported as NEW "
            "because their baseline/suppression entry has expired"
        )
    stale = [e for fp, e in by_fp.items() if fp not in seen]
    if stale:
        warnings.append(
            f"{len(stale)} baseline entr{'y is' if len(stale) == 1 else 'ies are'} stale "
            "(no longer reported); review and remove them"
        )
    unmatched = [s for s in suppressions if not any(_matches(s, f) for f in findings)]
    if unmatched:
        warnings.append(f"{len(unmatched)} suppression(s) matched nothing in this scan")
    return result, warnings


def review_baseline(baseline: Baseline, current: list[Finding] | None, today: date) -> list[dict[str, str]]:
    """Return one row per entry describing its health, for `baseline review`."""
    live = {f.fingerprint for f in current} if current is not None else None
    rows = []
    for entry in sorted(baseline.entries, key=lambda e: (e.file or "", e.rule_id, e.fingerprint)):
        problems = []
        if is_expired(entry.expires, today):
            problems.append("EXPIRED")
        elif entry.expires is None:
            problems.append("no-expiry")
        elif (entry.expires - today).days <= 14:
            problems.append("expires-soon")
        if live is not None and entry.fingerprint not in live:
            problems.append("STALE")
        rows.append(
            {
                "fingerprint": entry.fingerprint,
                "severity": entry.severity.value,
                "rule": sanitize(entry.rule_id, limit=60),
                "file": sanitize(entry.file or "-", limit=80),
                "owner": sanitize(entry.owner, limit=40),
                "expires": str(entry.expires) if entry.expires else "-",
                "reason": sanitize(entry.reason, limit=80),
                "health": ",".join(problems) or "ok",
            }
        )
    return rows
