"""Severity thresholds and build-failure policy."""

from __future__ import annotations

from .config import PolicySettings
from .schemas import Finding, FindingStatus, PolicyResult, Severity


def evaluate(
    findings: list[Finding], policy: PolicySettings, fail_on_override: str | None = None
) -> PolicyResult:
    """Fail when a finding at or above the threshold is NEW (or baseline, if configured)."""
    fail_on = fail_on_override or policy.fail_on
    if fail_on == "none":
        return PolicyResult(
            passed=True,
            fail_on=fail_on,
            fail_on_baseline=policy.fail_on_baseline,
            violating_findings=0,
            reasons=["report-only mode: severity thresholds are not enforced"],
        )
    threshold = Severity(fail_on)
    counted = {FindingStatus.NEW}
    if policy.fail_on_baseline:
        counted.add(FindingStatus.BASELINE)
    violating = [f for f in findings if f.status in counted and f.severity.rank >= threshold.rank]
    reasons: list[str] = []
    for sev in sorted({f.severity for f in violating}, key=lambda s: -s.rank):
        n = sum(1 for f in violating if f.severity is sev)
        reasons.append(f"{n} {sev.value} finding(s) at or above the '{fail_on}' threshold")
    expired = sum(1 for f in violating if f.suppression_expired)
    if expired:
        reasons.append(f"including {expired} whose baseline/suppression has expired")
    return PolicyResult(
        passed=not violating,
        fail_on=fail_on,
        fail_on_baseline=policy.fail_on_baseline,
        violating_findings=len(violating),
        reasons=reasons,
    )
