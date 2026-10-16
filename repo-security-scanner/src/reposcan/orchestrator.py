"""Scan orchestration: validate, run scanners, merge, classify, apply policy."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import tempfile
import threading
from datetime import UTC, date, datetime
from pathlib import Path

from . import __version__
from .adapters import ScanContext, enabled_adapters
from .baseline import Baseline, apply_acceptance
from .config import Config
from .errors import ConfigError, ExitCode
from .paths import summarize_scope, validate_image_ref, validate_target
from .policy import evaluate
from .schemas import (
    Finding,
    FindingKind,
    PolicyResult,
    ScanMetadata,
    ScannerRun,
    ScanResult,
    summarize,
)

log = logging.getLogger("reposcan.orchestrator")
EVIDENCE_WITHHELD = "[line contains a secret reported by another scanner; evidence withheld]"


def now_utc() -> datetime:
    """Current time; honours SOURCE_DATE_EPOCH for reproducible reports."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=UTC)
    return datetime.now(tz=UTC).replace(microsecond=0)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(finding.fingerprint, finding)
    return list(seen.values())


def withhold_secret_lines(findings: list[Finding]) -> list[Finding]:
    """Never echo a source line in other findings if a secret scanner flagged that line."""
    secret_lines = {
        (f.file, n)
        for f in findings
        if f.kind is FindingKind.SECRET and f.file and f.line
        for n in range(f.line, (f.end_line or f.line) + 1)
    }
    if not secret_lines:
        return findings
    out = []
    for f in findings:
        if (
            f.kind is not FindingKind.SECRET
            and f.evidence
            and f.file
            and f.line in {n for (file, n) in secret_lines if file == f.file}
        ):
            f = f.model_copy(update={"evidence": EVIDENCE_WITHHELD})
        out.append(f)
    return out


def exit_code_for(runs: list[ScannerRun], policy: PolicyResult, cancelled: bool) -> tuple[ExitCode, str]:
    if cancelled:
        return ExitCode.CANCELLED, "scan cancelled"
    broken = [r for r in runs if r.status != "ok"]
    if broken:
        names = ", ".join(f"{r.name} ({r.status})" for r in broken)
        return ExitCode.SCANNER_ERROR, f"scanner problem: {names}; results are incomplete"
    if not policy.passed:
        return ExitCode.POLICY_FAILED, "policy failed: " + "; ".join(policy.reasons)
    return ExitCode.OK, "scan complete, policy satisfied"


def run_scan(
    target: str,
    config: Config,
    *,
    only: list[str] | None = None,
    baseline: Baseline | None = None,
    baseline_label: str | None = None,
    fail_on: str | None = None,
    offline: bool | None = None,
    timeout: int | None = None,
    history: bool | None = None,
    image: str | None = None,
    allow_repo_ignore_files: bool = False,
    cancel: threading.Event | None = None,
    today: date | None = None,
    extra_warnings: list[str] | None = None,
) -> ScanResult:
    """Run the selected scanners against ``target`` and return the unified result."""
    root = validate_target(target)
    image_ref = validate_image_ref(image) if image else None
    use_history = config.scan.history if history is None else history
    if use_history and not (root / ".git").exists():
        raise ConfigError("--history requires a git repository (no .git found in the scan path)")
    if use_history and not root.is_dir():
        raise ConfigError("--history requires a directory")
    adapters = enabled_adapters(config, only)
    if not adapters:
        raise ConfigError("no scanners are enabled; enable at least one in the config or --scanners")
    is_offline = config.scan.offline if offline is None else offline
    started = now_utc()
    today = today or started.date()
    warnings = list(extra_warnings or [])
    scope = summarize_scope(root)
    scope = scope.model_copy(update={"history_scanned": use_history, "trivy_image": image_ref})
    if use_history:
        warnings.append(
            "history scanning runs `git` against repository data; a crafted repository can influence "
            "git (for example via textconv drivers). Scan untrusted history only in a sandbox."
        )
    if allow_repo_ignore_files and (root / ".gitleaksignore").exists():
        warnings.append(
            "the repository's .gitleaksignore is being honoured by Gitleaks (--allow-repo-ignore-files); "
            "findings listed there are hidden from this report"
        )

    workdir = Path(tempfile.mkdtemp(prefix="reposcan-"))
    workdir.chmod(0o700)
    try:
        ctx = ScanContext(
            target=root,
            workdir=workdir,
            config=config,
            offline=is_offline,
            timeout=float(timeout or config.scan.timeout_seconds),
            max_output_bytes=config.scan.max_output_bytes,
            history=use_history,
            image=image_ref,
            cancel=cancel,
            allow_repo_ignore_files=allow_repo_ignore_files,
        )
        runs: list[ScannerRun] = []
        findings: list[Finding] = []
        cancelled = False
        for adapter in adapters:
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            log.info("running %s", adapter.name)
            outcome = adapter.run(ctx)
            runs.append(outcome.run)
            findings.extend(outcome.findings)
            if outcome.run.status == "cancelled":
                cancelled = True
                break
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    warnings.extend(f"{run.name}: {w}" for run in runs for w in run.warnings)
    findings = withhold_secret_lines(dedupe(findings))
    findings, accept_warnings = apply_acceptance(findings, baseline, config.suppressions, today)
    warnings.extend(accept_warnings)
    findings.sort(key=lambda f: f.sort_key())
    policy = evaluate(findings, config.policy, fail_on)
    code, reason = exit_code_for(runs, policy, cancelled)
    finished = now_utc()
    return ScanResult(
        metadata=ScanMetadata(
            tool_version=__version__,
            started_at=started,
            finished_at=max(finished, started),
            python_version=platform.python_version(),
            platform=f"{platform.system()} {platform.machine()}",
            offline=is_offline,
            config_sources=[config.source],
            baseline_file=baseline_label,
        ),
        scope=scope,
        scanners=runs,
        findings=findings,
        summary=summarize(findings),
        policy=policy,
        warnings=warnings,
        exit_code=int(code),
        exit_reason=reason,
    )
