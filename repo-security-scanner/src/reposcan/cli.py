"""Command-line interface."""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
from datetime import date
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError

from . import __version__
from .adapters import ALL_ADAPTERS, ScanContext, ScannerAdapter, adapter_names, enabled_adapters
from .baseline import (
    Baseline,
    add_to_baseline,
    load_baseline,
    review_baseline,
    save_baseline,
)
from .config import Config, format_validation_error, load_config
from .errors import ConfigError, ExecutableNotFoundError, ExitCode, ReposcanError, ScannerError
from .orchestrator import now_utc, run_scan
from .paths import validate_file_arg, validate_output_dir, validate_target
from .redaction import RedactingFilter, sanitize
from .reporting.markdown import render_github_annotations, render_markdown
from .reporting.writer import FORMATS, write_reports, write_text_safely
from .schemas import ScanResult

app = typer.Typer(
    name="reposcan",
    help="Orchestrate Gitleaks, Semgrep, Trivy and OSV-Scanner: unified findings, baselines, CI policy.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
baseline_app = typer.Typer(help="Create and review baselines of accepted findings.", no_args_is_help=True)
report_app = typer.Typer(help="Render reports from a saved JSON result.", no_args_is_help=True)
config_app = typer.Typer(help="Configuration helpers.", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")
app.add_typer(report_app, name="report")
app.add_typer(config_app, name="config")

log = logging.getLogger("reposcan")
DEFAULT_FORMATS = "json,html,sarif,md"
MAX_REPORT_INPUT_BYTES = 256 * 1024 * 1024


def _echo(text: str = "", *, err: bool = False) -> None:
    typer.echo(sanitize(text), err=err)


def _setup_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("reposcan")
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.propagate = False


def _parse_date(value: str | None, what: str) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ConfigError(f"{what} must be an ISO date like 2026-12-31") from None


def _split(value: str | None) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _install_cancel_handlers(cancel: threading.Event) -> None:
    def handler(_signum: int, _frame: Any) -> None:
        cancel.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handler)


def _fail(exc: ReposcanError) -> typer.Exit:
    _echo(f"error: {exc}", err=True)
    return typer.Exit(int(exc.exit_code))


def _load_scan_inputs(config_path: str | None, baseline_path: str | None) -> tuple[Config, Baseline | None]:
    config = load_config(config_path)
    baseline = load_baseline(baseline_path) if baseline_path else None
    return config, baseline


def _print_summary(result: ScanResult, written: list[Path]) -> None:
    _echo(
        f"reposcan {result.metadata.tool_version}  target={result.scope.target}  "
        f"files={result.scope.file_count}"
    )
    for run in result.scanners:
        detail = f" - {run.error}" if run.error else ""
        _echo(
            f"  {run.name:<12} {run.status:<17} v{run.version or '?':<9} findings={run.finding_count}{detail}"
        )
    s = result.summary
    new = result.summary.by_status.get("new", 0)
    _echo(
        "findings: "
        + " ".join(f"{k}={v}" for k, v in s.by_severity.items())
        + f"  |  new={new} baseline={s.by_status.get('baseline', 0)} "
        f"suppressed={s.by_status.get('suppressed', 0)}"
    )
    for warning in result.warnings:
        _echo(f"warning: {warning}")
    for path in written:
        _echo(f"wrote {path}")
    _echo(f"result: {result.exit_reason} (exit {result.exit_code})")


@app.callback()
def _root() -> None:
    """reposcan - repository security scan orchestrator."""


@app.command()
def version() -> None:
    """Print the reposcan version."""
    typer.echo(f"reposcan {__version__}")


@app.command()
def doctor(
    config: Annotated[str | None, typer.Option(help="TOML config file.")] = None,
    all_scanners: Annotated[
        bool, typer.Option("--all", help="Check every known scanner, not just enabled ones.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Discover scanners and verify their versions against the supported ranges."""
    _setup_logging(verbose)
    try:
        cfg = load_config(config)
        adapters: list[ScannerAdapter] = (
            [a() for a in ALL_ADAPTERS] if all_scanners else enabled_adapters(cfg)
        )
        import tempfile

        rows = []
        with tempfile.TemporaryDirectory(prefix="reposcan-doctor-") as tmp:
            ctx = ScanContext(
                target=Path(tmp),
                workdir=Path(tmp),
                config=cfg,
                offline=True,
                timeout=30,
                max_output_bytes=65536,
            )
            for adapter in adapters:
                status, version_text, note = "ok", None, ""
                try:
                    _exe, version_text = adapter.discover(ctx)
                    if not adapter.version_supported(version_text):
                        status = "version_mismatch"
                        note = f"supported {adapter.supported}"
                except ExecutableNotFoundError as exc:
                    status, note = "not_found", str(exc)
                except ScannerError as exc:
                    status, note = "failed", str(exc)
                rows.append(
                    {
                        "scanner": adapter.name,
                        "status": status,
                        "version": version_text,
                        "supported": adapter.supported,
                        "tested": adapter.tested,
                        "note": sanitize(note, limit=200),
                    }
                )
    except ReposcanError as exc:
        raise _fail(exc) from None
    if as_json:
        typer.echo(json.dumps({"scanners": rows}, indent=2, sort_keys=True))
    else:
        _echo(f"reposcan {__version__}")
        for r in rows:
            _echo(
                f"  {r['scanner']:<12} {r['status']:<17} found={r['version'] or '-':<9} "
                f"supported={r['supported']:<10} tested={r['tested']} {r['note']}"
            )
    bad = [r for r in rows if r["status"] != "ok"]
    raise typer.Exit(int(ExitCode.SCANNER_ERROR) if bad else 0)


@app.command("update-db")
def update_db(
    config: Annotated[str | None, typer.Option(help="TOML config file.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Download/refresh Trivy's vulnerability DB (the ONLY command that needs network by design)."""
    import tempfile

    from .runner import run_command

    _setup_logging(verbose)
    try:
        cfg = load_config(config)
        adapter = next(a() for a in ALL_ADAPTERS if a.name == "trivy")
        with tempfile.TemporaryDirectory(prefix="reposcan-update-") as tmp:
            ctx = ScanContext(
                target=Path(tmp),
                workdir=Path(tmp),
                config=cfg,
                offline=False,
                timeout=float(cfg.scan.timeout_seconds),
                max_output_bytes=1_048_576,
            )
            exe, _version = adapter.discover(ctx)
            result = run_command(
                [
                    exe,
                    "image",
                    "--download-db-only",
                    "--quiet",
                    "--no-progress",
                    "--disable-telemetry",
                ],
                cwd=Path(tmp),
                env=adapter._env(ctx),
                timeout=ctx.timeout,
                max_output_bytes=ctx.max_output_bytes,
            )
    except ReposcanError as exc:
        raise _fail(exc) from None
    if result.returncode != 0:
        _echo(
            f"error: trivy database download failed: {sanitize(result.stderr.strip()[-300:])}",
            err=True,
        )
        raise typer.Exit(int(ExitCode.SCANNER_ERROR))
    _echo("trivy vulnerability database is up to date")
    _echo('OSV-Scanner databases are fetched on demand when scanners.osv.mode = "local-db" and --online')


def _execute_scan(
    path: str,
    config_path: str | None,
    baseline_path: str | None,
    scanners: str | None,
    fail_on: str | None,
    offline: bool | None,
    timeout: int | None,
    history: bool,
    image: str | None,
    allow_repo_ignore_files: bool,
    verbose: bool,
    extra_warnings: list[str] | None = None,
) -> ScanResult:
    _setup_logging(verbose)
    cfg, baseline = _load_scan_inputs(config_path, baseline_path)
    known = set(adapter_names())
    only = _split(scanners)
    if unknown := [s for s in only if s not in known]:
        raise ConfigError(f"unknown scanner(s): {', '.join(unknown)}; choose from {', '.join(sorted(known))}")
    if fail_on and fail_on not in {"critical", "high", "medium", "low", "info", "none"}:
        raise ConfigError("--fail-on must be one of critical, high, medium, low, info, none")
    cancel = threading.Event()
    _install_cancel_handlers(cancel)
    return run_scan(
        path,
        cfg,
        only=only or None,
        baseline=baseline,
        baseline_label=Path(baseline_path).name if baseline_path else None,
        fail_on=fail_on,
        offline=offline,
        timeout=timeout,
        history=history or None,
        image=image,
        allow_repo_ignore_files=allow_repo_ignore_files,
        cancel=cancel,
        extra_warnings=extra_warnings,
    )


@app.command()
def scan(
    path: Annotated[str, typer.Argument(help="Repository directory (or file) to scan.")] = ".",
    config: Annotated[
        str | None, typer.Option(help="TOML config file (never read from the scanned repo).")
    ] = None,
    baseline: Annotated[str | None, typer.Option(help="Baseline JSON of accepted findings.")] = None,
    scanners: Annotated[
        str | None, typer.Option(help="Comma-separated subset: gitleaks,semgrep,trivy,osv-scanner.")
    ] = None,
    fail_on: Annotated[
        str | None, typer.Option(help="critical|high|medium|low|info|none (overrides config).")
    ] = None,
    output_dir: Annotated[str, typer.Option(help="Where reports are written.")] = "reposcan-output",
    formats: Annotated[
        str, typer.Option("--format", help=f"Comma-separated: {','.join(FORMATS)}.")
    ] = DEFAULT_FORMATS,
    offline: Annotated[
        bool | None,
        typer.Option("--offline/--online", help="Disable scanner network access (needs warm DB caches)."),
    ] = None,
    timeout: Annotated[int | None, typer.Option(help="Per-scanner timeout in seconds.")] = None,
    history: Annotated[
        bool,
        typer.Option(
            help=(
                "Gitleaks scans git commit history (`git` mode) INSTEAD of the working tree. "
                "See the docs before using this on untrusted repositories."
            )
        ),
    ] = False,
    image: Annotated[
        str | None,
        typer.Option(
            help="Trivy scans this container image INSTEAD of the filesystem (pulls from a registry)."
        ),
    ] = None,
    allow_repo_ignore_files: Annotated[
        bool,
        typer.Option(
            help=(
                "Accept repository-supplied suppressions that scanners always honour "
                "(.gitleaksignore, Trivy inline ignores); recorded as a warning."
            )
        ),
    ] = False,
    github_annotations: Annotated[
        bool, typer.Option(help="Print GitHub workflow annotations for new findings.")
    ] = False,
    github_summary: Annotated[
        bool, typer.Option(help="Append a Markdown summary to $GITHUB_STEP_SUMMARY.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging (redacted).")] = False,
) -> None:
    """Scan PATH with the configured scanners and enforce the severity policy."""
    try:
        target = validate_target(path)
        out_dir, out_warnings = validate_output_dir(output_dir, target=target)
        chosen = _split(formats)
        if unknown := [f for f in chosen if f not in FORMATS]:
            raise ConfigError(f"unknown report format(s): {', '.join(unknown)}")
        result = _execute_scan(
            path,
            config,
            baseline,
            scanners,
            fail_on,
            offline,
            timeout,
            history,
            image,
            allow_repo_ignore_files,
            verbose,
            out_warnings,
        )
        written = write_reports(result, out_dir, chosen)
    except ReposcanError as exc:
        raise _fail(exc) from None
    except ValidationError as exc:
        _echo(f"error: {format_validation_error(exc)}", err=True)
        raise typer.Exit(int(ExitCode.CONFIG_ERROR)) from None
    if github_annotations:
        typer.echo(render_github_annotations(result), nl=False)
    if github_summary:
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            with open(summary_file, "a", encoding="utf-8") as fh:
                fh.write(render_markdown(result))
        else:
            _echo("warning: --github-summary given but GITHUB_STEP_SUMMARY is not set", err=True)
    _print_summary(result, written)
    raise typer.Exit(result.exit_code)


@baseline_app.command("create")
def baseline_create(
    path: Annotated[str, typer.Argument(help="Repository to scan.")] = ".",
    owner: Annotated[str, typer.Option(help="Person or team accountable for these findings.")] = ...,  # type: ignore[assignment]
    reason: Annotated[str, typer.Option(help="Why these findings are accepted.")] = ...,  # type: ignore[assignment]
    expires: Annotated[str | None, typer.Option(help="ISO date after which acceptance lapses.")] = None,
    baseline_file: Annotated[
        str, typer.Option("--baseline-file", help="Baseline to create or extend.")
    ] = "reposcan-baseline.json",
    config: Annotated[str | None, typer.Option(help="TOML config file.")] = None,
    scanners: Annotated[str | None, typer.Option(help="Comma-separated scanner subset.")] = None,
    from_report: Annotated[
        str | None, typer.Option(help="Use a saved JSON result instead of scanning.")
    ] = None,
    offline: Annotated[
        bool | None, typer.Option("--offline/--online", help="Disable scanner network access.")
    ] = None,
    allow_repo_ignore_files: Annotated[
        bool,
        typer.Option(
            help="Accept repository-supplied suppressions the scanners always honour (recorded as a warning)."
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Accept the current NEW findings into a baseline (owner and reason are mandatory)."""
    try:
        today = now_utc().date()
        expiry = _parse_date(expires, "--expires")
        existing = None
        target_file = Path(baseline_file).expanduser()
        if target_file.exists():
            existing = load_baseline(str(target_file))
        cfg = load_config(config)
        if from_report:
            result = _load_result(from_report)
        else:
            result = _execute_scan(
                path,
                config,
                str(target_file) if existing else None,
                scanners,
                "none",
                offline,
                None,
                False,
                None,
                allow_repo_ignore_files,
                verbose,
            )
        broken = [r for r in result.scanners if r.status != "ok"]
        if broken:
            raise ScannerError(
                "refusing to write a baseline from an incomplete scan: "
                + ", ".join(f"{r.name} ({r.status})" for r in broken)
            )
        candidates = result.new_findings
        baseline, added = add_to_baseline(
            existing,
            candidates,
            owner=owner,
            reason=reason,
            expires=expiry,
            today=today,
            config=cfg,
        )
        if added:
            save_baseline(baseline, target_file)
    except ReposcanError as exc:
        raise _fail(exc) from None
    _echo(f"baseline: {len(added)} finding(s) accepted, {len(baseline.entries)} total entries")
    for f in added:
        _echo(f"  + [{f.severity.value}] {f.scanner}:{f.rule_id} {f.file or f.artifact or ''}")
    if added:
        _echo(f"wrote {target_file}")
        _echo("review the file, then commit it under CODEOWNERS protection")
    else:
        _echo("nothing to add; baseline unchanged")


@baseline_app.command("review")
def baseline_review(
    baseline_file: Annotated[str, typer.Argument(help="Baseline JSON to review.")] = "reposcan-baseline.json",
    report: Annotated[
        str | None, typer.Option(help="Saved JSON result; enables stale-entry detection.")
    ] = None,
    strict: Annotated[
        bool, typer.Option(help="Exit 1 when any entry is EXPIRED, STALE or has no expiry.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List baseline entries with owner, reason, expiry and health."""
    try:
        baseline = load_baseline(baseline_file)
        current = None
        if report:
            current = list(_load_result(report).findings)
        rows = review_baseline(baseline, current, now_utc().date())
    except ReposcanError as exc:
        raise _fail(exc) from None
    if as_json:
        typer.echo(json.dumps(rows, indent=2, sort_keys=True))
    else:
        _echo(f"{len(rows)} baseline entr{'y' if len(rows) == 1 else 'ies'}")
        for r in rows:
            _echo(
                f"  {r['fingerprint'][:12]} {r['severity']:<8} {r['rule']:<34} {r['file']:<28} "
                f"owner={r['owner']} expires={r['expires']} [{r['health']}] {r['reason']}"
            )
    unhealthy = [r for r in rows if r["health"] != "ok" and r["health"] != "expires-soon"]
    raise typer.Exit(int(ExitCode.POLICY_FAILED) if strict and unhealthy else 0)


def _load_result(path: str) -> ScanResult:
    file = validate_file_arg(path, "report file", max_bytes=MAX_REPORT_INPUT_BYTES)
    try:
        return ScanResult.model_validate(json.loads(file.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ConfigError("report file is not valid JSON") from None
    except ValidationError as exc:
        raise ConfigError(
            f"report file does not match the reposcan schema: {format_validation_error(exc)}"
        ) from None


@report_app.command("render")
def report_render(
    input_file: Annotated[str, typer.Option("--input", help="reposcan JSON result.")],
    formats: Annotated[str, typer.Option("--format", help=f"Comma-separated: {','.join(FORMATS)}.")] = "html",
    output_dir: Annotated[str, typer.Option(help="Where reports are written.")] = "reposcan-output",
) -> None:
    """Re-render reports from a saved JSON result (validated against the schema)."""
    try:
        result = _load_result(input_file)
        out = Path(output_dir).expanduser()
        written = write_reports(result, out.resolve(), _split(formats))
    except ReposcanError as exc:
        raise _fail(exc) from None
    for p in written:
        _echo(f"wrote {p}")


@report_app.command("show")
def report_show(
    input_file: Annotated[str, typer.Option("--input", help="reposcan JSON result.")],
    status: Annotated[str | None, typer.Option(help="Only this status: new, baseline or suppressed.")] = None,
    scanner: Annotated[str | None, typer.Option(help="Only this scanner.")] = None,
) -> None:
    """Print findings from a saved JSON result as a compact table."""
    try:
        result = _load_result(input_file)
    except ReposcanError as exc:
        raise _fail(exc) from None
    rows = [
        f
        for f in result.findings
        if (status is None or f.status.value == status) and (scanner is None or f.scanner == scanner)
    ]
    _echo(f"{len(rows)} finding(s)")
    for f in rows:
        where = f"{f.file}:{f.line}" if f.file and f.line else (f.file or f.artifact or "-")
        dep = f" {f.dependency.name} {f.dependency.installed_version}" if f.dependency else ""
        _echo(f"{f.severity.value.upper():<8} {f.status.value:<10} {f.scanner:<11} {f.rule_id}  {where}{dep}")
        if f.evidence:
            _echo(f"           evidence: {f.evidence}")


@config_app.command("validate")
def config_validate(file: Annotated[str, typer.Argument(help="TOML config file.")]) -> None:
    """Validate a configuration file without scanning."""
    try:
        cfg = load_config(file)
        for rules in cfg.scanners.semgrep.rules:
            _echo(f"semgrep rules: {rules}")
    except ReposcanError as exc:
        raise _fail(exc) from None
    _echo(f"config OK: {cfg.source} (fail_on={cfg.policy.fail_on}, suppressions={len(cfg.suppressions)})")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        _echo("cancelled", err=True)
        sys.exit(int(ExitCode.CANCELLED))
    except Exception as exc:  # last line of defence: a crash must never look like exit 1
        _echo(
            f"internal error ({type(exc).__name__}): {sanitize(str(exc), limit=300)}. "
            "This is a bug in reposcan; please report it (see SECURITY.md if it involves a leak).",
            err=True,
        )
        sys.exit(int(ExitCode.INTERNAL_ERROR))


__all__ = ["app", "main", "write_text_safely"]
