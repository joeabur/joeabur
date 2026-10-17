"""Typer command line interface. Exit codes are documented in docs/user-guide.md."""

from __future__ import annotations

import functools
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, NoReturn, TypeVar

import typer
from pydantic import ValidationError

from fim import __version__, reporting, service
from fim.config import Config, load_config
from fim.errors import (
    BaselineError,
    ConfigError,
    DependencyError,
    FimError,
    LockError,
    TrustError,
    WatcherError,
)
from fim.models import Report

EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_USAGE = 2  # also Typer/Click's own usage-error code
EXIT_INCOMPLETE = 3
EXIT_UNTRUSTED = 4
EXIT_EXPORT = 5
EXIT_OPERATIONAL = 6

DEFAULT_CONFIG = "/etc/fim/fim.toml"
app = typer.Typer(
    name="fim",
    help="File Integrity Monitor: trusted baselines, change detection, evidence-backed alerts.",
    no_args_is_help=True,
    add_completion=False,
)
baseline_app = typer.Typer(help="Create, update, inspect and verify baselines.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect the baseline audit trail.", no_args_is_help=True)
report_app = typer.Typer(help="Convert saved JSON reports.", no_args_is_help=True)
config_app = typer.Typer(help="Validate configuration.", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")
app.add_typer(audit_app, name="audit")
app.add_typer(report_app, name="report")
app.add_typer(config_app, name="config")

F = TypeVar("F", bound=Callable[..., Any])


def _die(msg: str, code: int) -> NoReturn:
    typer.echo(f"error: {msg}", err=True)
    raise typer.Exit(code)


def guarded(fn: F) -> F:
    """Translate FimError subclasses into stable exit codes and one-line messages."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except TrustError as exc:
            _die(f"{exc}\nthe baseline is NOT trusted; see docs/troubleshooting.md", EXIT_UNTRUSTED)
        except ConfigError as exc:
            _die(str(exc), EXIT_USAGE)
        except (BaselineError, LockError, DependencyError, WatcherError) as exc:
            _die(str(exc), EXIT_OPERATIONAL)
        except FimError as exc:
            _die(str(exc), EXIT_EXPORT)

    return wrapper  # type: ignore[return-value]


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", envvar="FIM_CONFIG", help=f"TOML config (default {DEFAULT_CONFIG})"),
    ] = None,
) -> None:
    ctx.obj = {"config_path": str(config) if config else DEFAULT_CONFIG}


def _cfg(ctx: typer.Context) -> Config:
    return load_config(ctx.obj["config_path"])


def _is_interactive() -> bool:
    return sys.stdin.isatty()


def _passphrase() -> bytes | None:
    v = os.environ.get("FIM_KEY_PASSPHRASE")
    return v.encode() if v else None


def _warn(msgs: list[str]) -> None:
    for m in msgs:
        typer.echo(f"warning: {m}", err=True)


def _signer(cfg: Config, sign_key: Path | None) -> service.Signer | None:
    signer = service.make_signer(cfg, str(sign_key), _passphrase()) if sign_key else None
    service.require_signer_if_needed(cfg, signer)
    return signer


@app.command("version")
def version() -> None:
    """Print the version."""
    typer.echo(f"fim {__version__}")


# ------------------------------------------------------------------ config
@config_app.command("check")
@guarded
def config_check(ctx: typer.Context) -> None:
    """Validate the configuration file (syntax, schema, baseline location)."""
    cfg = _cfg(ctx)
    typer.echo(f"configuration OK: {ctx.obj['config_path']}")
    typer.echo(f"  roots: {', '.join(cfg.scan.roots)}")
    typer.echo(f"  baseline.dir: {cfg.baseline.dir}")
    typer.echo(f"  symlinks: {cfg.scan.symlinks}  exclusions: {len(cfg.scan.exclude)}")
    typer.echo(f"  signature verification: {'on' if cfg.baseline.public_key else 'off'}")


# ------------------------------------------------------------------ baseline
def _scan_for_baseline(cfg: Config, allow_incomplete: bool) -> Any:
    result = service.scan_now(cfg)
    if not result.complete and not allow_incomplete:
        typer.echo(
            f"scan INCOMPLETE: {len(result.issues)} issue(s); refusing to write a "
            "baseline with gaps (re-run with --allow-incomplete to accept them knowingly):",
            err=True,
        )
        for i in result.issues[:20]:
            typer.echo(f"  {i.kind.value}: {i.path} {i.detail}", err=True)
        raise typer.Exit(EXIT_INCOMPLETE)
    return result


@baseline_app.command("create")
@guarded
def baseline_create(
    ctx: typer.Context,
    reason: Annotated[str, typer.Option(help="Recorded in the audit trail")] = "initial baseline",
    force: Annotated[
        bool, typer.Option("--force", help="Create even though a baseline already exists")
    ] = False,
    allow_incomplete: Annotated[bool, typer.Option(help="Accept a scan with issues")] = False,
    sign_key: Annotated[Path | None, typer.Option(help="Ed25519 private key to sign with")] = None,
) -> None:
    """Scan the configured roots and write the first trusted baseline."""
    cfg = _cfg(ctx)
    store = service.store_for(cfg)
    signer = _signer(cfg, sign_key)
    if not force and store.dir.exists() and store.current_version() is not None:
        _die(
            "a baseline already exists; use 'fim baseline update' (reviewed) or --force to start "
            "a new version after an incident",
            EXIT_OPERATIONAL,
        )
    result = _scan_for_baseline(cfg, allow_incomplete)
    b = service.baseline_from_scan(
        store, cfg, result, action="create", reason=reason, signer=signer,
        detail={"forced": force},
    )  # fmt: skip
    typer.echo(f"baseline v{b.version} written to {store.path_for(b.version)}")
    typer.echo(f"  entries: {len(b.entries)}  hashed bytes: {result.bytes_hashed}")
    typer.echo(f"  complete: {str(b.complete).lower()}  signed: {str(signer is not None).lower()}")
    typer.echo(f"  content sha256: {b.content_sha256}")
    if not b.complete:
        raise typer.Exit(EXIT_INCOMPLETE)


@baseline_app.command("update")
@guarded
def baseline_update(
    ctx: typer.Context,
    reason: Annotated[str, typer.Option(help="Why this change is authorised (required)")],
    yes: Annotated[bool, typer.Option("--yes", help="Non-interactive confirmation")] = False,
    allow_incomplete: Annotated[bool, typer.Option(help="Accept a scan with issues")] = False,
    sign_key: Annotated[Path | None, typer.Option(help="Ed25519 private key to sign with")] = None,
) -> None:
    """Accept the current state of the filesystem as the new baseline (explicit confirmation)."""
    cfg = _cfg(ctx)
    store = service.store_for(cfg)
    signer = _signer(cfg, sign_key)
    if not reason.strip():
        _die("--reason must not be empty", EXIT_USAGE)
    trusted = service.load_trusted(cfg, store)  # never re-baseline on top of an untrusted one
    _warn(trusted.warnings)
    report, result = service.run_scan(cfg, trusted)
    typer.echo(reporting.render_text(report, threshold=cfg.policy.alert_threshold))
    if not result.complete and not allow_incomplete:
        _die("scan is incomplete; fix the issues above or pass --allow-incomplete", EXIT_INCOMPLETE)
    if not yes:
        if not _is_interactive():
            _die("confirmation required: run interactively or pass --yes", EXIT_USAGE)
        answer = typer.prompt(
            f"Accept ALL {report.summary.event_count} change(s) above as the new baseline? "
            'Type "yes" to continue'
        )
        if answer.strip().lower() != "yes":
            typer.echo("aborted; baseline unchanged")
            raise typer.Exit(EXIT_USAGE)
    new = service.baseline_from_scan(
        store, cfg, result, action="update", reason=reason, signer=signer,
        detail={"previous_version": trusted.baseline.version,
                "previous_sha256": trusted.baseline.content_sha256,
                "accepted_events": service.change_counts(report)},
    )  # fmt: skip
    typer.echo(f"baseline updated: v{trusted.baseline.version} -> v{new.version}")
    typer.echo(f"  signed: {str(signer is not None).lower()}  audit reason: {reason.strip()}")


@baseline_app.command("verify")
@guarded
def baseline_verify(
    ctx: typer.Context,
    version: Annotated[int | None, typer.Option(help="Specific version (default: current)")] = None,
) -> None:
    """Check baseline integrity, signature and audit-trail consistency (no filesystem scan)."""
    cfg = _cfg(ctx)
    store = service.store_for(cfg)
    trusted = service.load_trusted(cfg, store, version)
    n = store.verify_audit() if store.audit_path.exists() else 0
    b = trusted.baseline
    typer.echo(f"baseline v{b.version}: integrity OK (sha256 {b.content_sha256[:16]}…)")
    typer.echo(f"signature: {trusted.signature}")
    typer.echo(f"audit trail: {n} record(s), hash chain OK")
    _warn(trusted.warnings)


@baseline_app.command("list")
@guarded
def baseline_list(ctx: typer.Context) -> None:
    """List stored baseline versions."""
    cfg = _cfg(ctx)
    store = service.store_for(cfg)
    store.ensure_dir(create=False)
    cur = store.current_version()
    for v in store.versions():
        signed = "signed" if store.sig_path_for(v).exists() else "unsigned"
        typer.echo(f"v{v:<4} {'CURRENT' if v == cur else '       '} {signed}  {store.path_for(v)}")


@baseline_app.command("show")
@guarded
def baseline_show(
    ctx: typer.Context,
    version: Annotated[int | None, typer.Option()] = None,
    entries: Annotated[bool, typer.Option("--entries", help="List every recorded path")] = False,
) -> None:
    """Show baseline metadata (and optionally every entry)."""
    cfg = _cfg(ctx)
    store = service.store_for(cfg)
    store.ensure_dir(create=False)
    b = store.load(version).baseline
    typer.echo(f"version: {b.version}\ncreated_at: {b.created_at}\nhostname: {b.hostname}")
    typer.echo(f"tool_version: {b.tool_version}\ncomplete: {str(b.complete).lower()}")
    typer.echo(f"roots: {', '.join(b.roots)}\nentries: {len(b.entries)}")
    typer.echo(f"content_sha256: {b.content_sha256}\nprev_sha256: {b.prev_sha256}")
    if entries:
        for p, r in b.entries.items():
            typer.echo(f"{r.type.value:<8} {r.mode} {r.uid}:{r.gid} {r.size:>10} {r.sha256 or '-'} {p}")


# ------------------------------------------------------------------ scan
@app.command("scan")
@guarded
def scan(
    ctx: typer.Context,
    root: Annotated[
        list[Path] | None, typer.Option("--root", help="Limit to a subtree of a configured root")
    ] = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write JSON report here")] = None,
    csv_out: Annotated[
        Path | None, typer.Option("--csv", help="Write events CSV here (+ .issues.csv)")
    ] = None,
    syslog: Annotated[bool, typer.Option("--syslog", help="Send events per [export.syslog]")] = False,
    overwrite: Annotated[bool, typer.Option(help="Allow replacing existing output files")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="No human-readable output")] = False,
) -> None:
    """Verify the filesystem against the trusted baseline."""
    cfg = _cfg(ctx)
    if syslog and not cfg.export.syslog:
        _die("--syslog needs an [export.syslog] section in the config", EXIT_USAGE)
    store = service.store_for(cfg)
    trusted = service.load_trusted(cfg, store)
    _warn(trusted.warnings)
    report, _ = service.run_scan(cfg, trusted, [str(r) for r in root] if root else None)
    if not quiet:
        typer.echo(reporting.render_text(report, threshold=cfg.policy.alert_threshold), nl=False)
    exit_code = _emit_exports(cfg, report, json_out, csv_out, syslog, overwrite)
    s = report.summary
    if not s.complete:
        exit_code = EXIT_INCOMPLETE
    elif s.alert:
        exit_code = EXIT_CHANGES
    if exit_code:
        raise typer.Exit(exit_code)


def _emit_exports(
    cfg: Config,
    report: Report,
    json_out: Path | None,
    csv_out: Path | None,
    syslog: bool,
    overwrite: bool,
) -> int:
    code = EXIT_OK
    if json_out:
        reporting.write_output(json_out, reporting.report_json(report), overwrite=overwrite)
    if csv_out:
        reporting.write_output(csv_out, reporting.events_csv(report), overwrite=overwrite)
        reporting.write_output(
            reporting.issues_path_for(csv_out), reporting.issues_csv(report), overwrite=overwrite
        )
    if syslog and cfg.export.syslog:
        try:
            reporting.send_syslog(
                reporting.syslog_messages(report, cfg.export.syslog), cfg.export.syslog.address
            )
        except FimError as exc:
            typer.echo(f"error: {exc}", err=True)
            code = EXIT_EXPORT
    return code


# ------------------------------------------------------------------ report convert
@report_app.command("convert")
@guarded
def report_convert(
    input_file: Annotated[Path, typer.Argument(metavar="REPORT_JSON")],
    fmt: Annotated[str, typer.Option("--format", help="text | csv | cef | rfc5424")] = "text",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    overwrite: Annotated[bool, typer.Option()] = False,
) -> None:
    """Re-render a saved JSON report as text, CSV, CEF or RFC 5424 syslog lines."""
    try:
        if input_file.stat().st_size > 256 * 1024 * 1024:
            _die("report is larger than 256 MiB", EXIT_USAGE)
        report = Report.model_validate(json.loads(input_file.read_bytes()))
    except (OSError, ValueError, ValidationError) as exc:
        _die(f"{input_file} is not a valid fim report: {exc}", EXIT_USAGE)
    from fim.config import SyslogConfig

    if fmt == "text":
        data = reporting.render_text(report).encode()
    elif fmt == "csv":
        data = reporting.events_csv(report)
        if output:
            reporting.write_output(
                reporting.issues_path_for(output), reporting.issues_csv(report), overwrite=overwrite
            )
    elif fmt in ("cef", "rfc5424"):
        # conversion output is for forwarding, so use the network (RFC 5424) framing, not local BSD framing
        sc = SyslogConfig(format=fmt, min_severity="info", address="udp://127.0.0.1:514")
        data = ("\n".join(reporting.syslog_messages(report, sc)) + "\n").encode()
    else:
        _die(f"unknown format {fmt!r}", EXIT_USAGE)
    if output:
        reporting.write_output(output, data, overwrite=overwrite)
    else:
        sys.stdout.buffer.write(data)


# ------------------------------------------------------------------ keys
@app.command("keygen")
@guarded
def keygen(
    ctx: typer.Context,
    private: Annotated[Path, typer.Option(help="Where to write the PRIVATE key (mode 0600)")],
    public: Annotated[Path, typer.Option(help="Where to write the public key")],
) -> None:
    """Generate an Ed25519 signing keypair. Set FIM_KEY_PASSPHRASE to encrypt the private key."""
    from fim import signing

    priv, pub = os.path.abspath(private), os.path.abspath(public)
    cfg_path = ctx.obj["config_path"]
    if os.path.exists(cfg_path):  # keep keys away from the baseline and the monitored roots
        cfg = load_config(cfg_path)
        for label, p in (("private key", priv), ("public key", pub)):
            real = os.path.realpath(p)
            from fim.pathutil import is_within

            if is_within(real, os.path.realpath(cfg.baseline.dir)) or any(
                is_within(real, os.path.realpath(r)) for r in cfg.scan.roots
            ):
                _die(
                    f"{label} path must be outside the baseline directory and monitored roots",
                    EXIT_USAGE,
                )
    try:
        kid = signing.generate_keypair(priv, pub, _passphrase())
    except FileExistsError as exc:
        _die(f"refusing to overwrite existing file: {exc.filename}", EXIT_OPERATIONAL)
    typer.echo(f"key id: {kid}")
    typer.echo(f"private key: {priv} (mode 0600, encrypted: {str(bool(_passphrase())).lower()})")
    typer.echo(f"public key:  {pub}")
    typer.echo("Move the private key off this host (or into an HSM/offline store); never commit it.")


@app.command("sign")
@guarded
def sign(
    ctx: typer.Context,
    key: Annotated[Path, typer.Option(help="Ed25519 private key")],
    version: Annotated[int | None, typer.Option()] = None,
    reason: Annotated[str, typer.Option()] = "baseline signed",
) -> None:
    """Create/replace the detached signature of an existing baseline (e.g. after key rotation)."""
    cfg = _cfg(ctx)
    store = service.store_for(cfg)
    signer = service.make_signer(cfg, str(key), _passphrase())
    loaded = store.load(version)
    sig_text, kid = signer(loaded.raw)
    store.write_signature(loaded.baseline.version, sig_text, reason=reason, key_id=kid)
    typer.echo(f"signed baseline v{loaded.baseline.version} with {kid}")


# ------------------------------------------------------------------ audit
@audit_app.command("show")
@guarded
def audit_show(ctx: typer.Context, as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Print audit records."""
    store = service.store_for(_cfg(ctx))
    store.ensure_dir(create=False)
    for rec in store.read_audit():
        if as_json:
            typer.echo(json.dumps(rec, sort_keys=True))
        else:
            typer.echo(
                f"#{rec['seq']} {rec['timestamp']} {rec['action']:<7} v{rec['baseline_version']} "
                f"user={rec['user']}(uid {rec['uid']}) reason={rec['reason']!r}"
            )


@audit_app.command("verify")
@guarded
def audit_verify(ctx: typer.Context) -> None:
    """Verify the audit hash chain."""
    store = service.store_for(_cfg(ctx))
    store.ensure_dir(create=False)
    typer.echo(f"audit trail OK: {store.verify_audit()} record(s)")


# ------------------------------------------------------------------ watch
@app.command("watch")
@guarded
def watch(
    ctx: typer.Context,
    syslog: Annotated[bool, typer.Option("--syslog")] = False,
    max_seconds: Annotated[float | None, typer.Option(hidden=True)] = None,
) -> None:
    """Real-time monitoring (needs the 'watch' extra); also runs periodic full scans."""
    from fim.watcher import Watcher

    cfg = _cfg(ctx)
    if syslog and not cfg.export.syslog:
        _die("--syslog needs an [export.syslog] section in the config", EXIT_USAGE)
    store = service.store_for(cfg)
    trusted = service.load_trusted(cfg, store)
    _warn(trusted.warnings)

    def on_report(report: Report) -> None:
        typer.echo(report.model_dump_json())  # one compact JSON document per line (JSON Lines)
        if syslog and cfg.export.syslog:
            try:
                reporting.send_syslog(
                    reporting.syslog_messages(report, cfg.export.syslog), cfg.export.syslog.address
                )
            except FimError as exc:
                typer.echo(f"error: {exc}", err=True)

    def full_scan() -> None:
        report, _ = service.run_scan(cfg, service.load_trusted(cfg, store))
        if report.events or not report.summary.complete:
            on_report(report)

    watcher = Watcher(cfg, trusted.baseline, on_report, full_scan)
    typer.echo(
        f"watching {', '.join(cfg.scan.roots)} (Ctrl-C to stop; periodic full scan every "
        f"{cfg.watch.full_scan_interval_seconds}s)",
        err=True,
    )
    try:
        watcher.run(max_seconds=max_seconds)
    except KeyboardInterrupt:
        watcher.stop()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
