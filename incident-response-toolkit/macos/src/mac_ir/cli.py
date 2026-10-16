"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import PACKAGE, PLATFORM_LABEL, TOOL_NAME, __version__
from .analyze import analyze
from .collect import plan_collection, run_collection
from .collectors import REGISTRY
from .config import ConfigError, load_config, redaction_patterns
from .context import Context
from .detections.engine import RuleError
from .evidence.manifest import EvidenceError, build_manifest, verify_manifest, write_manifest
from .ioc.schema import IocError
from .models import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED
from .platform_info import detect_platform, doctor_checks
from .reporting.report import build_report, write_reports
from .utils.redact import Redactor
from .utils.run import euid


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=f"python -m {PACKAGE}",
        description=f"{TOOL_NAME}: read-only {PLATFORM_LABEL} incident-response collection and analysis. "
        "Use only on systems you are authorised to investigate.",
        epilog="Exit codes: 0 ok · 1 error · 2 usage · 3 verification failed · 10 findings present "
        "(only with --fail-on-findings).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    p.add_argument("--config", type=Path, help="YAML configuration file (see docs/configuration.md)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="show platform information").add_argument("--json", action="store_true")
    sub.add_parser("doctor", help="check readiness: platform, privileges, native utilities")
    c = sub.add_parser("collect", help="collect evidence (read-only)")
    c.add_argument("--profile", default="basic", help="collection profile: basic | extended (default basic)")
    c.add_argument("--output", type=Path, required=True, help="parent directory; a unique sub-directory is created")
    c.add_argument("--collectors", help="comma-separated subset: " + ",".join(REGISTRY))
    c.add_argument("--dry-run", action="store_true", help="print planned operations; collect nothing")
    c.add_argument("--log-hours", type=int, help="log time window in hours (default from config)")
    c.add_argument(
        "--import-log", action="append", type=Path, default=[], help="also import this exported ndjson log file"
    )
    c.add_argument(
        "--import-archive", action="append", type=Path, default=[], help="also read this .logarchive bundle (read-only)"
    )
    c.add_argument(
        "--allow-unsupported-os",
        action="store_true",
        help="attempt live collection on a non-macOS system (testing only)",
    )
    for name, helptext in (
        ("scan", "analyse evidence: detections and IOC matching"),
        ("report", "generate JSON/CSV/Markdown reports"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--input", type=Path, required=True, help="evidence directory")
        s.add_argument("--iocs", type=Path, help="IOC file (JSON or YAML)")
        s.add_argument("--rules", type=Path, help="rules directory (default: ./rules or $IR_TOOLKIT_RULES)")
        s.add_argument("--baseline", type=Path, help="earlier evidence directory for baseline-diff rules")
        s.add_argument("--allow-unverified", action="store_true", help="analyse even if manifest verification fails")
        if name == "scan":
            s.add_argument("--json", action="store_true", help="print findings as JSON")
            s.add_argument("--fail-on-findings", action="store_true", help="exit 10 when any finding exists")
        else:
            s.add_argument("--output", type=Path, required=True, help="report directory (files are never overwritten)")
    v = sub.add_parser("verify-manifest", help="verify evidence hashes against manifest.json")
    v.add_argument("--input", type=Path, required=True)
    v.add_argument("--json", action="store_true")
    sl = sub.add_parser(
        "seal", help="create manifest.json for an existing artifacts/ directory (imported/synthetic evidence)"
    )
    sl.add_argument("--input", type=Path, required=True)
    return p


def _redactor(cfg: dict) -> Redactor:
    return Redactor(redaction_patterns(cfg), cfg["redaction"]["enabled"])


def _cmd_info(args: argparse.Namespace) -> int:
    info = detect_platform()
    if args.json:
        print(json.dumps(info, indent=2))
        return EXIT_OK
    print(f"{TOOL_NAME} {__version__}")
    for k in ("system", "pretty_name", "kernel", "architecture", "version_supported", "python", "euid"):
        print(f"{k:14}: {info.get(k)}")
    print(f"{'timestamp':14}: {info['timestamp_utc']}")
    return EXIT_OK


def _cmd_doctor(_: argparse.Namespace) -> int:
    info = detect_platform()
    checks = doctor_checks(info)
    for status, name, detail in checks:
        print(f"[{status:4}] {name}: {detail}")
    if not info["is_root"]:
        print(
            "\nNote: this tool never calls sudo. Some sources need elevated access; you decide whether to re-run "
            "individual collectors as root (see docs/security-and-limitations.md)."
        )
    return EXIT_ERROR if any(s == "FAIL" for s, _, _ in checks) else EXIT_OK


def _cmd_collect(args: argparse.Namespace, cfg: dict) -> int:
    profiles = cfg["profiles"]
    if args.profile not in profiles:
        print(f"error: unknown profile {args.profile!r}; available: {', '.join(profiles)}", file=sys.stderr)
        return EXIT_USAGE
    names = profiles[args.profile]["collectors"]
    if args.collectors:
        names = [n.strip() for n in args.collectors.split(",") if n.strip()]
        bad = [n for n in names if n not in REGISTRY]
        if bad:
            print(f"error: unknown collector(s) {bad}; available: {', '.join(REGISTRY)}", file=sys.stderr)
            return EXIT_USAGE
    hours = args.log_hours if args.log_hours is not None else cfg["logs"]["window_hours"]
    if not 1 <= hours <= 2160:
        print("error: --log-hours must be between 1 and 2160", file=sys.stderr)
        return EXIT_USAGE
    for lg in args.import_log:
        if not lg.is_file():
            print(f"error: --import-log file not found: {lg}", file=sys.stderr)
            return EXIT_USAGE
    for arc in args.import_archive:
        if not arc.is_dir() or arc.suffix != ".logarchive":
            print(f"error: --import-archive must be an existing .logarchive directory: {arc}", file=sys.stderr)
            return EXIT_USAGE
    ctx = Context(
        config=cfg,
        redactor=_redactor(cfg),
        deep=profiles[args.profile]["deep"],
        log_window_hours=hours,
        import_logs=args.import_log,
        import_archives=args.import_archive,
    )
    if args.dry_run:
        print(
            f"DRY RUN: profile={args.profile}; nothing will be collected or written. Output would go under "
            f"{args.output}/<host>-<UTC time>-<id>/"
        )
        for step in plan_collection(ctx, names):
            print(f"\n[{step['collector']}] {step['description']}\n  privileges: {step['privilege_note']}")
            for op in step["operations"]:
                print(f"  - {op}")
        return EXIT_OK
    if not detect_platform()["is_macos"] and not args.allow_unsupported_os:
        print(
            "error: live collection is only supported on macOS (this system is not Darwin). Use --dry-run to preview, "
            "or run scan/report/verify-manifest on evidence collected from a Mac. See docs/security-and-limitations.md.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if euid() == 0:
        print(
            "note: running as root. Collection remains read-only, but the evidence may contain more sensitive data.",
            file=sys.stderr,
        )
    evdir, digest, manifest = run_collection(ctx, args.profile, names, args.output)
    print(f"Evidence collected: {evdir}")
    print(f"Manifest SHA-256 (store a copy separately): {digest}")
    for a in manifest["artifacts"]:
        print(f"  {a['name']:12} {a['status']:11} records={a['record_count']:<6} errors={len(a['errors'])}")
    if any(a["status"] in ("partial", "failed") for a in manifest["artifacts"]):
        print(
            "Some data is missing (see manifest errors). Missing data is NOT evidence of absence of activity. "
            "Re-run specific collectors with appropriate privileges if justified."
        )
    print(f"EVIDENCE_DIR={evdir}")
    return EXIT_OK


def _cmd_analyze(args: argparse.Namespace, cfg: dict) -> int:
    if not args.input.is_dir():
        print(f"error: evidence directory not found: {args.input}", file=sys.stderr)
        return EXIT_USAGE
    for opt in (args.iocs, args.baseline, args.rules):
        if opt is not None and not opt.exists():
            print(f"error: path not found: {opt}", file=sys.stderr)
            return EXIT_USAGE
    result = analyze(args.input, cfg, args.iocs, args.rules, args.baseline)
    ver = result["verification"]
    if ver is not None and not ver["ok"] and not args.allow_unverified:
        print(
            "error: evidence integrity verification FAILED (modified="
            f"{len(ver['modified'])}, missing={len(ver['missing'])}, unexpected={len(ver['unexpected'])}). "
            "Re-run with --allow-unverified to analyse anyway.",
            file=sys.stderr,
        )
        return EXIT_VERIFY_FAILED
    findings = result["findings"]
    if args.command == "scan":
        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            if ver is not None and not ver["ok"]:
                print("WARNING: analysing evidence that FAILED integrity verification")
            print(f"{len(findings)} finding(s) from {result['rules_count']} rules")
            for f in findings:
                print(
                    f"[{f.severity.upper():8}/{f.confidence:6}] {f.rule_id} {f.title}\n    {f.why}\n    ref: {f.evidence_ref}"
                )
            for n in result["notes"]:
                print(f"note: {n}")
            print("A finding is a lead, not a verdict. Missing coverage is not a clean result.")
        return EXIT_FINDINGS if (args.fail_on_findings and findings) else EXIT_OK
    report = build_report(
        result["artifacts"], result["manifest"], findings, result["ioc_meta"], result["notes"], ver, _redactor(cfg)
    )
    written = write_reports(report, args.output, args.input / "manifest.json")
    for w in written:
        print(f"wrote {w}")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    if not args.input.is_dir():
        print(f"error: evidence directory not found: {args.input}", file=sys.stderr)
        return EXIT_USAGE
    res = verify_manifest(args.input)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if res["error"]:
            print(f"ERROR: {res['error']}")
        else:
            print(f"Manifest SHA-256: {res['manifest_sha256']}")
            print(f"Verified files : {res['verified']}")
            for key in ("modified", "missing", "unexpected", "unsafe"):
                for item in res[key]:
                    print(f"{key.upper():10}: {item}")
            print("RESULT: " + ("PASS: all hashes match" if res["ok"] else "FAIL: evidence differs from manifest"))
    return EXIT_OK if res["ok"] else EXIT_VERIFY_FAILED


def _cmd_seal(args: argparse.Namespace) -> int:
    if not (args.input / "artifacts").is_dir():
        print("error: --input must contain an artifacts/ directory", file=sys.stderr)
        return EXIT_USAGE
    if (args.input / "manifest.json").exists():
        print("error: manifest.json already exists; refusing to overwrite", file=sys.stderr)
        return EXIT_ERROR
    from .utils.timeutil import utcnow_iso

    manifest = build_manifest(
        args.input,
        {
            "platform": PLATFORM_LABEL,
            "profile": "imported",
            "collectors_requested": [],
            "started_at": None,
            "finished_at": utcnow_iso(),
            "host": {"hostname": "imported"},
            "privileged": False,
            "euid": None,
            "not_run": {},
        },
    )
    _, digest = write_manifest(args.input, manifest)
    print(f"sealed {args.input}; manifest SHA-256 {digest}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
        if args.command == "info":
            return _cmd_info(args)
        if args.command == "doctor":
            return _cmd_doctor(args)
        if args.command == "collect":
            return _cmd_collect(args, cfg)
        if args.command in ("scan", "report"):
            return _cmd_analyze(args, cfg)
        if args.command == "verify-manifest":
            return _cmd_verify(args)
        if args.command == "seal":
            return _cmd_seal(args)
    except (ConfigError, RuleError, IocError, EvidenceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileExistsError as exc:
        print(f"error: refusing to overwrite existing file: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except PermissionError as exc:
        print(f"error: permission denied: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_USAGE
