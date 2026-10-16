"""Adapter behaviour: parsing real captured output and every failure mode."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from reposcan.adapters import GitleaksAdapter, OsvAdapter, SemgrepAdapter, TrivyAdapter
from reposcan.adapters.base import ScanContext, ScannerAdapter, parse_version
from reposcan.config import Config
from reposcan.schemas import FindingKind, Severity

from ..helpers import fixture_text, make_fake_scanner


def make_ctx(target: Path, tmp_path: Path, config: Config | None = None, **kw: object) -> ScanContext:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return ScanContext(
        target=target.resolve(),
        workdir=work,
        config=config or Config(),
        offline=False,
        timeout=20,
        max_output_bytes=5_000_000,
        **kw,  # type: ignore[arg-type]
    )


def run(adapter: ScannerAdapter, bin_dir: Path, tmp_path: Path, repo: Path, **fake: object):  # type: ignore[no-untyped-def]
    make_fake_scanner(bin_dir, adapter.name, **fake)  # type: ignore[arg-type]
    return adapter.run(make_ctx(repo, tmp_path))


# ---- parsing real output ------------------------------------------------------------


def test_gitleaks_parses_real_output(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    out = run(
        GitleaksAdapter(),
        bin_dir,
        tmp_path,
        demo_repo,
        report=fixture_text("gitleaks-demo.json").replace("/repo", str(demo_repo)),
        exit_code=10,
    )
    assert out.run.status == "ok" and out.run.exit_code == 10
    assert {f.rule_id for f in out.findings} == {"reposcan-synthetic-token", "generic-api-key"}
    for f in out.findings:
        assert f.kind is FindingKind.SECRET and f.file == "app/settings.py" and f.cwe == ["CWE-798"]
        assert "AAAABBBBCCCC" not in (f.evidence or "")


def test_gitleaks_clean(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    out = run(GitleaksAdapter(), bin_dir, tmp_path, clean_repo, report="[]", exit_code=0)
    assert out.run.status == "ok" and out.findings == []


def test_semgrep_parses_real_output(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    report = fixture_text("semgrep-demo.json").replace("/repo", str(demo_repo))
    out = run(SemgrepAdapter(), bin_dir, tmp_path, demo_repo, report=report)
    assert out.run.status == "ok"
    by_rule = {f.rule_id: f for f in out.findings}
    assert set(by_rule) == {
        "reposcan.python.sql-string-concat",
        "reposcan.python.subprocess-shell-true",
        "reposcan.python.eval-call",
        "reposcan.python.weak-hash",
    }
    sql = by_rule["reposcan.python.sql-string-concat"]
    assert sql.severity is Severity.HIGH and sql.line == 13 and sql.file == "app/server.py"
    assert sql.cwe == ["CWE-89"] and "execute(query)" in (sql.evidence or "")
    assert by_rule["reposcan.python.weak-hash"].severity is Severity.MEDIUM


def test_trivy_parses_real_output(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    out = run(TrivyAdapter(), bin_dir, tmp_path, demo_repo, report=fixture_text("trivy-demo.json"))
    assert out.run.status == "ok"
    deps = [f for f in out.findings if f.kind is FindingKind.DEPENDENCY]
    mis = [f for f in out.findings if f.kind is FindingKind.MISCONFIGURATION]
    assert len(deps) == 13 and len(mis) == 3
    jinja = next(f for f in deps if f.rule_id == "CVE-2019-10906")
    assert jinja.file == "requirements.txt"
    assert (
        jinja.dependency and jinja.dependency.name == "Jinja2" and jinja.dependency.fixed_version == "2.10.1"
    )
    assert jinja.cve == ["CVE-2019-10906"] and jinja.severity is Severity.HIGH
    assert "Upgrade Jinja2 to 2.10.1" in (jinja.remediation or "")
    root = next(f for f in mis if f.rule_id.endswith("DS-0002") or f.rule_id == "DS-0002")
    assert root.file == "infra/Dockerfile" and root.severity is Severity.HIGH


def test_osv_parses_real_output_and_collapses_aliases(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    report = fixture_text("osv-scanner-demo.json").replace("/repo", str(demo_repo))
    out = run(OsvAdapter(), bin_dir, tmp_path, demo_repo, report=report, exit_code=1)
    assert out.run.status == "ok" and out.run.exit_code == 1
    keys = [(f.dependency.name if f.dependency else "", f.rule_id) for f in out.findings]
    assert len(keys) == len(set(keys)) == 13
    sample = next(f for f in out.findings if f.rule_id == "CVE-2019-10906")
    assert sample.severity is Severity.HIGH and sample.file == "requirements.txt"
    assert sample.dependency and sample.dependency.fixed_version == "2.10.1"


def test_fingerprints_are_unique_and_line_independent(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    report = json.loads(fixture_text("semgrep-demo.json").replace("/repo", str(demo_repo)))
    first = run(SemgrepAdapter(), bin_dir, tmp_path, demo_repo, report=json.dumps(report))
    for r in report["results"]:
        r["start"]["line"] += 40
        r["end"]["line"] += 40
    (demo_repo / "app" / "server.py").write_text("\n" * 40 + (demo_repo / "app" / "server.py").read_text())
    second = run(SemgrepAdapter(), bin_dir, tmp_path, demo_repo, report=json.dumps(report))
    assert {f.fingerprint for f in first.findings} == {f.fingerprint for f in second.findings}
    assert len({f.fingerprint for f in first.findings}) == len(first.findings)


def test_identical_lines_get_distinct_fingerprints(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    (demo_repo / "app" / "dup.py").write_text("eval(a)\neval(a)\n")
    row = {
        "check_id": "r.eval",
        "path": str(demo_repo / "app" / "dup.py"),
        "extra": {"severity": "ERROR", "message": "m", "lines": "requires login", "metadata": {}},
    }
    rows = [
        {**row, "start": {"line": n, "col": 1, "offset": n * 8}, "end": {"line": n, "col": 8}} for n in (1, 2)
    ]
    out = run(
        SemgrepAdapter(),
        bin_dir,
        tmp_path,
        demo_repo,
        report=json.dumps({"results": rows, "errors": []}),
    )
    assert len({f.fingerprint for f in out.findings}) == 2


# ---- failure modes ----------------------------------------------------------------------


@pytest.mark.parametrize("adapter_cls", [GitleaksAdapter, SemgrepAdapter, TrivyAdapter, OsvAdapter])
def test_scanner_absent(
    adapter_cls: type[ScannerAdapter], bin_dir: Path, tmp_path: Path, clean_repo: Path
) -> None:
    out = adapter_cls().run(make_ctx(clean_repo, tmp_path))
    assert out.run.status == "not_found" and "not installed" in (out.run.error or "")
    assert out.findings == []


@pytest.mark.parametrize("version", ["7.9.0", "9.0.0"])
def test_version_mismatch_is_an_error_by_default(
    version: str, bin_dir: Path, tmp_path: Path, clean_repo: Path
) -> None:
    out = run(GitleaksAdapter(), bin_dir, tmp_path, clean_repo, version=version)
    assert out.run.status == "version_mismatch" and "supported range" in (out.run.error or "")
    assert out.run.version == version


def test_version_mismatch_can_downgrade_to_warning(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", version="9.1.0", report="[]")
    cfg = Config.model_validate({"scan": {"version_policy": "warn"}})
    out = GitleaksAdapter().run(make_ctx(clean_repo, tmp_path, cfg))
    assert out.run.status == "ok" and any("supported range" in w for w in out.run.warnings)


def test_unexpected_exit_code_is_a_failure_not_clean(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    out = run(
        GitleaksAdapter(),
        bin_dir,
        tmp_path,
        clean_repo,
        exit_code=1,
        stderr="fatal: boom",
        report="[]",
    )
    assert out.run.status == "failed" and out.run.exit_code == 1 and "boom" in (out.run.error or "")


def test_osv_api_failure_exit_127_is_not_reported_as_clean(
    bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    """Observed with the real tool: exit 127 AND an empty-but-valid report when the API is unreachable."""
    out = run(
        OsvAdapter(),
        bin_dir,
        tmp_path,
        demo_repo,
        exit_code=127,
        report='{"results": []}',
        stderr="Post https://api.osv.dev/v1/querybatch: Forbidden",
    )
    assert out.run.status == "failed" and out.findings == []


def test_stderr_secrets_are_redacted_in_errors(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    secret = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
    out = run(
        GitleaksAdapter(),
        bin_dir,
        tmp_path,
        clean_repo,
        exit_code=2,
        stderr=f"auth failed token={secret}",
    )
    assert secret not in (out.run.error or "")


def test_timeout(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", sleep=30)
    ctx = make_ctx(clean_repo, tmp_path)
    ctx.timeout = 0.5
    out = GitleaksAdapter().run(ctx)
    assert out.run.status == "timeout"


def test_cancellation(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", sleep=30)
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    out = GitleaksAdapter().run(make_ctx(clean_repo, tmp_path, cancel=cancel))
    assert out.run.status == "cancelled"


def test_oversized_process_output(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", stdout_flood=3_000_000, report="[]")
    ctx = make_ctx(clean_repo, tmp_path)
    ctx.max_output_bytes = 500_000
    out = GitleaksAdapter().run(ctx)
    assert out.run.status == "failed" and "bytes of output" in (out.run.error or "")


def test_oversized_report_file(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", report="[" + "0," * 400_000 + "0]")
    ctx = make_ctx(clean_repo, tmp_path)
    ctx.max_output_bytes = 100_000
    out = GitleaksAdapter().run(ctx)
    assert out.run.status == "failed" and "limit" in (out.run.error or "")


@pytest.mark.parametrize("payload", ["{not json", "", "\x00\x01"])
def test_malformed_json(payload: str, bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    out = run(GitleaksAdapter(), bin_dir, tmp_path, clean_repo, report=payload)
    assert out.run.status == "malformed_output" and out.findings == []


@pytest.mark.parametrize(
    ("adapter_cls", "payload"),
    [
        (GitleaksAdapter, '{"unexpected": "object"}'),
        (GitleaksAdapter, '["not-an-object"]'),
        (SemgrepAdapter, '["list"]'),
        (SemgrepAdapter, '{"results": [{"check_id": 5}], "errors": "x"}'),
        (TrivyAdapter, '{"Results": "nope"}'),
        (OsvAdapter, '{"results": [{"packages": "x"}]}'),
    ],
)
def test_unexpected_structure(
    adapter_cls: type[ScannerAdapter], payload: str, bin_dir: Path, tmp_path: Path, clean_repo: Path
) -> None:
    out = run(adapter_cls(), bin_dir, tmp_path, clean_repo, report=payload)
    assert out.run.status == "malformed_output"


def test_missing_report_file(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    out = run(GitleaksAdapter(), bin_dir, tmp_path, clean_repo, write_report=False)
    assert out.run.status == "failed" and "did not produce a report" in (out.run.error or "")


def test_semgrep_fatal_errors_are_not_clean(bin_dir: Path, tmp_path: Path, clean_repo: Path) -> None:
    payload = json.dumps({"results": [], "errors": [{"level": "error", "type": "Rule parse error"}]})
    out = run(SemgrepAdapter(), bin_dir, tmp_path, clean_repo, report=payload)
    assert out.run.status == "failed" and "Rule parse error" in (out.run.error or "")


# ---- hardening --------------------------------------------------------------------------


def test_repo_supplied_gitleaksignore_fails_closed(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    (demo_repo / ".gitleaksignore").write_text("anything\n")
    out = run(GitleaksAdapter(), bin_dir, tmp_path, demo_repo, report="[]")
    assert out.run.status == "failed" and ".gitleaksignore" in (out.run.error or "")
    allowed = GitleaksAdapter().run(make_ctx(demo_repo, tmp_path, allow_repo_ignore_files=True))
    assert allowed.run.status == "ok"


def test_gitleaks_command_neutralises_repo_controls(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    out = run(GitleaksAdapter(), bin_dir, tmp_path, demo_repo, report="[]")
    cmd = out.run.command
    assert cmd[0] == "gitleaks" and "--ignore-gitleaks-allow" in cmd and "--redact=100" in cmd
    assert "--config" in cmd and "--gitleaks-ignore-path" in cmd and cmd[1] == "dir"


def test_gitleaks_history_mode_uses_git_subcommand(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    make_fake_scanner(bin_dir, "gitleaks", report="[]")
    out = GitleaksAdapter().run(make_ctx(demo_repo, tmp_path, history=True))
    assert out.run.command[1] == "git"


def test_semgrep_command_is_offline_and_ignores_repo_ignore_files(
    bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    out = run(SemgrepAdapter(), bin_dir, tmp_path, demo_repo, report='{"results": [], "errors": []}')
    cmd = out.run.command
    assert "--no-git-ignore" in cmd and "--x-ignore-semgrepignore-files" in cmd and "--disable-nosem" in cmd
    assert cmd[cmd.index("--metrics") + 1] == "off" and "--disable-version-check" in cmd
    assert not any(a.startswith(("p/", "r/", "http")) for a in cmd)


@pytest.mark.parametrize("rule", ["p/default", "auto", "https://semgrep.dev/c/p/x", "r/python.lang"])
def test_semgrep_refuses_remote_rules_by_default(
    rule: str, bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    make_fake_scanner(bin_dir, "semgrep", report='{"results": [], "errors": []}')
    cfg = Config.model_validate({"scanners": {"semgrep": {"rules": [rule]}}})
    out = SemgrepAdapter().run(make_ctx(demo_repo, tmp_path, cfg))
    assert out.run.status == "failed" and "remote registry" in (out.run.error or "")


def test_trivy_command_ignores_repo_ignorefiles_and_supports_offline(
    bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    make_fake_scanner(bin_dir, "trivy", report='{"Results": []}')
    ctx = make_ctx(demo_repo, tmp_path)
    ctx.offline = True
    cmd = TrivyAdapter().run(ctx).run.command
    assert "--ignorefile" in cmd and "--skip-db-update" in cmd and "--offline-scan" in cmd
    assert cmd[1] == "fs"


def test_trivy_image_mode(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    make_fake_scanner(bin_dir, "trivy", report='{"Results": []}')
    cmd = TrivyAdapter().run(make_ctx(demo_repo, tmp_path, image="alpine:3.20")).run.command
    assert cmd[1] == "image" and cmd[-1] == "alpine:3.20"


def test_osv_command_variants(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    make_fake_scanner(bin_dir, "osv-scanner", report='{"results": []}')
    base = OsvAdapter().run(make_ctx(demo_repo, tmp_path)).run.command
    assert "--no-resolve" in base and "--no-ignore" in base and "--offline-vulnerabilities" not in base
    cfg = Config.model_validate({"scanners": {"osv": {"mode": "local-db"}}})
    local = OsvAdapter().run(make_ctx(demo_repo, tmp_path, cfg)).run.command
    assert "--offline-vulnerabilities" in local and "--download-offline-databases" in local


def test_secret_lines_in_unreadable_hostile_filename(bin_dir: Path, tmp_path: Path, demo_repo: Path) -> None:
    hostile = {
        "RuleID": "x",
        "File": str(demo_repo / "a\x1b[31m.py"),
        "StartLine": 1,
        "Match": "REDACTED",
    }
    out = run(GitleaksAdapter(), bin_dir, tmp_path, demo_repo, report=json.dumps([hostile]), exit_code=10)
    assert out.findings and "\x1b" not in (out.findings[0].file or "")


def test_parse_version() -> None:
    assert parse_version("Version: 0.76.0\n") == "0.76.0"
    assert parse_version("osv-scanner version: 2.7.0") == "2.7.0"
    assert parse_version("no version") is None


def test_reported_command_has_no_local_paths_or_random_temp_names(
    bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    out = run(GitleaksAdapter(), bin_dir, tmp_path, demo_repo, report="[]")
    text = " ".join(out.run.command)
    assert str(tmp_path) not in text and str(demo_repo) not in text
    assert "<target>" in out.run.command and "<workdir>/gitleaks-report.json" in out.run.command
    assert "<path>/gitleaks.toml" in out.run.command


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("main.tf", "#trivy:ignore:AVD-AWS-0086\nresource {}\n"),
        ("k8s/deploy.yaml", "# tfsec:ignore:foo\n"),
        ("Dockerfile", "# trivy:ignore:DS-0002\nFROM x\n"),
    ],
)
def test_trivy_inline_ignore_directives_fail_closed(
    name: str, text: str, bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    target = demo_repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    make_fake_scanner(bin_dir, "trivy", report='{"Results": []}')
    refused = TrivyAdapter().run(make_ctx(demo_repo, tmp_path))
    assert refused.run.status == "failed" and "trivy:ignore" in (refused.run.error or "")
    assert name in (refused.run.error or "")
    allowed = TrivyAdapter().run(make_ctx(demo_repo, tmp_path, allow_repo_ignore_files=True))
    assert allowed.run.status == "ok" and any("inline ignore" in w for w in allowed.run.warnings)


def test_trivy_directive_scan_skips_dependency_only_runs_and_images(
    bin_dir: Path, tmp_path: Path, demo_repo: Path
) -> None:
    (demo_repo / "main.tf").write_text("#trivy:ignore:AVD-AWS-0086\n")
    make_fake_scanner(bin_dir, "trivy", report='{"Results": []}')
    deps_only = Config.model_validate({"scanners": {"trivy": {"scanners": ["vuln"]}}})
    assert TrivyAdapter().run(make_ctx(demo_repo, tmp_path, deps_only)).run.status == "ok"
    assert TrivyAdapter().run(make_ctx(demo_repo, tmp_path, image="alpine:3.20")).run.status == "ok"
