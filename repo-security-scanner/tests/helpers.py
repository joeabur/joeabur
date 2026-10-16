"""Test helpers: fake scanner executables that replay sanitised real output."""

from __future__ import annotations

import stat
import sys
import textwrap
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCANNER_OUTPUT = FIXTURES / "scanner-output"
REPO_ROOT = Path(__file__).resolve().parent.parent

_VERSION_ARG = {
    "gitleaks": "version",
    "semgrep": "--version",
    "trivy": "--version",
    "osv-scanner": "--version",
}
_REPORT_FLAG = {
    "gitleaks": "--report-path",
    "semgrep": "--json-output",
    "trivy": "--output",
    "osv-scanner": "--output-file",
}
_VERSION_TEXT = {
    "gitleaks": "{v}",
    "semgrep": "{v}",
    "trivy": "Version: {v}",
    "osv-scanner": "osv-scanner version: {v}\nosv-scalibr version: 0.5.3",
}
DEFAULT_VERSION = {
    "gitleaks": "8.30.1",
    "semgrep": "1.181.0",
    "trivy": "0.76.0",
    "osv-scanner": "2.7.0",
}
LEAK_CODE = {"gitleaks": 10, "semgrep": 0, "trivy": 0, "osv-scanner": 1}


def fixture_text(name: str) -> str:
    return (SCANNER_OUTPUT / name).read_text(encoding="utf-8")


def make_fake_scanner(
    bin_dir: Path,
    name: str,
    *,
    report: str | None = None,
    exit_code: int = 0,
    version: str | None = None,
    stderr: str = "",
    stdout_flood: int = 0,
    sleep: float = 0.0,
    write_report: bool = True,
) -> Path:
    """Create ``bin_dir/name``: answers version queries, then writes ``report`` and exits."""
    version_text = _VERSION_TEXT[name].format(v=version or DEFAULT_VERSION[name])
    body = textwrap.dedent(
        f"""\
        #!{sys.executable}
        import sys, time
        args = sys.argv[1:]
        if args[:1] == [{_VERSION_ARG[name]!r}]:
            print({version_text!r})
            sys.exit(0)
        time.sleep({sleep!r})
        flag = {_REPORT_FLAG[name]!r}
        if {write_report!r} and flag in args:
            path = args[args.index(flag) + 1]
            with open(path, "w", encoding="utf-8") as fh:
                fh.write({(report if report is not None else "[]")!r})
        if {stdout_flood!r}:
            sys.stdout.write("A" * {stdout_flood!r})
            sys.stdout.flush()
        sys.stderr.write({stderr!r})
        sys.exit({exit_code!r})
        """
    )
    path = bin_dir / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def install_demo_scanners(
    bin_dir: Path, repo: Path, *, only: tuple[str, ...] = tuple(DEFAULT_VERSION)
) -> None:
    """Fake all scanners to replay the real demo-repo output, rooted at ``repo``."""
    for name in only:
        make_fake_scanner(
            bin_dir,
            name,
            report=fixture_text(f"{name}-demo.json").replace("/repo", str(repo)),
            exit_code=LEAK_CODE[name],
        )


def install_clean_scanners(bin_dir: Path, *, only: tuple[str, ...] = tuple(DEFAULT_VERSION)) -> None:
    for name in only:
        make_fake_scanner(bin_dir, name, report=fixture_text(f"{name}-clean.json"), exit_code=0)
