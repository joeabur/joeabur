"""Documentation checks: documented commands, config examples, links, paths and report schema."""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from pathlib import Path

import jsonschema
import pytest
import yaml
from typer.testing import CliRunner

from reposcan.cli import app
from reposcan.config import Config, load_config
from reposcan.schemas import ScanResult

from ..helpers import FIXTURES, REPO_ROOT
from .factories import dep_finding, finding, result

DOC_FILES = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "CONTRIBUTING.md",
    REPO_ROOT / "SECURITY.md",
    REPO_ROOT / "CODE_OF_CONDUCT.md",
    *sorted((REPO_ROOT / "docs").glob("*.md")),
]
GUIDES = [
    "getting-started.md",
    "walkthrough.md",
    "user-guide.md",
    "configuration.md",
    "troubleshooting.md",
    "security-and-limitations.md",
    "examples.md",
    "threat-model.md",
]
FENCE_RE = re.compile(r"^```(?P<lang>[\w+-]*)[^\n]*\n(?P<body>.*?)^```", re.S | re.M)
LINK_RE = re.compile(r"(?<!\!)\[[^\]]*\]\((?P<target>[^)\s]+)\)")
PATH_RE = re.compile(
    r"`((?:docs|sample-data|tests|policies|examples|scripts|src|\.github)/[A-Za-z0-9_.\-/]*)`"
)
runner = CliRunner()


def blocks(path: Path, lang: str) -> list[str]:
    return [m["body"] for m in FENCE_RE.finditer(path.read_text(encoding="utf-8")) if m["lang"] == lang]


def slug(heading: str) -> str:
    text = re.sub(r"`", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    body = FENCE_RE.sub("", path.read_text(encoding="utf-8"))
    return {slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.*)$", body, re.M)}


def ids(paths: list[Path]) -> list[str]:
    return [p.relative_to(REPO_ROOT).as_posix() for p in paths]


# ---- links ------------------------------------------------------------------------------------


@pytest.mark.parametrize("doc", DOC_FILES, ids=ids(DOC_FILES))
def test_internal_links_and_anchors_resolve(doc: Path) -> None:
    text = FENCE_RE.sub("", doc.read_text(encoding="utf-8"))
    problems = []
    for match in LINK_RE.finditer(text):
        target = match["target"]
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        file_part, _, fragment = target.partition("#")
        dest = (doc.parent / file_part).resolve() if file_part else doc
        if not dest.exists():
            problems.append(f"missing file: {target}")
            continue
        if fragment and dest.suffix == ".md" and fragment not in anchors(dest):
            problems.append(f"missing anchor: {target}")
    assert not problems, problems


def test_readme_links_to_every_guide() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for guide in GUIDES:
        assert f"docs/{guide}" in readme, guide
    for extra in ("LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"):
        assert extra in readme, extra


def test_required_files_and_directories_exist() -> None:
    for name in (
        "src",
        "tests/unit",
        "tests/integration",
        "tests/fixtures",
        "sample-data",
        "policies",
        "examples",
        "docs",
        "scripts",
        ".github/workflows",
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "docs/threat-model.md",
        "pyproject.toml",
        "uv.lock",
    ):
        assert (REPO_ROOT / name).exists(), name


@pytest.mark.parametrize("doc", DOC_FILES, ids=ids(DOC_FILES))
def test_referenced_repository_paths_exist(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8")
    missing = []
    for rel in PATH_RE.findall(text):
        if any(ch in rel for ch in "*<>"):
            continue
        if not (REPO_ROOT / rel.rstrip("/")).exists():
            missing.append(rel)
    assert not missing, missing


# ---- documented commands ------------------------------------------------------------------------


def logical_lines(body: str) -> list[str]:
    out: list[str] = []
    buf = ""
    for raw in body.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append(buf + line)
        buf = ""
    return out


def reposcan_commands(doc: Path) -> list[list[str]]:
    commands = []
    for body in blocks(doc, "bash"):
        if "<<" in body and "reposcan" not in body.split("<<")[0]:
            body = body.split("<<")[0]
        for line in logical_lines(body):
            for segment in re.split(
                r"\s*(?:\|\||&&|\||;)\s*", line.split("#")[0] if "#" in line and '"#' not in line else line
            ):
                segment = segment.strip().removeprefix("$ ").strip()
                if segment.startswith(("reposcan ", "python -m reposcan ")):
                    try:
                        tokens = shlex.split(segment)
                    except ValueError:
                        continue
                    tokens = tokens[3:] if tokens[:3] == ["python", "-m", "reposcan"] else tokens[1:]
                    tokens = [t for t in tokens if not t.startswith(("2>", ">"))]
                    commands.append(tokens)
    return commands


def all_documented_commands() -> list[tuple[str, list[str]]]:
    return [(doc.name, cmd) for doc in DOC_FILES for cmd in reposcan_commands(doc)]


def test_there_are_documented_commands_to_check() -> None:
    assert len(all_documented_commands()) >= 40


@pytest.mark.parametrize(
    ("doc", "command"), all_documented_commands(), ids=lambda v: v if isinstance(v, str) else " ".join(v)[:60]
)
def test_documented_reposcan_commands_are_valid(doc: str, command: list[str]) -> None:
    """Every documented command parses: known subcommands, known options (appending --help)."""
    res = runner.invoke(app, [*command, "--help"])
    assert res.exit_code == 0, f"{doc}: reposcan {' '.join(command)}\n{res.output}"


def test_documented_scripts_exist_and_are_executable() -> None:
    for doc in DOC_FILES:
        for body in blocks(doc, "bash"):
            for rel in re.findall(r"(?:^|\s)((?:\.\./)?scripts/[\w.\-]+\.(?:sh|py))", body):
                path = REPO_ROOT / rel
                assert path.exists(), f"{doc.name}: {rel}"
                assert path.stat().st_mode & 0o111, f"{rel} is not executable"


# ---- configuration examples ----------------------------------------------------------------------


def config_blocks() -> list[tuple[str, str]]:
    out = []
    for doc in DOC_FILES:
        for body in blocks(doc, "toml"):
            if body.lstrip().startswith("# reposcan:config"):
                out.append((doc.name, body))
    return out


def test_config_examples_exist() -> None:
    assert len(config_blocks()) >= 4


@pytest.mark.parametrize(("doc", "body"), config_blocks(), ids=lambda v: v[:20].replace("\n", " "))
def test_documented_config_examples_validate(doc: str, body: str) -> None:
    Config.model_validate(tomllib.loads(body))


@pytest.mark.parametrize(
    "path",
    sorted((REPO_ROOT / "policies").glob("*.toml"))
    + sorted((REPO_ROOT / "examples" / "configs").glob("*.toml")),
    ids=lambda p: p.name,
)
def test_shipped_toml_files_parse(path: Path) -> None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if path.name.startswith("gitleaks"):
        assert "extend" in data or "rules" in data
    else:
        assert isinstance(load_config(str(path)), Config)


def test_bundled_scanner_configs_parse() -> None:
    data_dir = REPO_ROOT / "src" / "reposcan" / "data"
    gitleaks = tomllib.loads((data_dir / "gitleaks.toml").read_text(encoding="utf-8"))
    assert gitleaks["extend"]["useDefault"] is True
    rules = yaml.safe_load((data_dir / "semgrep-rules.yml").read_text(encoding="utf-8"))["rules"]
    assert {r["id"] for r in rules} >= {"reposcan.python.eval-call", "reposcan.python.weak-hash"}


# ---- YAML (workflows, GitLab) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
        REPO_ROOT / "examples" / "gitlab" / ".gitlab-ci.yml",
    ],
    ids=lambda p: p.name,
)
def test_ci_yaml_parses(path: Path) -> None:
    assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), dict)


@pytest.mark.parametrize("doc", DOC_FILES, ids=ids(DOC_FILES))
def test_yaml_blocks_in_docs_parse(doc: Path) -> None:
    for body in blocks(doc, "yaml"):
        yaml.safe_load(body)


def test_workflows_pass_hygiene_checks() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_workflows", REPO_ROOT / "scripts" / "check_workflows.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    problems = [
        p for f in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")) for p in module.check_file(f)
    ]
    assert problems == []


def test_workflow_hygiene_checker_catches_problems(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_workflows", REPO_ROOT / "scripts" / "check_workflows.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "on:\n  pull_request_target:\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - run: |\n          echo ${{ github.event.pull_request.title }}\n"
        "      - uses: docker://alpine:3\n"
    )
    problems = module.check_file(bad)
    text = "\n".join(problems)
    assert (
        "permissions" in text and "pull_request_target" in text and "not pinned to a full commit SHA" in text
    )
    assert "untrusted expression" in text and "image digest" in text


# ---- report schema, fixtures and diagrams -----------------------------------------------------------


def test_committed_report_schema_is_current_and_validates_a_report() -> None:
    schema = json.loads((REPO_ROOT / "docs" / "report-schema.json").read_text(encoding="utf-8"))
    from reposcan.schemas import ScanResult as Model

    expected = Model.model_json_schema()
    expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    expected["title"] = "reposcan JSON report"
    assert schema == expected, "run: python scripts/generate_schema.py"
    sample = result([finding("r"), dep_finding()])
    jsonschema.Draft202012Validator(schema).validate(json.loads(sample.model_dump_json()))


def test_every_scanner_fixture_is_valid_json_without_local_paths() -> None:
    for path in sorted((FIXTURES / "scanner-output").glob("*.json")):
        text = path.read_text(encoding="utf-8")
        json.loads(text)
        assert "/home/" not in text and "/tmp/" not in text and "/root/" not in text, path.name


def test_fixture_provenance_is_documented() -> None:
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    for path in sorted((FIXTURES / "scanner-output").glob("*.json")):
        assert path.name in readme, path.name


def test_demo_repo_line_numbers_match_the_fixtures_and_docs() -> None:
    """Fixtures, docs and integration tests assert these lines: guard them against reformatting."""
    server = (REPO_ROOT / "sample-data" / "demo-repo" / "app" / "server.py").read_text().splitlines()
    assert "conn.execute(query)" in server[12]
    assert "shell=True" in server[17]
    assert "hashlib.md5" in server[22]
    assert "eval(expression)" in server[27]
    settings = (REPO_ROOT / "sample-data" / "demo-repo" / "app" / "settings.py").read_text().splitlines()
    assert settings[3].startswith("SERVICE_TOKEN") and settings[6].startswith("internal_api_key")


def test_demo_secrets_are_clearly_synthetic() -> None:
    text = (REPO_ROOT / "sample-data" / "demo-repo" / "app" / "settings.py").read_text()
    assert "SYNTHETIC" in text and "DEMO_TOKEN_" in text
    assert not re.search(
        r"AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|xox[bp]-|sk_live_|BEGIN [A-Z ]*PRIVATE KEY", text
    )


def test_mermaid_diagrams_are_present_and_accurate_in_scope() -> None:
    all_text = "\n".join(b for doc in DOC_FILES for b in blocks(doc, "mermaid"))
    guide_diagrams = blocks(REPO_ROOT / "docs" / "user-guide.md", "mermaid")
    assert len(guide_diagrams) == 3  # orchestration, per-scanner pipeline, CI workflow
    orchestration = guide_diagrams[0] + guide_diagrams[1]
    for scanner in ("gitleaks", "semgrep", "trivy", "osv-scanner"):
        assert scanner in orchestration
    for status in ("not_found", "version_mismatch", "timeout", "cancelled", "malformed_output", "failed"):
        assert status in orchestration
    for code in ("130", "3", "1", "0", "exit 2"):
        assert code in guide_diagrams[0]
    ci = guide_diagrams[2]
    for needle in ("persist-credentials", "SARIF", "Branch protection", "release"):
        assert needle in ci
    for body in blocks(REPO_ROOT / "docs" / "user-guide.md", "mermaid"):
        assert body.count("[") == body.count("]") and body.count("{") == body.count("}")
        assert body.count('"') % 2 == 0
    assert all_text.count("flowchart") >= 5


def test_status_values_in_docs_match_the_code() -> None:
    from typing import get_args

    from reposcan.schemas import ScannerRun

    statuses = set(get_args(ScannerRun.model_fields["status"].annotation))
    text = (REPO_ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")
    for status in statuses - {"ok", "skipped"}:
        assert status in text, status


def test_documented_exit_codes_match_the_code() -> None:
    from reposcan.errors import ExitCode

    expected = {int(c) for c in ExitCode}
    assert expected == {0, 1, 2, 3, 4, 130}
    guide = (REPO_ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")
    for code in expected:
        assert re.search(rf"^\| {code} \|", guide, re.M), code


def test_scanner_version_tables_match_adapters() -> None:
    from reposcan.adapters import ALL_ADAPTERS

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    guide = (REPO_ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")
    for adapter in ALL_ADAPTERS:
        assert adapter.tested in readme and adapter.supported in readme, adapter.name
        assert adapter.tested in guide and adapter.supported in guide, adapter.name


def test_scan_result_schema_roundtrip_of_sample_report() -> None:
    sample = result([finding("r")])
    assert ScanResult.model_validate_json(sample.model_dump_json()) == sample
