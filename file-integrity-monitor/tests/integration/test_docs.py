"""Documentation tests: executable walkthrough, expected outputs, links, commands, configs, schemas."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests import docs_runner as d

ROOT = d.ROOT
DOCS = sorted((ROOT / "docs").glob("*.md"))
ALL_MD = [ROOT / n for n in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md")] + DOCS

REQUIRED_DOCS = [
    "getting-started.md", "walkthrough.md", "user-guide.md", "configuration.md",
    "troubleshooting.md", "security-and-limitations.md", "examples.md", "threat-model.md",
]  # fmt: skip


@pytest.fixture(scope="module")
def walkthrough_run() -> tuple[list[d.Block], dict[int, str]]:
    blocks = d.parse_blocks((ROOT / "docs" / "walkthrough.md").read_text())
    return blocks, d.run_blocks(blocks)


def test_required_docs_exist_and_linked_from_readme() -> None:
    readme = (ROOT / "README.md").read_text()
    for name in REQUIRED_DOCS:
        assert (ROOT / "docs" / name).is_file(), name
        assert f"docs/{name}" in readme, f"README does not link docs/{name}"
    for name in ("SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "LICENSE"):
        assert (ROOT / name).is_file(), name


def test_walkthrough_executes_and_outputs_match(walkthrough_run) -> None:  # type: ignore[no-untyped-def]
    blocks, outputs = walkthrough_run
    run_idx = [i for i, b in enumerate(blocks) if b.kind == "run"]
    assert len(run_idx) >= 8
    assert set(run_idx) == set(outputs), "a run block produced no output marker"
    checked = 0
    for i, b in enumerate(blocks):
        if b.kind != "expect":
            continue
        prev_run = max(j for j in run_idx if j < i)
        ok, missing = d.expect_matches(b.text, outputs[prev_run])
        assert ok, (
            f"walkthrough.md line {b.line}: expected output line not found in real output:\n"
            f"  {missing!r}\n--- real output (normalised) ---\n" + "\n".join(d.normalise(outputs[prev_run]))
        )
        checked += 1
    assert checked >= 8


def test_walkthrough_cleanup_removed_everything(walkthrough_run) -> None:  # type: ignore[no-untyped-def]
    _, outputs = walkthrough_run
    assert "workspace removed" in list(outputs.values())[-1]
    assert not list(Path("/tmp").glob("fim-tutorial.*"))


def _fim_commands(md_text: str) -> list[str]:
    cmds = []
    for b in d.parse_blocks(md_text):
        if b.lang not in ("bash", "sh", "console", "shell"):
            continue
        text = b.text.replace("\\\n", " ")
        for raw in text.splitlines():
            line = raw.strip().lstrip("$ ").strip()
            for part in re.split(r"\s*(?:&&|\|\||;|\|)\s*", line):
                if re.match(r"^(sudo\s+)?fim(\s|$)", part):
                    cmds.append(re.sub(r"^sudo\s+", "", part))
    return cmds


def _cli_surface() -> dict[tuple[str, ...], set[str]]:
    """{command path: set of option names} derived from the real Typer/Click app."""
    import typer.main

    root = typer.main.get_command(__import__("fim.cli", fromlist=["app"]).app)
    surface: dict[tuple[str, ...], set[str]] = {}

    def walk(cmd: object, path: tuple[str, ...]) -> None:
        opts = {o for p in cmd.params if hasattr(p, "secondary_opts") for o in (*p.opts, *p.secondary_opts)}  # type: ignore[attr-defined]
        surface[path] = opts | {"--help"}
        if hasattr(cmd, "commands"):
            for name, sub in cmd.commands.items():  # type: ignore[attr-defined]
                walk(sub, (*path, name))

    walk(root, ())
    return surface


@pytest.mark.parametrize("md", ALL_MD, ids=lambda p: p.name)
def test_documented_fim_commands_exist(md: Path) -> None:
    surface = _cli_surface()
    global_opts = surface[()]
    for cmd in _fim_commands(md.read_text()):
        tokens = cmd.split()[1:]
        path: tuple[str, ...] = ()
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t.startswith("-"):
                name = t.split("=")[0]
                known = surface[path] | (global_opts if path else set()) | {"-c", "-q", "-o"}
                assert name in known, (
                    f"{md.name}: unknown option {name!r} for 'fim {' '.join(path)}' in: {cmd}"
                )
                if name in ("--config", "-c") and "=" not in t:
                    i += 1
            elif (*path, t) in surface:
                path = (*path, t)
            else:
                break  # positional argument
            i += 1
        assert path in surface, cmd


def test_command_reference_covers_every_command() -> None:
    guide = (ROOT / "docs" / "user-guide.md").read_text()
    for path in _cli_surface():
        if path and len(path) == (1 if path[0] not in ("baseline", "audit", "report", "config") else 2):
            assert f"fim {' '.join(path)}" in guide, f"user-guide.md lacks `fim {' '.join(path)}`"


def _slug(heading: str) -> str:
    s = re.sub(r"[`*_]", "", heading.strip().lower())
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


@pytest.mark.parametrize("md", ALL_MD, ids=lambda p: p.name)
def test_internal_links_resolve(md: Path) -> None:
    text = md.read_text()
    text_nocode = re.sub(r"```.*?```", "", text, flags=re.S)
    for m in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", text_nocode):
        target = m.group(1)
        if re.match(r"^(https?:|mailto:)", target):
            continue
        path_part, _, anchor = target.partition("#")
        dest = md if not path_part else (md.parent / path_part).resolve()
        assert dest.exists(), f"{md.name}: broken link {target}"
        if anchor and dest.suffix == ".md":
            heads = [
                _slug(h)
                for h in re.findall(
                    r"^#{1,6}\s+(.*)$", re.sub(r"```.*?```", "", dest.read_text(), flags=re.S), flags=re.M
                )
            ]
            assert anchor in heads, f"{md.name}: anchor #{anchor} not found in {dest.name}"


def test_mermaid_diagrams_are_wellformed() -> None:
    kinds = ("flowchart", "graph", "sequenceDiagram", "stateDiagram-v2", "classDiagram")
    found = 0
    for md in ALL_MD:
        for b in d.parse_blocks(md.read_text()):
            if b.lang != "mermaid":
                continue
            found += 1
            first = b.text.strip().splitlines()[0]
            assert first.startswith(kinds), f"{md.name}:{b.line} unknown diagram type"
            for open_c, close_c in ("[]", "()", "{}"):
                assert b.text.count(open_c) == b.text.count(close_c), (
                    f"{md.name}:{b.line} unbalanced {open_c}{close_c}"
                )
            if first.startswith(("flowchart", "graph")):
                ids = set(re.findall(r"^\s*([A-Za-z_]\w*)\s*[\[({]", b.text, flags=re.M))
                ids |= set(re.findall(r"-->\s*(?:\|[^|]*\|\s*)?([A-Za-z_]\w*)\s*[\[({]", b.text))
                used = set(
                    re.findall(
                        r"(?:^|-->|---)\s*(?:\|[^|]*\|\s*)?([A-Za-z_]\w*)\s*(?:$|-->|---|\s*;)",
                        b.text,
                        flags=re.M,
                    )
                )
                assert used <= ids | {"end", "subgraph"}, (
                    f"{md.name}:{b.line} edges reference undefined nodes: {used - ids}"
                )
    assert found >= 2, "expected at least the architecture and workflow diagrams"


def test_documented_toml_examples_validate() -> None:
    import tomllib

    from fim.config import parse_config

    checked = 0
    for md in ALL_MD:
        for b in d.parse_blocks(md.read_text()):
            if b.lang != "toml" or "fim-test:skip" in b.text:
                continue
            data = tomllib.loads(b.text)
            if "baseline" in data and "scan" in data:
                parse_config(data)
                checked += 1
    assert checked >= 2
    for p in [
        *(ROOT / "config").glob("*.toml"),
        *(ROOT / "examples").glob("*.toml"),
        *(ROOT / "sample-data").glob("*.toml"),
    ]:
        from fim.config import load_config

        try:
            load_config(p)
        except Exception as exc:  # sample config points at a deleted demo dir; syntax must still be valid
            raise AssertionError(f"{p} invalid: {exc}") from exc
    tpl = (ROOT / "config" / "fim.tutorial.toml.in").read_text().replace("@WORK@", "/tmp/x")
    parse_config(tomllib.loads(tpl))


def test_sample_paths_in_docs_exist() -> None:
    pat = re.compile(r"`((?:sample-data|examples|config|scripts|systemd|tests|docs)/[\w./\-]+)`")
    for md in ALL_MD:
        for m in pat.finditer(md.read_text()):
            rel = m.group(1)
            if any(ch in rel for ch in "*<>"):
                continue
            assert (ROOT / rel).exists() or (md.parent / rel).exists(), f"{md.name}: `{rel}` does not exist"


def test_sample_reports_match_schema() -> None:
    from fim.models import Report

    rep = Report.model_validate_json((ROOT / "sample-data" / "sample-report.json").read_text())
    assert rep.summary.event_count == len(rep.events) == 4
    csv_lines = (ROOT / "sample-data" / "sample-report.csv").read_text().splitlines()
    assert len(csv_lines) == 1 + len(rep.events)
    assert len((ROOT / "sample-data" / "sample-report.cef").read_text().splitlines()) == len(rep.events)
    assert len((ROOT / "sample-data" / "sample-report.syslog").read_text().splitlines()) == len(rep.events)


def test_published_json_schema_is_current_and_validates_samples() -> None:
    from fim.models import Report

    schema_path = ROOT / "docs" / "schemas" / "report.schema.json"
    on_disk = json.loads(schema_path.read_text())
    assert on_disk == Report.model_json_schema(), "run: python scripts/generate_schema.py"
    jsonschema = pytest.importorskip("jsonschema")
    sample = json.loads((ROOT / "sample-data" / "sample-report.json").read_text())
    jsonschema.validate(sample, on_disk)


def test_markers_are_followed_by_the_right_block() -> None:
    for md in DOCS:
        text = md.read_text()
        for m in re.finditer(r"<!-- fim-test:(run|expect) -->\n```(\w+)", text):
            assert (m.group(1), m.group(2)) in {("run", "bash"), ("expect", "text")}, (
                f"{md.name}: {m.group(0)!r}"
            )


def test_ci_workflow_is_valid_and_has_required_gates() -> None:
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((ROOT.parent / ".github" / "workflows" / "fim-ci.yml").read_text())
    jobs = set(wf["jobs"])
    assert {"lint-and-types", "tests", "dependency-audit", "dependency-review", "secret-scan"} <= jobs
    assert {"install-smoke-ubuntu", "install-smoke-rhel", "reproducibility"} <= jobs
    text = (ROOT.parent / ".github" / "workflows" / "fim-ci.yml").read_text()
    for needle in ("shellcheck", "bats", "mypy", "ruff", "gitleaks", "pip-audit", "dependency-review-action"):
        assert needle in text, needle
    assert wf["permissions"] == {"contents": "read"}


def test_workflow_actions_are_pinned_to_commit_shas() -> None:
    text = (ROOT.parent / ".github" / "workflows" / "fim-ci.yml").read_text()
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", text, flags=re.M)
    assert uses, "no actions found"
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u), (
            f"action not pinned to a full commit SHA: {u}"
        )


def test_dependabot_config_is_valid() -> None:
    yaml = pytest.importorskip("yaml")
    cfg = yaml.safe_load((ROOT.parent / ".github" / "dependabot.yml").read_text())
    ecos = {u["package-ecosystem"] for u in cfg["updates"]}
    assert {"uv", "github-actions"} <= ecos and "" not in ecos
