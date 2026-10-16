"""Documentation validation: links, referenced paths, CLI sub-commands and expected results."""

import json
import re
from pathlib import Path

import pytest

from linux_ir.cli import _parser, main

REPO = Path(__file__).resolve().parents[1]
DOCS = [REPO / "README.md", REPO / "CONTRIBUTING.md", *sorted((REPO / "docs").glob("*.md"))]
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")
PATHREF = re.compile(r"(?<![\w/.-])((?:examples|rules|configs|scripts|tests|docs|requirements)/[\w./-]+\.\w+)")
REQUIRED_DOCS = [
    "getting-started",
    "walkthrough",
    "user-guide",
    "configuration",
    "troubleshooting",
    "security-and-limitations",
    "architecture",
    "evidence-handling",
    "examples",
]


def test_required_docs_exist_and_are_linked_from_readme():
    readme = (REPO / "README.md").read_text()
    for name in REQUIRED_DOCS:
        assert (REPO / "docs" / f"{name}.md").is_file()
        assert f"docs/{name}.md" in readme


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_resolve(doc):
    for target in LINK.findall(doc.read_text()):
        if target.startswith(("http://", "https://", "mailto:")) or target.startswith("<"):
            continue
        assert (doc.parent / target).resolve().exists(), f"{doc.name}: broken link {target}"


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_referenced_repo_paths_exist(doc):
    for ref in PATHREF.findall(doc.read_text()):
        if any(ch in ref for ch in "<>*"):
            continue
        if (
            ref.startswith(("examples/synthetic-evidence/case-001/", "examples/synthetic-evidence/baseline/"))
            or "my-" in ref
        ):
            continue
        assert (REPO / ref).exists(), f"{doc.name}: referenced path {ref} does not exist"


def test_documented_subcommands_exist():
    subs = set(_parser()._subparsers._group_actions[0].choices)  # type: ignore[union-attr]
    for doc in DOCS:
        for cmd in re.findall(r"python -m linux_ir(?: --config \S+)? ([a-z-]+)", doc.read_text()):
            assert cmd in subs, f"{doc.name}: unknown command {cmd}"


def test_documented_config_keys_are_valid():
    from linux_ir.config import DEFAULTS

    text = (REPO / "docs/configuration.md").read_text()
    for key in re.findall(r"`((?:limits|logs|detection|ioc|redaction)\.[a-z_]+)`", text):
        section, name = key.split(".")
        assert name in DEFAULTS[section], key


def test_expected_results_match_scan(capsys):
    rc = main(
        [
            "scan",
            "--input",
            str(REPO / "examples/synthetic-evidence/case-001"),
            "--iocs",
            str(REPO / "examples/iocs.json"),
            "--baseline",
            str(REPO / "examples/synthetic-evidence/baseline"),
            "--json",
        ]
    )
    assert rc == 0
    got = sorted(
        (
            {k: f[k] for k in ("rule_id", "severity", "confidence", "classification", "evidence_ref")}
            for f in json.loads(capsys.readouterr().out)
        ),
        key=lambda x: (x["rule_id"], x["evidence_ref"]),
    )
    assert got == json.loads((REPO / "examples/expected-results/scan-findings.json").read_text())


def test_synthetic_data_is_clearly_synthetic():
    iocs = json.loads((REPO / "examples/iocs.json").read_text())
    assert iocs["synthetic"] is True and "TEST DATA" in iocs["description"]
    for ind in iocs["indicators"]:
        if ind["type"] == "ip":
            assert ind["value"].startswith(("203.0.113.", "198.51.100.", "192.0.2."))
        if ind["type"] == "domain":
            assert ind["value"].endswith(".example.test")
