from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from reposcan.config import Config

from .helpers import REPO_ROOT

DEMO_REPO = REPO_ROOT / "sample-data" / "demo-repo"
CLEAN_REPO = REPO_ROOT / "sample-data" / "clean-repo"


@pytest.fixture
def demo_repo(tmp_path: Path) -> Path:
    """A private copy of the bundled demo repository."""
    dest = tmp_path / "demo-repo"
    shutil.copytree(DEMO_REPO, dest)
    return dest


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    dest = tmp_path / "clean-repo"
    shutil.copytree(CLEAN_REPO, dest)
    return dest


@pytest.fixture
def bin_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Directory that is the ONLY place scanners are found (PATH is replaced)."""
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", str(d))
    return d


@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SOURCE_DATE_EPOCH", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", os.environ.get("HOME", "/tmp"))
