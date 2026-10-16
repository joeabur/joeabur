"""Shared fixtures. Every test works inside pytest's temporary directory; a guard makes any scan
of a path outside it fail loudly so the default suite can never touch real system paths."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fim.cli import app
from fim.config import Config, parse_config
from fim.scanner import Scanner


@pytest.fixture(autouse=True)
def _never_scan_outside_tmp(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = os.path.realpath(tmp_path_factory.getbasetemp())
    original = Scanner.scan

    def guarded(self: Scanner, roots: list[str] | None = None):  # type: ignore[no-untyped-def]
        for r in roots if roots is not None else self.cfg.roots:
            assert os.path.realpath(r).startswith(base), f"test tried to scan outside tmp: {r}"
        return original(self, roots)

    monkeypatch.setattr(Scanner, "scan", guarded)


@dataclass
class Workspace:
    root: Path
    data: Path
    state: Path
    config_path: Path

    def config(self, **scan_overrides: object) -> Config:
        return make_config(self, **scan_overrides)


def make_config(
    ws: Workspace, *, policy: dict | None = None, baseline: dict | None = None, **scan: object
) -> Config:
    scan_cfg: dict = {"roots": [str(ws.data)], **scan}
    base_cfg: dict = {"dir": str(ws.state / "baselines"), **(baseline or {})}
    return parse_config({"baseline": base_cfg, "scan": scan_cfg, "policy": policy or {}})


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    data = tmp_path / "data"
    state = tmp_path / "state"
    data.mkdir()
    state.mkdir()
    (data / "a.txt").write_text("alpha\n")
    (data / "sub").mkdir()
    (data / "sub" / "b.txt").write_text("bravo\n")
    cfg = tmp_path / "fim.toml"
    cfg.write_text(f'[baseline]\ndir = "{state}/baselines"\n[scan]\nroots = ["{data}"]\n')
    return Workspace(tmp_path, data, state, cfg)


@pytest.fixture
def run(ws: Workspace) -> Callable[..., object]:
    """Invoke the CLI in-process against the workspace config."""
    runner = CliRunner()

    def _run(
        *args: str, config: Path | None = None, env: dict[str, str] | None = None, input: str | None = None
    ):  # type: ignore[no-untyped-def]
        full_env = {"FIM_CONFIG": str(config or ws.config_path), **(env or {})}
        return runner.invoke(app, list(args), env=full_env, input=input)

    return _run
