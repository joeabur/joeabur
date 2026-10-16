from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from fim import service
from fim.errors import DependencyError
from fim.models import Report
from fim.scanner import Scanner
from fim.watcher import PathProcessor, Watcher, _load_watchdog
from tests.conftest import Workspace


@pytest.fixture
def trusted(ws: Workspace):  # type: ignore[no-untyped-def]
    cfg = ws.config(exclude=[f"{ws.data}/ignored/**"])
    store = service.store_for(cfg)
    service.baseline_from_scan(store, cfg, Scanner(cfg.scan).scan(), action="create", reason="t", signer=None)
    return cfg, service.load_trusted(cfg, store).baseline


class TestPathProcessor:
    def test_reports_only_dirty_paths(self, ws: Workspace, trusted) -> None:  # type: ignore[no-untyped-def]
        cfg, baseline = trusted
        (ws.data / "a.txt").write_text("changed")
        (ws.data / "sub" / "b.txt").write_text("also changed")  # not marked dirty
        rep = PathProcessor(cfg, baseline).process({str(ws.data / "a.txt")})
        assert rep is not None
        assert [(e.event_type.value, Path(e.path).name) for e in rep.events] == [("modified", "a.txt")]
        assert rep.summary.mode == "partial"

    def test_deleted_and_added(self, ws: Workspace, trusted) -> None:  # type: ignore[no-untyped-def]
        cfg, baseline = trusted
        (ws.data / "sub" / "b.txt").unlink()
        (ws.data / "new").write_text("n")
        rep = PathProcessor(cfg, baseline).process({str(ws.data / "sub" / "b.txt"), str(ws.data / "new")})
        assert {(e.event_type.value, Path(e.path).name) for e in rep.events} == {
            ("deleted", "b.txt"),
            ("added", "new"),
        }  # type: ignore[union-attr]
        assert rep.issues == []  # type: ignore[union-attr]  # a deleted path is not a scan issue

    def test_new_directory_subtree_is_scanned(self, ws: Workspace, trusted) -> None:  # type: ignore[no-untyped-def]
        cfg, baseline = trusted
        (ws.data / "newdir").mkdir()
        (ws.data / "newdir" / "x").write_text("x")
        rep = PathProcessor(cfg, baseline).process({str(ws.data / "newdir")})
        assert {Path(e.path).name for e in rep.events} == {"newdir", "x"}  # type: ignore[union-attr]

    def test_excluded_and_out_of_scope_paths_ignored(self, ws: Workspace, trusted) -> None:  # type: ignore[no-untyped-def]
        cfg, baseline = trusted
        (ws.data / "ignored").mkdir()
        (ws.data / "ignored" / "f").write_text("f")
        p = PathProcessor(cfg, baseline)
        assert p.process({str(ws.data / "ignored" / "f"), "/etc/passwd", str(ws.root / "state")}) is None

    def test_duplicates_are_suppressed_but_new_content_is_not(self, ws: Workspace, trusted) -> None:  # type: ignore[no-untyped-def]
        cfg, baseline = trusted
        p = PathProcessor(cfg, baseline)
        a = str(ws.data / "a.txt")
        (ws.data / "a.txt").write_text("v1")
        assert p.process({a}) is not None
        assert p.process({a}) is None  # same evidence, no repeat alert
        (ws.data / "a.txt").write_text("v2")
        assert p.process({a}) is not None  # different content hash => new event


def test_missing_watchdog_gives_fallback_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "watchdog.observers", None)
    with pytest.raises(DependencyError, match="fim scan"):
        _load_watchdog()


@pytest.mark.watcher
def test_real_inotify_events_end_to_end(ws: Workspace, trusted) -> None:  # type: ignore[no-untyped-def]
    pytest.importorskip("watchdog")
    cfg, baseline = trusted
    reports: list[Report] = []
    w = Watcher(cfg, baseline, reports.append)
    try:
        w.start()
    except OSError as exc:  # pragma: no cover - sandbox without inotify
        pytest.skip(f"inotify unavailable: {exc}")
    try:
        time.sleep(0.3)
        (ws.data / "a.txt").write_text("tampered")
        (ws.data / "dropped.sh").write_text("#!/bin/sh\n")
        (ws.data / "sub" / "b.txt").unlink()
        deadline = time.monotonic() + 10
        seen: set[tuple[str, str]] = set()
        while time.monotonic() < deadline and len(seen) < 3:
            time.sleep(0.3)
            r = w.drain()
            if r:
                reports.append(r)
            seen = {(e.event_type.value, Path(e.path).name) for rep in reports for e in rep.events}
        assert {("modified", "a.txt"), ("added", "dropped.sh"), ("deleted", "b.txt")} <= seen
    finally:
        w.stop()


@pytest.mark.watcher
def test_cli_watch_emits_json_lines(ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
    import json
    import os
    import subprocess
    import threading

    pytest.importorskip("watchdog")
    assert run("baseline", "create").exit_code == 0
    env = {**os.environ, "FIM_CONFIG": str(ws.config_path)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "fim.cli", "watch", "--max-seconds", "5"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    threading.Timer(1.5, lambda: (ws.data / "a.txt").write_text("tampered")).start()
    stdout, stderr = proc.communicate(timeout=30)
    assert proc.returncode == 0, stderr
    docs = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert docs, stderr
    assert any(e["event_type"] == "modified" for d in docs for e in d["events"])
