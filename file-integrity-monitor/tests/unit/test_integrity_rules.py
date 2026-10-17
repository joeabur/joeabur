from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fim import integrity, scanner
from fim.baseline import compute_content_hash
from fim.models import Baseline, EventType, FileRecord, FileType, IssueKind, Severity, record_to_json
from fim.scanner import Scanner
from tests.conftest import Workspace


def baseline_from(ws: Workspace, cfg=None, **kw: object) -> tuple[Baseline, object]:  # type: ignore[no-untyped-def]
    cfg = cfg or ws.config(**kw)
    res = Scanner(cfg.scan).scan()
    body = {
        "format": "fim-baseline", "schema_version": 1, "version": 1,
        "created_at": "2026-01-01T00:00:00+00:00", "hostname": "h", "tool_version": "t",
        "roots": cfg.scan.roots, "exclude": cfg.scan.exclude, "symlinks": cfg.scan.symlinks,
        "complete": res.complete, "issues": [], "prev_sha256": None,
        "entries": {p: record_to_json(r) for p, r in res.entries.items()},
    }  # fmt: skip
    body["content_sha256"] = compute_content_hash(body)
    return Baseline.model_validate(body), cfg


def events_for(ws: Workspace, baseline: Baseline, cfg) -> list:  # type: ignore[no-untyped-def]
    res = Scanner(cfg.scan).scan()
    return integrity.compare(cfg, baseline, res, scan_id="t")


def by_type(events: list) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in events:
        out.setdefault(e.event_type.value, []).append(Path(e.path).name)
    return out


def test_identical_is_clean(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    assert events_for(ws, b, cfg) == []


def test_content_change(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "a.txt").write_text("ALPHA!\n")
    ev = events_for(ws, b, cfg)
    assert by_type(ev)["modified"] == ["a.txt"]
    mod = next(e for e in ev if e.event_type is EventType.MODIFIED)
    assert {c.field for c in mod.changes} == {"size", "sha256"}
    assert mod.severity is Severity.HIGH and mod.before.sha256 != mod.after.sha256


def test_same_size_content_change_detected_by_hash(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    st0 = (ws.data / "a.txt").stat()
    (ws.data / "a.txt").write_text("ALPHA\n")  # same length
    os.utime(ws.data / "a.txt", ns=(st0.st_atime_ns, st0.st_mtime_ns))  # and forged mtime
    ev = events_for(ws, b, cfg)
    assert by_type(ev) == {"modified": ["a.txt"]}
    assert [c.field for c in ev[0].changes] == ["sha256"]


def test_metadata_only_mtime_change_is_info(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    os.utime(ws.data / "a.txt", (1_000_000_000, 1_000_000_000))
    ev = events_for(ws, b, cfg)
    assert by_type(ev) == {"metadata_changed": ["a.txt"]}
    assert ev[0].severity is Severity.INFO


def test_permission_change(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "a.txt").chmod(0o600)
    ev = events_for(ws, b, cfg)
    assert by_type(ev) == {"permission_changed": ["a.txt"]}
    assert (ev[0].changes[0].old, ev[0].changes[0].new) == ("0644", "0600")


def test_setuid_and_world_writable_escalate(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "a.txt").chmod(0o4755)
    (ws.data / "sub" / "b.txt").chmod(0o666)
    ev = {Path(e.path).name: e for e in events_for(ws, b, cfg)}
    assert ev["a.txt"].severity is Severity.CRITICAL and "setuid_set" in ev["a.txt"].risk_flags
    assert ev["b.txt"].severity is Severity.HIGH and ev["b.txt"].risk_flags == ["world_writable"]


def test_owner_change(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    key = str(ws.data / "a.txt")
    entries = dict(b.entries)
    entries[key] = dataclasses.replace(entries[key], uid=4242, gid=4343)
    forged = b.model_copy(update={"entries": entries})
    ev = events_for(ws, forged, cfg)
    assert by_type(ev) == {"owner_changed": ["a.txt"]}
    assert {c.field for c in ev[0].changes} == {"uid", "gid"}


def test_added_and_deleted(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "new.txt").write_text("n")
    (ws.data / "sub" / "b.txt").unlink()
    t = by_type(events_for(ws, b, cfg))
    assert t == {"added": ["new.txt"], "deleted": ["b.txt"]}


def test_deleting_a_directory_reports_children(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "sub" / "b.txt").unlink()
    (ws.data / "sub").rmdir()
    assert sorted(by_type(events_for(ws, b, cfg))["deleted"]) == ["b.txt", "sub"]


def test_type_change_file_to_symlink(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "a.txt").unlink()
    (ws.data / "a.txt").symlink_to("/etc/passwd")
    ev = events_for(ws, b, cfg)
    assert by_type(ev) == {"type_changed": ["a.txt"]}


def test_symlink_retarget(ws: Workspace) -> None:
    (ws.data / "ln").symlink_to("/usr/bin/true")
    b, cfg = baseline_from(ws)
    (ws.data / "ln").unlink()
    (ws.data / "ln").symlink_to("/tmp/evil")
    ev = events_for(ws, b, cfg)
    assert by_type(ev) == {"symlink_changed": ["ln"]}
    assert ev[0].changes[0].new == "/tmp/evil"


def test_directory_mtime_churn_is_not_an_event(ws: Workspace) -> None:
    b, cfg = baseline_from(ws)
    (ws.data / "sub" / "tmp").write_text("x")
    (ws.data / "sub" / "tmp").unlink()  # dir mtime changed, content identical
    assert events_for(ws, b, cfg) == []


class TestIncompleteScansNeverBecomeFalseDeletions:
    def test_unlistable_directory_does_not_report_children_deleted(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b, cfg = baseline_from(ws)
        real = os.scandir

        def deny(path):  # type: ignore[no-untyped-def]
            if str(path) == str(ws.data / "sub"):
                raise PermissionError(13, "denied")
            return real(path)

        monkeypatch.setattr(scanner.os, "scandir", deny)
        res = Scanner(cfg.scan).scan()
        ev = integrity.compare(cfg, b, res, scan_id="t")
        assert ev == []  # not 'deleted'...
        assert IssueKind.WALK_ERROR in {i.kind for i in res.issues}  # ...but loudly incomplete
        assert not res.complete

    def test_aborted_scan_reports_no_deletions(self, ws: Workspace) -> None:
        b, cfg = baseline_from(ws)
        for i in range(5):
            (ws.data / f"f{i}").write_text("x")
        cfg2 = ws.config(max_files=2)
        res = Scanner(cfg2.scan).scan()
        assert res.aborted
        ev = integrity.compare(cfg2, b, res, scan_id="t")
        assert EventType.DELETED not in {e.event_type for e in ev}

    def test_vanished_file_is_deleted_and_flagged(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        b, cfg = baseline_from(ws)
        target = ws.data / "a.txt"
        real_open = os.open

        def vanish(path, flags, *a, **k):  # type: ignore[no-untyped-def]
            if str(path) == str(target):
                target.unlink()
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(scanner.os, "open", vanish)
        res = Scanner(cfg.scan).scan()
        ev = integrity.compare(cfg, b, res, scan_id="t")
        assert by_type(ev) == {"deleted": ["a.txt"]}
        assert IssueKind.VANISHED in {i.kind for i in res.issues}

    def test_newly_excluded_paths_are_not_deletions(self, ws: Workspace) -> None:
        b, _ = baseline_from(ws)
        cfg2 = ws.config(exclude=[f"{ws.data}/sub/**"])
        res = Scanner(cfg2.scan).scan()
        ev = integrity.compare(cfg2, b, res, scan_id="t")
        assert by_type(ev) == {}

    def test_unhashed_entries_do_not_fake_modifications(self, ws: Workspace) -> None:
        b, cfg = baseline_from(ws)
        res = Scanner(cfg.scan).scan()
        key = str(ws.data / "a.txt")
        res.entries[key] = dataclasses.replace(res.entries[key], sha256=None)
        assert integrity.compare(cfg, b, res, scan_id="t") == []

    def test_scope_limits_deletion_detection(self, ws: Workspace) -> None:
        b, cfg = baseline_from(ws)
        (ws.data / "a.txt").unlink()
        (ws.data / "sub" / "b.txt").unlink()
        res = Scanner(cfg.scan).scan([str(ws.data / "sub")])
        ev = integrity.compare(cfg, b, res, scan_id="t", scope=[str(ws.data / "sub")])
        assert by_type(ev) == {"deleted": ["b.txt"]}


class TestPolicy:
    def test_first_matching_rule_wins_and_threshold(self, ws: Workspace) -> None:
        policy = {
            "alert_threshold": "high",
            "rules": [
                {"name": "sub-critical", "paths": [f"{ws.data}/sub/**"], "severity": "critical"},
                {"name": "all-low", "paths": [f"{ws.data}/**"], "severity": "low"},
            ],
        }
        cfg = ws.config(policy=policy)
        b, _ = baseline_from(ws, cfg)
        (ws.data / "a.txt").write_text("changed")
        (ws.data / "sub" / "b.txt").write_text("changed")
        res = Scanner(cfg.scan).scan()
        ev = {Path(e.path).name: e for e in integrity.compare(cfg, b, res, scan_id="t")}
        assert (ev["b.txt"].severity, ev["b.txt"].rule) == (Severity.CRITICAL, "sub-critical")
        assert (ev["a.txt"].severity, ev["a.txt"].rule) == (Severity.LOW, "all-low")
        report = integrity.build_report(cfg, b, res, list(ev.values()), scan_id="t")
        assert report.summary.alert and report.summary.max_severity is Severity.CRITICAL

    def test_event_filter_in_rule(self, ws: Workspace) -> None:
        cfg = ws.config(
            policy={
                "rules": [
                    {"name": "adds", "paths": [f"{ws.data}/**"], "events": ["added"], "severity": "low"}
                ]
            }
        )
        b, _ = baseline_from(ws, cfg)
        (ws.data / "n").write_text("n")
        (ws.data / "a.txt").write_text("zzz")
        res = Scanner(cfg.scan).scan()
        ev = {e.event_type.value: e for e in integrity.compare(cfg, b, res, scan_id="t")}
        assert ev["added"].severity is Severity.LOW and ev["modified"].severity is Severity.HIGH

    def test_below_threshold_is_not_alert(self, ws: Workspace) -> None:
        cfg = ws.config(policy={"alert_threshold": "critical"})
        b, _ = baseline_from(ws, cfg)
        (ws.data / "a.txt").write_text("zzz")
        res = Scanner(cfg.scan).scan()
        ev = integrity.compare(cfg, b, res, scan_id="t")
        rep = integrity.build_report(cfg, b, res, ev, scan_id="t")
        assert ev and not rep.summary.alert


def _rec(**kw: object) -> FileRecord:
    base = dict(type=FileType.FILE, size=1, mode="0644", uid=0, gid=0, mtime_ns=1, sha256="a" * 64)
    return FileRecord(**{**base, **kw})  # type: ignore[arg-type]


@settings(max_examples=60, deadline=None)
@given(
    size=st.integers(0, 10), mode=st.sampled_from(["0644", "0600", "0755"]),
    uid=st.integers(0, 3), mtime=st.integers(0, 3), sha=st.sampled_from(["a" * 64, "b" * 64]),
)  # fmt: skip
def test_diff_record_is_empty_iff_records_equal(size: int, mode: str, uid: int, mtime: int, sha: str) -> None:
    old = _rec()
    new = _rec(size=size, mode=mode, uid=uid, mtime_ns=mtime, sha256=sha)
    changes = integrity.diff_record("/p", old, new)
    assert (changes == []) == (old == new)


@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
@given(
    names=st.lists(st.from_regex(r"[a-z]{1,5}", fullmatch=True), min_size=1, max_size=6, unique=True),
    data=st.data(),
)
def test_compare_finds_exactly_the_injected_changes(
    tmp_path_factory: pytest.TempPathFactory, names: list[str], data: st.DataObject
) -> None:
    from fim.config import parse_config

    root = tmp_path_factory.mktemp("cmp") / "data"
    root.mkdir()
    for n in names:
        (root / n).write_text(n)
    cfg = parse_config({"baseline": {"dir": str(root.parent / "b")}, "scan": {"roots": [str(root)]}})
    res0 = Scanner(cfg.scan).scan()
    body = {
        "format": "fim-baseline", "schema_version": 1, "version": 1, "created_at": "x", "hostname": "h",
        "tool_version": "t", "roots": cfg.scan.roots, "exclude": [], "symlinks": "record", "complete": True,
        "issues": [], "prev_sha256": None, "entries": {p: record_to_json(r) for p, r in res0.entries.items()},
    }  # fmt: skip
    body["content_sha256"] = compute_content_hash(body)
    b = Baseline.model_validate(body)
    modified = set(data.draw(st.lists(st.sampled_from(names), unique=True, max_size=len(names))))
    remaining = [n for n in names if n not in modified]
    deleted = set(data.draw(st.lists(st.sampled_from(remaining), unique=True))) if remaining else set()
    for n in modified:
        (root / n).write_text(n + "-changed")
    for n in deleted:
        (root / n).unlink()
    (root / "ZZnew").write_text("new")
    ev = integrity.compare(cfg, b, Scanner(cfg.scan).scan(), scan_id="p")
    got = {(e.event_type.value, Path(e.path).name) for e in ev}
    want = {("modified", n) for n in modified} | {("deleted", n) for n in deleted} | {("added", "ZZnew")}
    assert got == want
