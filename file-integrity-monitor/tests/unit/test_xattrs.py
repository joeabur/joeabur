from __future__ import annotations

import errno
import os
import struct
from pathlib import Path

import pytest

from fim import integrity, scanner
from fim.models import EventType, IssueKind, Severity
from fim.scanner import Scanner, read_xattrs
from tests.conftest import Workspace
from tests.unit.test_integrity_rules import baseline_from, by_type, events_for


def _xattr_ok(path: Path) -> bool:
    try:
        os.setxattr(path, "user.fimprobe", b"1")
        os.removexattr(path, "user.fimprobe")
    except OSError:
        return False
    return True


@pytest.fixture
def xws(ws: Workspace) -> Workspace:
    if not _xattr_ok(ws.data / "a.txt"):
        pytest.skip("filesystem under the temp dir has no user.* xattr support")
    return ws


def test_records_xattr_hashes_not_values(xws: Workspace) -> None:
    os.setxattr(xws.data / "a.txt", "user.label", b"top-secret-value")
    rec = Scanner(xws.config().scan).scan().entries[str(xws.data / "a.txt")]
    assert list(rec.xattrs or {}) == ["user.label"]
    assert "top-secret-value" not in str(rec.xattrs)  # only a digest is stored


def test_xattr_change_add_remove_modify(xws: Workspace) -> None:
    f = xws.data / "a.txt"
    os.setxattr(f, "user.keep", b"1")
    os.setxattr(f, "user.gone", b"x")
    b, cfg = baseline_from(xws)
    os.setxattr(f, "user.keep", b"2")
    os.removexattr(f, "user.gone")
    os.setxattr(f, "user.new", b"n")
    ev = events_for(xws, b, cfg)
    assert by_type(ev) == {"xattr_changed": ["a.txt"]}
    assert {c.field for c in ev[0].changes} == {"xattr:user.keep", "xattr:user.gone", "xattr:user.new"}
    assert ev[0].severity is Severity.HIGH


def test_xattr_change_on_directory(xws: Workspace) -> None:
    b, cfg = baseline_from(xws)
    os.setxattr(xws.data / "sub", "user.x", b"1")
    assert by_type(events_for(xws, b, cfg)) == {"xattr_changed": ["sub"]}


def test_xattr_only_change_does_not_alter_content_events(xws: Workspace) -> None:
    b, cfg = baseline_from(xws)
    os.setxattr(xws.data / "a.txt", "user.x", b"1")
    assert [e.event_type for e in events_for(xws, b, cfg)] == [EventType.XATTR_CHANGED]


def test_disabled_option_records_nothing_and_ignores_changes(xws: Workspace) -> None:
    b, cfg = baseline_from(xws, xattrs=False)
    assert all(r.xattrs is None for r in b.entries.values())
    os.setxattr(xws.data / "a.txt", "user.x", b"1")
    assert events_for(xws, b, cfg) == []


def test_old_baseline_without_xattrs_does_not_alert(xws: Workspace) -> None:
    b, cfg = baseline_from(xws, xattrs=False)  # as produced by a pre-xattr version
    cfg2 = xws.config(xattrs=True)
    res = Scanner(cfg2.scan).scan()
    assert integrity.compare(cfg2, b, res, scan_id="t") == []


def test_unsupported_filesystem_gives_none(monkeypatch: pytest.MonkeyPatch, ws: Workspace) -> None:
    def nosup(*a: object, **k: object) -> None:
        raise OSError(errno.ENOTSUP, "Operation not supported")

    monkeypatch.setattr(scanner.os, "listxattr", nosup)
    res = Scanner(ws.config().scan).scan()
    assert res.complete and all(r.xattrs is None for r in res.entries.values())


def test_xattr_permission_error_is_reported_not_swallowed(
    monkeypatch: pytest.MonkeyPatch, ws: Workspace
) -> None:
    def deny(*a: object, **k: object) -> None:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(scanner.os, "listxattr", deny)
    res = Scanner(ws.config().scan).scan()
    assert not res.complete
    assert any(i.kind is IssueKind.UNREADABLE and i.detail.startswith("xattrs:") for i in res.issues)


def test_attribute_vanishing_between_list_and_get(monkeypatch: pytest.MonkeyPatch, xws: Workspace) -> None:
    os.setxattr(xws.data / "a.txt", "user.x", b"1")
    real = os.getxattr

    def gone(*a: object, **k: object) -> bytes:
        raise OSError(errno.ENODATA, "gone")

    monkeypatch.setattr(scanner.os, "getxattr", gone)
    assert read_xattrs(str(xws.data / "a.txt")) == {}
    monkeypatch.setattr(scanner.os, "getxattr", real)


@pytest.mark.skipif(os.geteuid() != 0, reason="setting security.capability needs CAP_SETFCAP")
def test_file_capability_is_critical(xws: Workspace) -> None:
    b, cfg = baseline_from(xws)
    # VFS_CAP_REVISION_2 blob granting CAP_NET_RAW (bit 13) as permitted+effective
    blob = struct.pack("<IIIII", 0x02000001, 1 << 13, 0, 0, 0)
    try:
        os.setxattr(xws.data / "a.txt", "security.capability", blob)
    except OSError as exc:
        pytest.skip(f"cannot set file capability here: {exc}")
    ev = events_for(xws, b, cfg)
    x = next(e for e in ev if e.event_type is EventType.XATTR_CHANGED)
    assert x.severity is Severity.CRITICAL and "file_capability_set" in x.risk_flags
