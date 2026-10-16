from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from fim import baseline as baseline_mod
from fim import service
from fim.baseline import BaselineStore, atomic_write
from fim.errors import BaselineError, LockError, TrustError
from fim.scanner import Scanner
from tests.conftest import Workspace


def make_store(ws: Workspace, **kw: int) -> tuple[BaselineStore, object]:
    cfg = ws.config()
    return BaselineStore(cfg.baseline.dir, **kw), cfg


def commit(store: BaselineStore, cfg, action: str = "create", reason: str = "t", signer=None):  # type: ignore[no-untyped-def]
    res = Scanner(cfg.scan).scan()
    return service.baseline_from_scan(store, cfg, res, action=action, reason=reason, signer=signer)


def test_roundtrip_and_permissions(ws: Workspace) -> None:
    store, cfg = make_store(ws)
    b = commit(store, cfg)
    assert b.version == 1 and b.prev_sha256 is None
    loaded = store.load()
    assert loaded.baseline == b
    assert (store.dir.stat().st_mode & 0o777) == 0o700
    for f in store.dir.iterdir():
        assert (f.stat().st_mode & 0o777) == 0o600, f
    assert store.current_version() == 1


def test_versions_chain(ws: Workspace) -> None:
    store, cfg = make_store(ws)
    b1 = commit(store, cfg)
    b2 = commit(store, cfg, "update")
    assert (b2.version, b2.prev_sha256) == (2, b1.content_sha256)
    assert store.versions() == [1, 2]
    assert store.load(1).baseline.version == 1  # old versions remain loadable


def test_prune_keeps_current_and_limit(ws: Workspace) -> None:
    store, cfg = make_store(ws, keep_versions=3)
    for _ in range(6):
        commit(store, cfg, "update")
    assert store.versions() == [4, 5, 6]
    assert store.load().baseline.version == 6


class TestCorruption:
    def test_bit_flip_in_entry_detected_by_content_hash(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        p = store.path_for(1)
        doc = json.loads(p.read_text())
        key = next(k for k in doc["entries"] if k.endswith("a.txt"))
        doc["entries"][key]["sha256"] = "0" * 64  # attacker 'blesses' a file by editing the baseline
        p.write_text(json.dumps(doc))
        with pytest.raises(TrustError, match="integrity check"):
            store.load()

    def test_truncated_json(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        p = store.path_for(1)
        p.write_bytes(p.read_bytes()[:50])
        with pytest.raises(TrustError, match="corrupt"):
            store.load()

    @pytest.mark.parametrize("payload", [b"", b"null", b"[]", b'{"format":"fim-baseline"}', b"\xff\xfe"])
    def test_garbage_files(self, ws: Workspace, payload: bytes) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        store.path_for(1).write_bytes(payload)
        with pytest.raises(TrustError):
            store.load()

    def test_version_mismatch_renamed_file(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        commit(store, cfg, "update")
        store.path_for(1).write_bytes(store.path_for(2).read_bytes())
        with pytest.raises(TrustError, match="claims to be version"):
            store.load(1)

    def test_missing_and_corrupt_current(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        (store.dir / "CURRENT").write_text("banana")
        with pytest.raises(BaselineError, match="CURRENT"):
            store.load()
        (store.dir / "CURRENT").unlink()
        with pytest.raises(BaselineError, match="no baseline"):
            store.load()

    def test_oversized_baseline_refused(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        store.max_bytes = 10
        with pytest.raises(BaselineError, match="max_baseline_bytes"):
            store.load()

    def test_symlinked_baseline_file_refused(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        real = store.path_for(1)
        moved = ws.root / "elsewhere.json"
        real.rename(moved)
        real.symlink_to(moved)
        with pytest.raises(BaselineError, match="regular file"):
            store.load()


class TestDirectorySafety:
    def test_unsafe_permissions_refused(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        store.dir.chmod(0o755)
        with pytest.raises(BaselineError, match="unsafe permissions"):
            store.load()

    def test_symlinked_directory_refused(self, ws: Workspace) -> None:
        real = ws.root / "real-b"
        real.mkdir(mode=0o700)
        link = ws.root / "link-b"
        link.symlink_to(real)
        with pytest.raises(BaselineError, match="symlink"):
            BaselineStore(link).ensure_dir(create=False)

    def test_wrong_owner_refused(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        monkeypatch.setattr(baseline_mod.os, "geteuid", lambda: 4242)
        with pytest.raises(BaselineError, match="owned by"):
            store.ensure_dir(create=False)


class TestAtomicity:
    def test_never_overwrites_without_flag(self, tmp_path: Path) -> None:
        atomic_write(tmp_path, "x", b"one", overwrite=False)
        with pytest.raises(FileExistsError):
            atomic_write(tmp_path, "x", b"two", overwrite=False)
        assert (tmp_path / "x").read_bytes() == b"one"
        assert [p.name for p in tmp_path.iterdir()] == ["x"]  # no temp litter

    def test_overwrite_is_replace(self, tmp_path: Path) -> None:
        atomic_write(tmp_path, "x", b"one", overwrite=True)
        atomic_write(tmp_path, "x", b"two", overwrite=True)
        assert (tmp_path / "x").read_bytes() == b"two"

    @pytest.mark.parametrize("fail_at", ["fsync", "replace"])
    def test_failure_leaves_old_content_and_no_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_at: str
    ) -> None:
        atomic_write(tmp_path, "x", b"original", overwrite=True)

        def boom(*a: object, **k: object) -> None:
            raise OSError(5, "simulated I/O error")

        monkeypatch.setattr(baseline_mod.os, fail_at, boom)
        with pytest.raises(OSError, match="simulated"):
            atomic_write(tmp_path, "x", b"NEW-CONTENT", overwrite=True)
        monkeypatch.undo()
        assert (tmp_path / "x").read_bytes() == b"original"
        assert [p.name for p in tmp_path.iterdir()] == ["x"]

    def test_crash_before_current_moves_leaves_previous_baseline_active(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        real = baseline_mod.atomic_write

        def crash_on_current(directory, name, data, *, overwrite):  # type: ignore[no-untyped-def]
            if name == "CURRENT":
                raise KeyboardInterrupt  # interrupted exactly before the pointer moves
            return real(directory, name, data, overwrite=overwrite)

        monkeypatch.setattr(baseline_mod, "atomic_write", crash_on_current)
        with pytest.raises(KeyboardInterrupt):
            commit(store, cfg, "update")
        monkeypatch.undo()
        assert store.current_version() == 1
        store.load()  # still valid
        assert store.versions() == [1, 2]  # orphan v2 exists but is not active
        b3 = commit(store, cfg, "update")  # next commit never collides with the orphan
        assert b3.version == 3

    def test_signature_failure_does_not_move_current(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)

        def bad_signer(data: bytes) -> tuple[str, str]:
            raise TrustError("hsm unavailable")

        with pytest.raises(TrustError):
            commit(store, cfg, "update", signer=bad_signer)
        assert store.current_version() == 1


class TestConcurrency:
    def test_threads_get_unique_versions(self, ws: Workspace) -> None:
        store, cfg = make_store(ws, keep_versions=100)
        commit(store, cfg)
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                commit(BaselineStore(cfg.baseline.dir, keep_versions=100), cfg, "update")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors
        assert store.versions() == list(range(1, 10))
        for v in store.versions():
            store.load(v)
        assert store.verify_audit() == 9

    def test_processes_get_unique_versions(self, ws: Workspace) -> None:
        store, cfg = make_store(ws, keep_versions=100)
        commit(store, cfg)
        code = textwrap.dedent(
            f"""
            from fim.config import load_config
            from fim import service
            from fim.scanner import Scanner
            cfg = load_config({str(ws.config_path)!r})
            st = service.store_for(cfg)
            res = Scanner(cfg.scan).scan()
            for _ in range(3):
                service.baseline_from_scan(st, cfg, res, action="update", reason="p", signer=None)
            """
        )
        procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(4)]
        assert [p.wait(timeout=60) for p in procs] == [0, 0, 0, 0]
        assert store.versions() == list(range(4, 14))  # default keep_versions=10 pruned the rest
        store.load()
        assert store.verify_audit() == 13

    def test_lock_timeout(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        with store.lock(), pytest.raises(LockError, match="another FIM operation"):
            with BaselineStore(store.dir).lock(timeout=0.2):
                pass


class TestAudit:
    def test_chain_and_fields(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg, reason="first")
        commit(store, cfg, "update", reason="second")
        recs = store.read_audit()
        assert [r["action"] for r in recs] == ["create", "update"]
        assert recs[1]["prev_hash"] == recs[0]["hash"]
        assert {"user", "uid", "pid", "timestamp", "reason", "baseline_sha256"} <= recs[0].keys()
        assert store.verify_audit() == 2
        assert (store.audit_path.stat().st_mode & 0o777) == 0o600

    def test_edit_detected(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg, reason="first")
        commit(store, cfg, "update", reason="second")
        lines = store.audit_path.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["reason"] = "totally legitimate"
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        store.audit_path.write_text("\n".join(lines) + "\n")
        with pytest.raises(TrustError, match="modified"):
            store.verify_audit()

    def test_deleted_record_detected(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        for _ in range(3):
            commit(store, cfg, "update")
        lines = store.audit_path.read_text().splitlines()
        store.audit_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
        with pytest.raises(TrustError, match="broken"):
            store.verify_audit()

    def test_rollback_to_older_baseline_detected(self, ws: Workspace) -> None:
        store, cfg = make_store(ws)
        commit(store, cfg)
        (ws.data / "a.txt").write_text("evil")
        commit(store, cfg, "update")
        (store.dir / "CURRENT").write_text("000001\n")  # attacker re-points to the older baseline
        with pytest.raises(TrustError, match="rollback"):
            service.load_trusted(cfg, store)
