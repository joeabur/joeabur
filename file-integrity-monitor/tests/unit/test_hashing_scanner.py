from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fim import hashing, scanner
from fim.models import FileType, IssueKind
from fim.scanner import Scanner
from tests.conftest import Workspace

pytestmark = pytest.mark.filterwarnings("ignore")


def scan(ws: Workspace, **kw: object) -> scanner.ScanResult:
    return Scanner(ws.config(**kw).scan).scan()


def kinds(res: scanner.ScanResult) -> set[IssueKind]:
    return {i.kind for i in res.issues}


class TestHashing:
    def test_known_vectors(self, tmp_path: Path) -> None:
        for data, want in [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ]:
            p = tmp_path / "f"
            p.write_bytes(data)
            fd = os.open(p, os.O_RDONLY)
            try:
                assert hashing.hash_fd(fd, chunk_size=4096) == (want, len(data))
            finally:
                os.close(fd)

    def test_streams_large_file_across_chunks(self, tmp_path: Path) -> None:
        p = tmp_path / "big.bin"
        blob = os.urandom(1024 * 1024)
        with p.open("wb") as fh:
            for _ in range(12):  # 12 MiB, never held in memory by the hasher
                fh.write(blob)
        fd = os.open(p, os.O_RDONLY)
        try:
            digest, n = hashing.hash_fd(fd, chunk_size=4096 + 7)
        finally:
            os.close(fd)
        assert n == 12 * 1024 * 1024
        h = hashlib.sha256()
        for _ in range(12):
            h.update(blob)
        assert digest == h.hexdigest()

    def test_byte_limit(self, tmp_path: Path) -> None:
        p = tmp_path / "f"
        p.write_bytes(b"x" * 100)
        fd = os.open(p, os.O_RDONLY)
        try:
            with pytest.raises(hashing.HashAborted):
                hashing.hash_fd(fd, chunk_size=10, byte_limit=50)
        finally:
            os.close(fd)

    @settings(max_examples=40, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
    @given(data=st.binary(max_size=20000), chunk=st.integers(min_value=1, max_value=5000))
    def test_matches_hashlib_for_any_chunking(self, tmp_path: Path, data: bytes, chunk: int) -> None:
        p = tmp_path / "h"
        p.write_bytes(data)
        fd = os.open(p, os.O_RDONLY)
        try:
            assert hashing.hash_fd(fd, chunk_size=chunk)[0] == hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)


class TestScannerBasics:
    def test_records_metadata_and_hash(self, ws: Workspace) -> None:
        res = scan(ws)
        assert res.complete and not res.aborted
        a = res.entries[str(ws.data / "a.txt")]
        assert a.type is FileType.FILE
        assert a.sha256 == hashlib.sha256(b"alpha\n").hexdigest()
        assert a.size == 6
        assert a.mode == f"{(ws.data / 'a.txt').stat().st_mode & 0o7777:04o}"
        assert a.uid == os.geteuid()
        assert res.entries[str(ws.data)].type is FileType.DIR
        assert res.entries[str(ws.data / "sub")].type is FileType.DIR

    def test_identical_scans_are_identical(self, ws: Workspace) -> None:
        assert scan(ws).entries == scan(ws).entries

    def test_scan_does_not_modify_files(self, ws: Workspace) -> None:
        before = {p: p.stat() for p in ws.data.rglob("*")}
        scan(ws)
        for p, st_before in before.items():
            st_after = p.stat()
            assert (st_after.st_mtime_ns, st_after.st_mode, st_after.st_size) == (
                st_before.st_mtime_ns,
                st_before.st_mode,
                st_before.st_size,
            )

    def test_exclusions_prune_and_file_patterns(self, ws: Workspace) -> None:
        (ws.data / "cache").mkdir()
        (ws.data / "cache" / "x").write_text("x")
        (ws.data / "noise.log").write_text("n")
        res = scan(ws, exclude=[f"{ws.data}/cache/**", f"{ws.data}/*.log"])
        paths = set(res.entries)
        assert str(ws.data / "cache") not in paths
        assert str(ws.data / "cache" / "x") not in paths
        assert str(ws.data / "noise.log") not in paths
        assert str(ws.data / "a.txt") in paths

    def test_root_missing_is_reported(self, ws: Workspace) -> None:
        cfg = ws.config()
        cfg.scan.roots.append(str(ws.root / "ghost"))
        res = Scanner(cfg.scan).scan()
        assert IssueKind.ROOT_MISSING in kinds(res) and not res.complete

    def test_special_files_not_opened(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        fifo = ws.data / "pipe"
        os.mkfifo(fifo)
        opened: list[str] = []
        real_open = os.open
        monkeypatch.setattr(
            scanner.os, "open", lambda p, *a, **k: (opened.append(str(p)), real_open(p, *a, **k))[1]
        )
        res = scan(ws)  # would hang forever if the FIFO were opened for reading
        assert res.entries[str(fifo)].type is FileType.SPECIAL
        assert str(fifo) not in opened

    def test_max_files_aborts_and_flags_incomplete(self, ws: Workspace) -> None:
        for i in range(10):
            (ws.data / f"f{i}").write_text(str(i))
        res = scan(ws, max_files=5)
        assert res.aborted and not res.complete
        assert IssueKind.LIMIT_REACHED in kinds(res)

    def test_timeout_aborts(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        base = time.monotonic()
        ticks = iter(range(1000))
        monkeypatch.setattr(scanner.time, "monotonic", lambda: base + next(ticks) * 10)
        res = scan(ws, timeout_seconds=15)
        assert res.aborted and IssueKind.TIMEOUT in kinds(res)

    def test_max_depth(self, ws: Workspace) -> None:
        d = ws.data
        for i in range(5):
            d = d / f"d{i}"
            d.mkdir()
        res = scan(ws, max_depth=2)
        assert IssueKind.MAX_DEPTH in kinds(res) and not res.complete

    def test_too_large_is_not_silently_clean(self, ws: Workspace) -> None:
        (ws.data / "big").write_bytes(b"z" * 5000)
        res = scan(ws, max_file_bytes=1000)
        assert IssueKind.TOO_LARGE in kinds(res)
        rec = res.entries[str(ws.data / "big")]
        assert rec.sha256 is None and rec.size == 5000
        assert not res.complete


class TestScannerFailures:
    def test_unreadable_file_reported(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        target = str(ws.data / "a.txt")
        real_open = os.open

        def deny(path, flags, *a, **k):  # type: ignore[no-untyped-def]
            if str(path) == target:
                raise PermissionError(13, "Permission denied")
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(scanner.os, "open", deny)
        res = scan(ws)
        assert not res.complete
        assert [i for i in res.issues if i.kind is IssueKind.UNREADABLE and i.path == target]
        assert res.entries[target].sha256 is None  # metadata kept, content unverified

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions")
    def test_real_chmod_000(self, ws: Workspace) -> None:
        p = ws.data / "secret"
        p.write_text("s")
        p.chmod(0)
        try:
            assert IssueKind.UNREADABLE in kinds(scan(ws))
        finally:
            p.chmod(0o600)

    def test_unreadable_directory_listing(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        real = os.scandir

        def deny(path):  # type: ignore[no-untyped-def]
            if str(path) == str(ws.data / "sub"):
                raise PermissionError(13, "Permission denied")
            return real(path)

        monkeypatch.setattr(scanner.os, "scandir", deny)
        res = scan(ws)
        assert IssueKind.WALK_ERROR in kinds(res) and not res.complete

    def test_file_vanishes_between_listing_and_open(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = ws.data / "a.txt"
        real_open = os.open

        def vanish(path, flags, *a, **k):  # type: ignore[no-untyped-def]
            if str(path) == str(target):
                target.unlink()
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(scanner.os, "open", vanish)
        res = scan(ws)
        assert IssueKind.VANISHED in kinds(res) and not res.complete
        assert str(target) not in res.entries

    def test_file_changes_while_hashing(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        target = ws.data / "a.txt"
        real_hash = scanner.hash_fd

        def racy(fd, **kw):  # type: ignore[no-untyped-def]
            out = real_hash(fd, **kw)
            with target.open("ab") as fh:  # someone appends after we read
                fh.write(b"more")
            return out

        monkeypatch.setattr(scanner, "hash_fd", racy)
        res = scan(ws)
        assert IssueKind.CHANGED_DURING_HASH in kinds(res) and not res.complete
        assert res.entries[str(target)].sha256 is None  # an unreliable hash is never recorded

    def test_file_grows_beyond_stat_size(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        def grows(fd, **kw):  # type: ignore[no-untyped-def]
            raise hashing.HashAborted("grew")

        monkeypatch.setattr(scanner, "hash_fd", grows)
        assert IssueKind.CHANGED_DURING_HASH in kinds(scan(ws))

    def test_inode_swapped_between_lstat_and_open(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = ws.data / "a.txt"
        real_open = os.open

        def swap(path, flags, *a, **k):  # type: ignore[no-untyped-def]
            if str(path) == str(target):
                os.link(target, ws.root / "keep-old-inode")  # stop the filesystem reusing the inode number
                target.unlink()
                target.write_text("attacker content")  # new inode, same name
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(scanner.os, "open", swap)
        res = scan(ws)
        assert IssueKind.REPLACED_DURING_SCAN in kinds(res)

    def test_replaced_by_symlink_is_not_followed(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = ws.data / "a.txt"
        secret = ws.root / "outside-secret"
        secret.write_text("do not read")
        real_open = os.open
        flags_seen: list[int] = []

        def swap(path, flags, *a, **k):  # type: ignore[no-untyped-def]
            if str(path) == str(target):
                flags_seen.append(flags)
                target.unlink()
                target.symlink_to(secret)
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(scanner.os, "open", swap)
        res = scan(ws)
        assert flags_seen[0] & os.O_NOFOLLOW
        assert IssueKind.REPLACED_DURING_SCAN in kinds(res)  # ELOOP from O_NOFOLLOW
        assert res.entries.get(str(target)) is None or res.entries[str(target)].sha256 is None


class TestSymlinks:
    @pytest.fixture
    def links(self, ws: Workspace) -> Workspace:
        outside = ws.root / "outside"
        outside.mkdir()
        (outside / "o.txt").write_text("outside")
        (ws.data / "to_file").symlink_to(ws.data / "a.txt")
        (ws.data / "to_outside_dir").symlink_to(outside)
        (ws.data / "to_outside_file").symlink_to(outside / "o.txt")
        (ws.data / "dangling").symlink_to(ws.root / "nowhere")
        return ws

    def test_record_policy_never_follows(self, links: Workspace) -> None:
        res = scan(links)
        e = res.entries
        assert e[str(links.data / "to_file")].type is FileType.SYMLINK
        assert e[str(links.data / "to_file")].link_target == str(links.data / "a.txt")
        assert e[str(links.data / "to_file")].sha256 is None
        assert not any("/to_outside_dir/" in p for p in e)
        assert res.complete

    def test_skip_policy(self, links: Workspace) -> None:
        res = scan(links, symlinks="skip")
        assert not any(r.type is FileType.SYMLINK for r in res.entries.values())

    def test_follow_within_roots_only_by_default(self, links: Workspace) -> None:
        res = scan(links, symlinks="follow")
        e = res.entries
        assert e[str(links.data / "to_file")].sha256 == hashlib.sha256(b"alpha\n").hexdigest()
        assert not any("/to_outside_dir/" in p for p in e)
        assert e[str(links.data / "to_outside_file")].sha256 is None
        outside = [i for i in res.issues if i.kind is IssueKind.SYMLINK_OUTSIDE_ROOT]
        assert len(outside) == 3  # two outside targets + the dangling link
        assert res.complete  # informational: policy decision, not a coverage gap

    def test_follow_outside_requires_explicit_flag(self, links: Workspace) -> None:
        res = scan(links, symlinks="follow", follow_outside_roots=True)
        assert str(links.data / "to_outside_dir" / "o.txt") in res.entries
        assert res.entries[str(links.data / "to_outside_file")].sha256 is not None

    def test_symlink_loop_detected(self, ws: Workspace) -> None:
        (ws.data / "sub" / "up").symlink_to(ws.data)
        res = scan(ws, symlinks="follow")
        assert IssueKind.SYMLINK_LOOP in kinds(res) and not res.complete
        assert res.entries_scanned < 100

    def test_link_cycle_between_dirs_terminates(self, ws: Workspace) -> None:
        (ws.data / "x").mkdir()
        (ws.data / "y").mkdir()
        (ws.data / "x" / "to_y").symlink_to(ws.data / "y")
        (ws.data / "y" / "to_x").symlink_to(ws.data / "x")
        res = scan(ws, symlinks="follow", max_depth=20)
        assert res.entries_scanned < 500


@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
@given(
    files=st.dictionaries(
        st.from_regex(r"[a-z]{1,6}(/[a-z]{1,6}){0,2}", fullmatch=True),
        st.binary(max_size=64),
        max_size=8,
    )
)
def test_scan_hashes_match_contents_for_arbitrary_trees(
    tmp_path_factory: pytest.TempPathFactory, files: dict[str, bytes]
) -> None:
    root = tmp_path_factory.mktemp("prop") / "data"
    root.mkdir()
    written: dict[str, bytes] = {}
    for rel, data in files.items():
        p = root / rel
        if any(str(p).startswith(w + "/") or w.startswith(str(p) + "/") for w in written):
            continue  # skip file/dir name collisions
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            continue
        p.write_bytes(data)
        written[str(p)] = data
    from fim.config import parse_config

    cfg = parse_config({"baseline": {"dir": str(root.parent / "b")}, "scan": {"roots": [str(root)]}})
    res = Scanner(cfg.scan).scan()
    for path, data in written.items():
        assert res.entries[path].sha256 == hashlib.sha256(data).hexdigest()


def test_file_records_stay_lightweight(ws: Workspace) -> None:
    """Guards the memory budget (~2 KiB/entry at 300k files): records must be slotted dataclasses,
    not pydantic model instances carrying a per-object __dict__."""
    rec = scan(ws).entries[str(ws.data / "a.txt")]
    assert not hasattr(rec, "__dict__")
    assert hasattr(type(rec), "__slots__")


class TestRootsAndMounts:
    def test_single_file_root(self, ws: Workspace) -> None:
        cfg = ws.config()
        cfg.scan.roots[:] = [str(ws.data / "a.txt")]
        res = Scanner(cfg.scan).scan()
        assert list(res.entries) == [str(ws.data / "a.txt")] and res.complete

    def test_symlinked_root_is_followed_because_the_operator_named_it(self, ws: Workspace) -> None:
        link = ws.root / "rootlink"
        link.symlink_to(ws.data)
        cfg = ws.config()
        cfg.scan.roots[:] = [str(link)]
        res = Scanner(cfg.scan).scan()
        assert str(link / "a.txt") in res.entries

    def test_unstatable_root_and_entries_are_reported(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_stat, real_lstat = os.stat, os.lstat

        def deny_stat(p, *a, **k):  # type: ignore[no-untyped-def]
            if str(p) == str(ws.data):
                raise PermissionError(13, "Permission denied")
            return real_stat(p, *a, **k)

        monkeypatch.setattr(scanner.os, "stat", deny_stat)
        res = scan(ws)
        assert IssueKind.UNREADABLE in kinds(res) and not res.complete
        monkeypatch.setattr(scanner.os, "stat", real_stat)

        def deny_lstat(p, *a, **k):  # type: ignore[no-untyped-def]
            if str(p).endswith("b.txt"):
                raise PermissionError(13, "Permission denied")
            return real_lstat(p, *a, **k)

        monkeypatch.setattr(scanner.os, "lstat", deny_lstat)
        res = scan(ws)
        assert any(i.kind is IssueKind.UNREADABLE and i.path.endswith("b.txt") for i in res.issues)

    def test_readlink_failures_are_reported(self, ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
        (ws.data / "ln").symlink_to("a.txt")

        def fail(p):  # type: ignore[no-untyped-def]
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(scanner.os, "readlink", fail)
        assert IssueKind.UNREADABLE in kinds(scan(ws))

        def gone(p):  # type: ignore[no-untyped-def]
            raise FileNotFoundError

        monkeypatch.setattr(scanner.os, "readlink", gone)
        assert IssueKind.VANISHED in kinds(scan(ws))

    @pytest.mark.skipif(os.geteuid() != 0, reason="mounting needs root")
    def test_one_file_system_does_not_cross_real_mounts(self, ws: Workspace) -> None:
        import subprocess

        mnt = ws.data / "mnt"
        mnt.mkdir()
        if subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(mnt)], capture_output=True).returncode != 0:
            pytest.skip("cannot mount tmpfs here")
        try:
            (mnt / "inside-mount.txt").write_text("x")
            default = scan(ws)  # one_file_system = true
            assert str(mnt) in default.entries  # the mount point itself is recorded...
            assert str(mnt / "inside-mount.txt") not in default.entries  # ...but not crossed
            crossing = scan(ws, one_file_system=False)
            assert str(mnt / "inside-mount.txt") in crossing.entries
        finally:
            subprocess.run(["umount", str(mnt)], capture_output=True)


def test_root_that_is_a_symlink_to_a_file_is_hashed(ws: Workspace) -> None:
    link = ws.root / "filelink"
    link.symlink_to(ws.data / "a.txt")
    cfg = ws.config()
    cfg.scan.roots[:] = [str(link)]
    res = Scanner(cfg.scan).scan()
    assert res.complete
    rec = res.entries[str(link)]
    assert rec.type is FileType.FILE and rec.sha256 == hashlib.sha256(b"alpha\n").hexdigest()
