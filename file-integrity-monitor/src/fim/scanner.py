"""Filesystem scanner: walks configured roots and produces FileRecords plus explicit issues.

Design rules
------------
* Nothing is ever written, chmod-ed, or restored. Files are opened read-only (O_NOATIME is
  requested where permitted so the scan does not even touch atime).
* Anything that prevents full verification becomes a ScanIssue. A scan with blocking issues is
  *incomplete* and must never be reported as clean.
* Symlinks are not followed unless ``symlinks = "follow"``; even then targets outside the
  configured roots are only followed with ``follow_outside_roots = true``.
* Special files (FIFOs, sockets, devices) are recorded from lstat and never opened.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass, field

from fim.config import ScanConfig
from fim.hashing import HashAborted, hash_fd
from fim.models import FileRecord, FileType, IssueKind, ScanIssue
from fim.pathutil import is_within, matches_any

_INFORMATIONAL = {IssueKind.SYMLINK_OUTSIDE_ROOT}


def is_blocking(issue: ScanIssue) -> bool:
    return issue.kind not in _INFORMATIONAL


@dataclass
class ScanResult:
    roots: list[str]
    entries: dict[str, FileRecord] = field(default_factory=dict)
    issues: list[ScanIssue] = field(default_factory=list)
    entries_scanned: int = 0
    bytes_hashed: int = 0
    aborted: bool = False
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def complete(self) -> bool:
        return not any(is_blocking(i) for i in self.issues)

    def issue_paths(self) -> set[str]:
        return {i.path for i in self.issues if is_blocking(i)}


class _Abort(Exception):
    pass


def _record_from_stat(
    st: os.stat_result, ftype: FileType, sha: str | None, link_target: str | None = None
) -> FileRecord:
    return FileRecord(
        type=ftype,
        size=st.st_size,
        mode=f"{st.st_mode & 0o7777:04o}",
        uid=st.st_uid,
        gid=st.st_gid,
        mtime_ns=st.st_mtime_ns,
        sha256=sha,
        link_target=link_target,
    )


class Scanner:
    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self._real_roots = [os.path.realpath(r) for r in cfg.roots]
        self._result = ScanResult(roots=list(cfg.roots))
        self._deadline: float | None = None
        self._root_dev = 0

    # ---------------------------------------------------------------- public API
    def scan(self, roots: list[str] | None = None) -> ScanResult:
        """Scan ``roots`` (default: all configured roots) and return records plus issues."""
        targets = roots if roots is not None else list(self.cfg.roots)
        self._result = ScanResult(roots=list(targets))
        res = self._result
        res.started_at = time.time()
        self._deadline = time.monotonic() + self.cfg.timeout_seconds if self.cfg.timeout_seconds else None
        try:
            for root in targets:
                self._scan_root(root)
        except _Abort:
            res.aborted = True
        res.finished_at = time.time()
        return res

    # ---------------------------------------------------------------- internals
    def _issue(self, kind: IssueKind, path: str, detail: str = "") -> None:
        self._result.issues.append(ScanIssue(kind=kind, path=path, detail=detail))

    def _tick(self, path: str) -> None:
        res = self._result
        res.entries_scanned += 1
        if res.entries_scanned > self.cfg.max_files:
            self._issue(IssueKind.LIMIT_REACHED, path, f"max_files={self.cfg.max_files} exceeded")
            raise _Abort
        if self._deadline is not None and time.monotonic() > self._deadline:
            self._issue(IssueKind.TIMEOUT, path, f"timeout_seconds={self.cfg.timeout_seconds}")
            raise _Abort

    def _scan_root(self, root: str) -> None:
        try:
            # roots are operator-configured, so following a symlinked root is explicit intent
            st = os.stat(root)
        except FileNotFoundError:
            self._issue(IssueKind.ROOT_MISSING, root, "configured root does not exist")
            return
        except OSError as exc:
            self._issue(IssueKind.UNREADABLE, root, exc.strerror or str(exc))
            return
        self._root_dev = st.st_dev
        self._walk(root)

    def _walk(self, start: str) -> None:
        stack: list[tuple[str, int, tuple[str, ...]]] = [(start, 0, ())]
        while stack:
            cur, depth, chain = stack.pop()
            if self.cfg.exclude and matches_any(cur, self.cfg.exclude):
                continue
            try:
                lst = os.lstat(cur)
            except FileNotFoundError:
                self._issue(IssueKind.VANISHED, cur, "disappeared before it could be inspected")
                continue
            except OSError as exc:
                self._issue(IssueKind.UNREADABLE, cur, exc.strerror or str(exc))
                continue
            mode = lst.st_mode
            if stat.S_ISDIR(mode):
                if self.cfg.exclude and matches_any(cur, self.cfg.exclude, is_dir=True):
                    continue
                self._tick(cur)
                self._result.entries[cur] = _record_from_stat(lst, FileType.DIR, None)
                if not (self.cfg.one_file_system and lst.st_dev != self._root_dev):
                    self._push_children(cur, depth, chain, stack)
            elif stat.S_ISLNK(mode):
                self._handle_symlink(cur, lst, depth, chain, stack)
            elif stat.S_ISREG(mode):
                self._tick(cur)
                self._handle_file(cur, lst, follow=False)
            else:
                self._tick(cur)
                self._result.entries[cur] = _record_from_stat(lst, FileType.SPECIAL, None)

    def _push_children(
        self,
        cur: str,
        depth: int,
        chain: tuple[str, ...],
        stack: list[tuple[str, int, tuple[str, ...]]],
    ) -> None:
        if depth >= self.cfg.max_depth:
            self._issue(IssueKind.MAX_DEPTH, cur, f"max_depth={self.cfg.max_depth}")
            return
        try:
            with os.scandir(cur) as it:
                names = sorted(e.name for e in it)
        except FileNotFoundError:
            self._issue(IssueKind.VANISHED, cur, "directory disappeared during listing")
            return
        except OSError as exc:
            self._issue(IssueKind.WALK_ERROR, cur, exc.strerror or str(exc))
            return
        base = "" if cur == "/" else cur
        for name in reversed(names):  # LIFO stack: reversed push => sorted processing order
            stack.append((f"{base}/{name}", depth + 1, chain))

    # ---- symlinks
    def _handle_symlink(
        self,
        cur: str,
        lst: os.stat_result,
        depth: int,
        chain: tuple[str, ...],
        stack: list[tuple[str, int, tuple[str, ...]]],
    ) -> None:
        policy = self.cfg.symlinks
        if policy == "skip":
            return
        self._tick(cur)
        try:
            target = os.readlink(cur)
        except FileNotFoundError:
            self._issue(IssueKind.VANISHED, cur, "symlink disappeared")
            return
        except OSError as exc:
            self._issue(IssueKind.UNREADABLE, cur, exc.strerror or str(exc))
            return
        link_rec = _record_from_stat(lst, FileType.SYMLINK, None, target)
        if policy == "record":
            self._result.entries[cur] = link_rec
            return
        real = os.path.realpath(cur)
        inside = any(is_within(real, r) for r in self._real_roots)
        if not inside and not self.cfg.follow_outside_roots:
            detail = f"target {real} is outside configured roots; not followed"
            self._issue(IssueKind.SYMLINK_OUTSIDE_ROOT, cur, detail)
            self._result.entries[cur] = link_rec
            return
        try:
            tst = os.stat(cur)
        except FileNotFoundError:  # dangling: the link itself is still recorded
            self._result.entries[cur] = link_rec
            return
        except OSError as exc:
            self._issue(IssueKind.UNREADABLE, cur, exc.strerror or str(exc))
            return
        if stat.S_ISDIR(tst.st_mode):
            self._result.entries[cur] = link_rec
            parent_real = os.path.realpath(os.path.dirname(cur))
            if real in chain or is_within(parent_real, real):
                self._issue(IssueKind.SYMLINK_LOOP, cur, f"link resolves to ancestor {real}")
                return
            if self.cfg.exclude and matches_any(cur, self.cfg.exclude, is_dir=True):
                return
            self._push_children(cur, depth, (*chain, real), stack)
        elif stat.S_ISREG(tst.st_mode):
            self._handle_file(cur, lst, follow=True, link_target=target)
        else:
            self._result.entries[cur] = link_rec

    # ---- regular files
    @contextlib.contextmanager
    def _open_ro(self, path: str, follow: bool) -> Iterator[int]:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if not follow:
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags | getattr(os, "O_NOATIME", 0))
        except PermissionError:
            # O_NOATIME needs ownership/CAP_FOWNER; retry without it so a real EACCES surfaces
            fd = os.open(path, flags)
        try:
            yield fd
        finally:
            os.close(fd)

    def _handle_file(
        self, path: str, lst: os.stat_result, *, follow: bool, link_target: str | None = None
    ) -> None:
        ftype = FileType.SYMLINK if follow else FileType.FILE
        limit = self.cfg.max_file_bytes or None
        try:
            with self._open_ro(path, follow) as fd:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or (
                    not follow and (st.st_ino, st.st_dev) != (lst.st_ino, lst.st_dev)
                ):
                    self._issue(
                        IssueKind.REPLACED_DURING_SCAN,
                        path,
                        "file type or inode changed before open",
                    )
                    return
                if limit is not None and st.st_size > limit:
                    detail = f"{st.st_size} bytes exceeds max_file_bytes={limit}; content not hashed"
                    self._issue(IssueKind.TOO_LARGE, path, detail)
                    self._result.entries[path] = _record_from_stat(st, ftype, None, link_target)
                    return
                try:
                    digest, nread = hash_fd(fd, chunk_size=self.cfg.chunk_size, byte_limit=st.st_size)
                except HashAborted:  # grew while we were reading it
                    digest, nread = "", -1
                st2 = os.fstat(fd)
        except FileNotFoundError:
            self._issue(IssueKind.VANISHED, path, "disappeared before it could be read")
            return
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                self._issue(IssueKind.REPLACED_DURING_SCAN, path, "replaced by a symlink before open")
            else:
                self._issue(IssueKind.UNREADABLE, path, exc.strerror or str(exc))
            # metadata we do have is still evidence, but there is no content hash
            self._result.entries[path] = _record_from_stat(lst, ftype, None, link_target)
            return
        if nread != st.st_size or (st2.st_size, st2.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
            detail = f"size/mtime changed while hashing (size {st.st_size} -> {st2.st_size})"
            self._issue(IssueKind.CHANGED_DURING_HASH, path, detail)
            self._result.entries[path] = _record_from_stat(st2, ftype, None, link_target)
            return
        self._result.bytes_hashed += nread
        self._result.entries[path] = _record_from_stat(st, ftype, digest, link_target)
