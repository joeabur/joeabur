"""Versioned, atomically written baseline storage with a hash-chained audit trail.

Layout of ``baseline.dir`` (mode 0700, owned by the running user)::

    baseline-000001.json        immutable once written
    baseline-000001.json.sig    optional detached signature
    CURRENT                     "000001\\n" pointer to the active version
    audit.jsonl                 append-only, hash-chained audit records
    .lock                       flock target

Honest scope: everything here detects accident and casual tampering. An attacker who can write
this directory *and* holds your signing key can forge all of it (see docs/security-and-limitations.md).
"""

from __future__ import annotations

import contextlib
import fcntl
import getpass
import json
import os
import re
import socket
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from fim import __version__
from fim.errors import BaselineError, LockError, TrustError
from fim.hashing import sha256_bytes
from fim.models import BASELINE_SCHEMA_VERSION, Baseline, FileRecord, ScanIssue, record_to_json

_NAME_RE = re.compile(r"^baseline-(\d{6,})\.json$")
SIGNER = Any  # callable: bytes -> tuple[str, str]  (signature text, key id)


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_content_hash(body: dict[str, Any]) -> str:
    body = {k: v for k, v in body.items() if k != "content_sha256"}
    return sha256_bytes(_canonical(body))


def serialize(baseline: Baseline) -> bytes:
    return (json.dumps(baseline.model_dump(mode="json"), sort_keys=True, indent=1) + "\n").encode()


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(directory: Path, name: str, data: bytes, *, overwrite: bool) -> None:
    """Write ``data`` to ``directory/name`` atomically (temp file + fsync + rename/link).

    With ``overwrite=False`` an existing file is never replaced (FileExistsError).
    """
    final = directory / name
    tmp = directory / f".{name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        if overwrite:
            os.replace(tmp, final)
        else:
            os.link(tmp, final)  # fails with FileExistsError instead of clobbering
            os.unlink(tmp)
        fsync_dir(directory)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


@dataclass
class LoadedBaseline:
    baseline: Baseline
    raw: bytes
    path: Path


class BaselineStore:
    def __init__(self, directory: str | Path, *, keep_versions: int = 10, max_bytes: int = 512 << 20):
        self.dir = Path(directory)
        self.keep_versions = keep_versions
        self.max_bytes = max_bytes

    # ------------------------------------------------------------ directory safety
    def ensure_dir(self, *, create: bool) -> None:
        try:
            st = os.lstat(self.dir)
        except FileNotFoundError:
            if not create:
                raise BaselineError(f"baseline directory {self.dir} does not exist") from None
            self.dir.parent.mkdir(parents=True, exist_ok=True)
            os.mkdir(self.dir, 0o700)
            os.chmod(self.dir, 0o700)
            return
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise BaselineError(f"{self.dir} must be a real directory (not a symlink or file)")
        if st.st_uid != os.geteuid():
            raise BaselineError(f"{self.dir} is owned by uid {st.st_uid}, not by the current user")
        if st.st_mode & 0o077:
            raise BaselineError(
                f"{self.dir} has unsafe permissions {st.st_mode & 0o777:04o}; run: chmod 700 {self.dir}"
            )

    @contextlib.contextmanager
    def lock(self, timeout: float = 10.0, *, create: bool = False) -> Iterator[None]:
        self.ensure_dir(create=create)
        fd = os.open(self.dir / ".lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise LockError(
                            f"another FIM operation holds {self.dir}/.lock (waited {timeout:g}s)"
                        ) from None
                    time.sleep(0.05)
            yield
        finally:
            os.close(fd)  # closing the descriptor releases the flock

    # ------------------------------------------------------------ versions
    def versions(self) -> list[int]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in self.dir.iterdir():
            m = _NAME_RE.match(p.name)
            if m:
                out.append(int(m.group(1)))
        return sorted(out)

    def path_for(self, version: int) -> Path:
        return self.dir / f"baseline-{version:06d}.json"

    def sig_path_for(self, version: int) -> Path:
        return self.dir / f"baseline-{version:06d}.json.sig"

    def current_version(self) -> int | None:
        try:
            text = (self.dir / "CURRENT").read_text().strip()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BaselineError(f"cannot read CURRENT pointer: {exc}") from exc
        if not re.fullmatch(r"\d{6,}", text):
            raise BaselineError("CURRENT pointer is corrupt")
        return int(text)

    # ------------------------------------------------------------ load / verify
    def load(self, version: int | None = None) -> LoadedBaseline:
        self.ensure_dir(create=False)
        if version is None:
            version = self.current_version()
            if version is None:
                raise BaselineError(f"no baseline in {self.dir}; run 'fim baseline create' first")
        path = self.path_for(version)
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                raise BaselineError(f"{path} is not a regular file")
            if st.st_size > self.max_bytes:
                raise BaselineError(f"{path} exceeds max_baseline_bytes ({st.st_size} bytes)")
            raw = path.read_bytes()
        except FileNotFoundError:
            raise BaselineError(f"baseline version {version} not found: {path}") from None
        except OSError as exc:
            raise BaselineError(f"cannot read {path}: {exc}") from exc
        try:
            doc = json.loads(raw)
            baseline = Baseline.model_validate(doc)
        except (ValueError, ValidationError) as exc:
            raise TrustError(f"baseline {path.name} is corrupt or malformed: {exc}") from exc
        if baseline.schema_version != BASELINE_SCHEMA_VERSION:
            raise BaselineError(
                f"baseline schema {baseline.schema_version} unsupported (expected {BASELINE_SCHEMA_VERSION})"
            )
        if baseline.version != version:
            raise TrustError(f"{path.name} claims to be version {baseline.version}")
        digest_ok = compute_content_hash(doc) == baseline.content_sha256
        del doc  # the parsed JSON tree is ~0.7 KiB/entry; release it before the caller scans
        if not digest_ok:
            raise TrustError(
                f"baseline {path.name} failed its integrity check (content hash mismatch): "
                "it was modified or corrupted after it was written"
            )
        return LoadedBaseline(baseline, raw, path)

    # ------------------------------------------------------------ write
    def commit(
        self,
        *,
        entries: dict[str, FileRecord],
        roots: list[str],
        exclude: list[str],
        symlinks: str,
        complete: bool,
        issues: list[ScanIssue],
        action: str,
        reason: str,
        signer: Any = None,
        audit_detail: dict[str, Any] | None = None,
    ) -> Baseline:
        """Write the next baseline version atomically, then move CURRENT, then audit."""
        with self.lock(create=True):
            existing = self.versions()
            current = self.current_version()
            prev_hash: str | None = None
            if current is not None:
                prev_hash = self.load(current).baseline.content_sha256
            version = max([current or 0, *existing]) + 1
            body = {
                "format": "fim-baseline",
                "schema_version": BASELINE_SCHEMA_VERSION,
                "version": version,
                "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "hostname": socket.gethostname(),
                "tool_version": __version__,
                "roots": roots,
                "exclude": exclude,
                "symlinks": symlinks,
                "complete": complete,
                "issues": [i.model_dump(mode="json") for i in issues],
                "prev_sha256": prev_hash,
                "entries": {p: record_to_json(r) for p, r in sorted(entries.items())},
            }
            body["content_sha256"] = compute_content_hash(body)
            baseline = Baseline.model_validate(body)
            data = serialize(baseline)
            try:
                atomic_write(self.dir, self.path_for(version).name, data, overwrite=False)
            except FileExistsError:
                raise BaselineError(f"refusing to overwrite existing baseline version {version}") from None
            key = None
            if signer is not None:
                sig_text, key = signer(data)
                atomic_write(self.dir, self.sig_path_for(version).name, sig_text.encode(), overwrite=False)
            atomic_write(self.dir, "CURRENT", f"{version:06d}\n".encode(), overwrite=True)
            self._audit_locked(
                action=action,
                reason=reason,
                baseline_version=version,
                baseline_sha256=baseline.content_sha256,
                detail={
                    "signed": key is not None,
                    "key_id": key,
                    "entries": len(entries),
                    "complete": complete,
                    **(audit_detail or {}),
                },
            )
            self._prune_locked(version)
            return baseline

    def write_signature(self, version: int, sig_text: str, *, reason: str, key_id: str) -> None:
        with self.lock():
            loaded = self.load(version)
            atomic_write(self.dir, self.sig_path_for(version).name, sig_text.encode(), overwrite=True)
            self._audit_locked(
                action="sign",
                reason=reason,
                baseline_version=version,
                baseline_sha256=loaded.baseline.content_sha256,
                detail={"signed": True, "key_id": key_id},
            )

    def _prune_locked(self, current: int) -> None:
        versions = [v for v in self.versions() if v != current]
        excess = max(0, len(versions) + 1 - self.keep_versions)
        for v in versions[:excess]:
            for p in (self.path_for(v), self.sig_path_for(v)):
                with contextlib.suppress(FileNotFoundError):
                    p.unlink()

    # ------------------------------------------------------------ audit trail
    @property
    def audit_path(self) -> Path:
        return self.dir / "audit.jsonl"

    def read_audit(self) -> list[dict[str, Any]]:
        try:
            lines = self.audit_path.read_text().splitlines()
        except FileNotFoundError:
            return []
        records = []
        for n, line in enumerate(lines, 1):
            try:
                records.append(json.loads(line))
            except ValueError as exc:
                raise TrustError(f"audit.jsonl line {n} is not valid JSON") from exc
        return records

    def _audit_locked(
        self,
        *,
        action: str,
        reason: str,
        baseline_version: int | None,
        baseline_sha256: str | None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        records = self.read_audit()
        prev = records[-1]["hash"] if records else "0" * 64
        try:
            user = getpass.getuser()
        except (KeyError, OSError):
            user = f"uid:{os.geteuid()}"
        rec: dict[str, Any] = {
            "seq": len(records) + 1,
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "action": action,
            "reason": reason,
            "user": user,
            "uid": os.geteuid(),
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "baseline_version": baseline_version,
            "baseline_sha256": baseline_sha256,
            "detail": detail or {},
            "prev_hash": prev,
        }
        rec["hash"] = sha256_bytes(_canonical(rec))
        fd = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, _canonical(rec) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        return rec

    def audit(self, **kwargs: Any) -> dict[str, Any]:
        with self.lock():
            return self._audit_locked(**kwargs)

    def verify_audit(self) -> int:
        """Check the hash chain; returns the number of records. Raises TrustError on breakage."""
        prev = "0" * 64
        records = self.read_audit()
        for i, rec in enumerate(records, 1):
            claimed = rec.get("hash")
            check = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("seq") != i or rec.get("prev_hash") != prev:
                raise TrustError(f"audit trail broken at record {i} (sequence/chain mismatch)")
            if sha256_bytes(_canonical(check)) != claimed:
                raise TrustError(f"audit trail record {i} was modified (hash mismatch)")
            prev = claimed
        return len(records)

    def audit_baseline_mismatch(self, baseline: Baseline) -> str | None:
        """Cross-check CURRENT against the audit trail's last baseline-writing record."""
        records = [r for r in self.read_audit() if r.get("action") in ("create", "update")]
        if not records:
            return None
        last = records[-1]
        if last["baseline_version"] != baseline.version or last["baseline_sha256"] != baseline.content_sha256:
            return (
                f"audit trail says the current baseline is v{last['baseline_version']} "
                f"({str(last['baseline_sha256'])[:12]}…) but CURRENT is v{baseline.version} "
                f"({baseline.content_sha256[:12]}…): possible rollback or tampering"
            )
        return None
