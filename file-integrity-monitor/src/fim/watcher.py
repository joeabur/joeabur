"""Optional real-time monitoring on top of ``watchdog`` (inotify on Linux).

Honest limits (also in docs/security-and-limitations.md):

* inotify can drop events (queue overflow), cannot watch paths that do not exist yet, and a file
  created inside a brand-new directory can be missed in the instant before a watch is added.
  Therefore the watcher *also* runs a periodic full scan (``watch.full_scan_interval_seconds``),
  which is the authoritative check. Events are a latency optimisation, not a guarantee.
* Event delivery is best-effort per path: a changed path is re-inspected against the baseline
  after a debounce window; the baseline itself is never modified by the watcher.
* If ``watchdog`` is not installed, ``fim watch`` fails with instructions and the documented
  fallback is a periodic ``fim scan`` (systemd timer or cron).
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import Any

from fim.config import Config
from fim.errors import DependencyError
from fim.integrity import build_report, compare, new_scan_id
from fim.models import Baseline, Report
from fim.pathutil import is_within, matches_any
from fim.scanner import Scanner


class PathProcessor:
    """Library-independent core: given a set of dirty paths, produce a partial-scan report.

    Unit-testable without watchdog or inotify.
    """

    def __init__(self, cfg: Config, baseline: Baseline) -> None:
        self.cfg = cfg
        self.baseline = baseline
        self._seen: set[tuple[str, str, str]] = set()

    def relevant(self, path: str) -> bool:
        if not any(is_within(path, r) for r in self.cfg.scan.roots):
            return False
        return not (self.cfg.scan.exclude and matches_any(path, self.cfg.scan.exclude))

    def process(self, paths: set[str]) -> Report | None:
        """Re-inspect ``paths``; return a report containing only events not yet reported."""
        dirty = sorted({p for p in paths if self.relevant(p)})
        if not dirty:
            return None
        scanner = Scanner(self.cfg.scan)
        scan_id = new_scan_id()
        merged = scanner.scan([])  # empty result with fresh timestamps
        merged.roots = dirty
        for p in dirty:
            if not os.path.lexists(p):
                continue  # deleted: compare() reports it from the baseline
            res = scanner.scan([p])
            merged.entries.update(res.entries)
            merged.issues.extend(res.issues)
            merged.entries_scanned += res.entries_scanned
            merged.bytes_hashed += res.bytes_hashed
            merged.aborted = merged.aborted or res.aborted
            merged.finished_at = res.finished_at
        events = compare(self.cfg, self.baseline, merged, scan_id=scan_id, scope=dirty)
        fresh = []
        for e in events:
            key = (
                e.path,
                e.event_type.value,
                (e.after.sha256 or e.after.mode) if e.after else "gone",
            )
            if key not in self._seen:
                self._seen.add(key)
                fresh.append(e)
        if not fresh and merged.complete:
            return None
        return build_report(self.cfg, self.baseline, merged, fresh, scan_id=scan_id, mode="partial")


def _load_watchdog() -> tuple[Any, Any]:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        raise DependencyError(
            "filesystem watching needs 'watchdog': pip install 'fim-tool[watch]'. "
            "Fallback: run 'fim scan' periodically (see systemd/fim-scan.timer)."
        ) from exc
    return Observer, FileSystemEventHandler


class Watcher:
    def __init__(
        self,
        cfg: Config,
        baseline: Baseline,
        on_report: Callable[[Report], None],
        on_full_scan: Callable[[], None] | None = None,
    ) -> None:
        self.cfg = cfg
        self.processor = PathProcessor(cfg, baseline)
        self.on_report = on_report
        self.on_full_scan = on_full_scan
        self._dirty: set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.observer: Any = None

    # called from watchdog's thread
    def _mark(self, *paths: str | bytes | None) -> None:
        with self._lock:
            for p in paths:
                if p:
                    self._dirty.add(os.fsdecode(p))

    def start(self) -> None:
        observer_cls, handler_base = _load_watchdog()
        outer = self

        class Handler(handler_base):  # type: ignore[misc,valid-type]
            def on_any_event(self, event: Any) -> None:
                if event.event_type in ("opened", "closed_no_write"):
                    return  # read-only access is not a change (and our own scan opens files)
                if event.is_directory and event.event_type == "modified":
                    return  # a directory's mtime churns on every child change
                outer._mark(event.src_path, getattr(event, "dest_path", None))

        self.observer = observer_cls()
        for root in self.cfg.scan.roots:
            if os.path.isdir(root):
                self.observer.schedule(Handler(), root, recursive=True)
        self.observer.start()

    def stop(self) -> None:
        self._stop.set()
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)

    def drain(self) -> Report | None:
        with self._lock:
            dirty, self._dirty = self._dirty, set()
        return self.processor.process(dirty) if dirty else None

    def run(self, *, max_seconds: float | None = None) -> None:
        """Blocking loop. ``max_seconds`` exists for tests."""
        self.start()
        started = time.monotonic()
        last_full = started
        try:
            while not self._stop.is_set():
                time.sleep(self.cfg.watch.debounce_seconds)
                report = self.drain()
                if report is not None:
                    self.on_report(report)
                interval = self.cfg.watch.full_scan_interval_seconds
                if interval and self.on_full_scan and time.monotonic() - last_full >= interval:
                    self.on_full_scan()
                    last_full = time.monotonic()
                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                    break
        finally:
            self.stop()
