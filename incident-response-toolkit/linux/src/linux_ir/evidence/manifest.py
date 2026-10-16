"""Evidence directory layout, manifest generation, loading and integrity verification."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .. import TOOL_NAME, __version__
from ..models import CollectorResult
from ..utils.paths import UnsafePathError, safe_join, sha256_bytes, sha256_file, write_exclusive

MANIFEST_NAME = "manifest.json"
SCHEMA_VERSION = 1
LIMITATIONS = [
    "Live-response collection is not a forensic disk image; volatile state changed while collecting.",
    "The manifest is stored beside the evidence: it detects accidental or naive changes but is not independently "
    "tamper-proof. Store a copy of the manifest SHA-256 (or a signed manifest) separately.",
    "Timestamps are those reported by the host clock, normalised to UTC; clock accuracy is not verified.",
    "Inaccessible or unexamined sources are listed in the coverage section; absence of data is not "
    "absence of activity.",
]


class EvidenceError(Exception):
    pass


def artifact_document(res: CollectorResult, collected_at: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact": res.name,
        "collected_at": collected_at,
        "status": res.status,
        "sources": res.sources,
        "notes": res.notes,
        "errors": [e.to_dict() for e in res.errors],
        "records": res.records,
    }


def write_artifact(evdir: Path, doc: dict[str, Any]) -> Path:
    rel = f"artifacts/{doc['artifact']}.json"
    (evdir / "artifacts").mkdir(mode=0o700, exist_ok=True)
    target = safe_join(evdir, rel)
    write_exclusive(target, json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n")
    return target


def _iter_files(evdir: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(evdir, followlinks=False):
        dirnames.sort()
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.name == MANIFEST_NAME and p.parent == evdir:
                continue
            out.append(p)
    return out


def build_manifest(evdir: Path, meta: dict[str, Any]) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for p in _iter_files(evdir):
        if p.is_symlink():
            raise EvidenceError(f"refusing to seal symlink inside evidence directory: {p}")
        files.append({"path": p.relative_to(evdir).as_posix(), "size": p.stat().st_size, "sha256": sha256_file(p)})
    arts = []
    coverage: dict[str, list[str]] = {s: [] for s in ("ok", "partial", "failed", "skipped", "unavailable")}
    for f in files:
        if f["path"].startswith("artifacts/") and f["path"].endswith(".json"):
            doc = json.loads((evdir / f["path"]).read_text())
            arts.append(
                {
                    "name": doc["artifact"],
                    "path": f["path"],
                    "status": doc["status"],
                    "record_count": len(doc["records"]),
                    "sources": doc["sources"],
                    "errors": doc["errors"],
                    "notes": doc["notes"],
                }
            )
            coverage.setdefault(doc["status"], []).append(doc["artifact"])
    for name, why in meta.pop("not_run", {}).items():
        coverage["skipped"].append(name)
        arts.append(
            {
                "name": name,
                "path": None,
                "status": "skipped",
                "record_count": 0,
                "sources": [],
                "errors": [],
                "notes": [why],
            }
        )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        **meta,
        "artifacts": arts,
        "coverage": coverage,
        "files": files,
        "limitations": LIMITATIONS,
    }
    return manifest


def write_manifest(evdir: Path, manifest: dict[str, Any]) -> tuple[Path, str]:
    data = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    path = evdir / MANIFEST_NAME
    write_exclusive(path, data)
    return path, sha256_bytes(data)


def verify_manifest(evdir: Path) -> dict[str, Any]:
    """Recompute hashes and compare with the manifest. Never modifies the evidence."""
    mpath = evdir / MANIFEST_NAME
    result: dict[str, Any] = {
        "ok": False,
        "manifest_sha256": None,
        "verified": 0,
        "modified": [],
        "missing": [],
        "unexpected": [],
        "unsafe": [],
        "error": None,
    }
    try:
        raw = mpath.read_bytes()
    except FileNotFoundError:
        result["error"] = f"{MANIFEST_NAME} not found in {evdir}"
        return result
    except OSError as exc:
        result["error"] = str(exc)
        return result
    result["manifest_sha256"] = sha256_bytes(raw)
    try:
        manifest = json.loads(raw)
        entries = manifest["files"]
        if not isinstance(entries, list):
            raise ValueError("files is not a list")
    except (ValueError, KeyError, TypeError):
        result["error"] = "manifest is not valid JSON or lacks a 'files' list"
        return result
    listed = set()
    for e in entries:
        try:
            rel = e["path"]
            p = safe_join(evdir, rel)
        except (UnsafePathError, KeyError, TypeError) as exc:
            result["unsafe"].append(str(exc))
            continue
        listed.add(rel)
        if p.is_symlink():
            result["unsafe"].append(f"{rel}: is a symlink")
            continue
        if not p.exists():
            result["missing"].append(rel)
            continue
        try:
            actual = sha256_file(p)
        except OSError as exc:
            result["modified"].append({"path": rel, "reason": f"unreadable: {exc}"})
            continue
        if actual != e.get("sha256") or p.stat().st_size != e.get("size"):
            result["modified"].append({"path": rel, "expected": e.get("sha256"), "actual": actual})
        else:
            result["verified"] += 1
    for p in _iter_files(evdir):
        rel = p.relative_to(evdir).as_posix()
        if rel not in listed:
            result["unexpected"].append(rel)
    result["ok"] = not (result["modified"] or result["missing"] or result["unexpected"] or result["unsafe"])
    return result


def load_evidence(evdir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    """Load artifact documents (and the manifest if present). Malformed files raise EvidenceError."""
    adir = evdir / "artifacts"
    if not adir.is_dir():
        raise EvidenceError(f"{evdir} does not look like an evidence directory (no artifacts/ folder)")
    arts: dict[str, dict[str, Any]] = {}
    for p in sorted(adir.glob("*.json")):
        if p.is_symlink():
            raise EvidenceError(f"refusing to follow symlink: {p}")
        try:
            doc = json.loads(p.read_text())
            if not isinstance(doc.get("records"), list) or "artifact" not in doc:
                raise ValueError("missing 'artifact' or 'records'")
        except (ValueError, OSError) as exc:
            raise EvidenceError(f"malformed artifact file {p.name}: {exc}") from exc
        arts[doc["artifact"]] = doc
    manifest = None
    mp = evdir / MANIFEST_NAME
    if mp.is_file():
        try:
            manifest = json.loads(mp.read_text())
        except ValueError as exc:
            raise EvidenceError(f"manifest.json is not valid JSON: {exc}") from exc
    return arts, manifest
