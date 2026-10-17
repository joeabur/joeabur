"""Orchestration used by the CLI: trust checks, baseline create/update, scans."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field

from fim.baseline import BaselineStore, LoadedBaseline
from fim.config import Config
from fim.errors import BaselineError, ConfigError, TrustError
from fim.integrity import build_report, compare, new_scan_id
from fim.models import Baseline, EventType, Report
from fim.pathutil import is_within, validate_abs_path
from fim.scanner import Scanner, ScanResult

Signer = Callable[[bytes], tuple[str, str]]


@dataclass
class Trusted:
    loaded: LoadedBaseline
    signature: str  # "verified (<key id>)" or "not configured"
    warnings: list[str] = field(default_factory=list)

    @property
    def baseline(self) -> Baseline:
        return self.loaded.baseline


def store_for(cfg: Config) -> BaselineStore:
    return BaselineStore(
        cfg.baseline.dir,
        keep_versions=cfg.baseline.keep_versions,
        max_bytes=cfg.baseline.max_baseline_bytes,
    )


def load_trusted(cfg: Config, store: BaselineStore, version: int | None = None) -> Trusted:
    """Load a baseline and refuse (TrustError) unless it passes every configured check:

    1. schema + embedded content hash (detects corruption and naive edits);
    2. detached signature, when ``baseline.public_key`` is configured (a missing signature is a
       failure, otherwise deleting the .sig would disable the check);
    3. cross-check against the audit trail (detects rollback to an older version).
    """
    store.ensure_dir(create=False)
    loaded = store.load(version)
    b = loaded.baseline
    warnings: list[str] = []
    sig_status = "not configured"
    if cfg.baseline.public_key:
        from fim import signing

        sig_path = store.sig_path_for(b.version)
        try:
            sig_text = sig_path.read_text()
        except FileNotFoundError:
            raise TrustError(
                f"{sig_path.name} is missing but a public key is configured: refusing unsigned baseline"
            ) from None
        except OSError as exc:
            raise TrustError(f"cannot read {sig_path.name}: {exc}") from exc
        kid = signing.verify_signature(cfg.baseline.public_key, loaded.raw, sig_text)
        sig_status = f"verified ({kid})"
    else:
        warnings.append("baseline is not signed: only accidental corruption is detectable")
    loaded.raw = b""  # only needed for the signature check above; free it (large estates)
    if version is None:  # the audit cross-check only describes the *current* baseline
        mismatch = store.audit_baseline_mismatch(b)
        if mismatch:
            raise TrustError(mismatch)
        if not store.read_audit():
            warnings.append("no audit trail found next to the baseline")
    if (b.roots, b.exclude, b.symlinks) != (
        cfg.scan.roots,
        cfg.scan.exclude,
        cfg.scan.symlinks,
    ):
        warnings.append(
            "scan configuration (roots/exclude/symlinks) differs from the one used to build the "
            "baseline; run an authorized 'fim baseline update' if the change is intended"
        )
    if not b.complete:
        warnings.append("this baseline was created from an INCOMPLETE scan; coverage has gaps")
    return Trusted(loaded, sig_status, warnings)


def make_signer(cfg: Config, key_path: str, passphrase: bytes | None) -> Signer:
    from fim import signing

    key_path = validate_abs_path(os.path.abspath(key_path), what="signing key path")
    bdir = os.path.realpath(cfg.baseline.dir)
    real_key = os.path.realpath(key_path)
    if is_within(real_key, bdir):
        raise TrustError("signing key must not be stored inside the baseline directory")
    for root in cfg.scan.roots:
        if is_within(real_key, os.path.realpath(root)):
            raise TrustError("signing key must not be stored inside a monitored root")
    # Fail before anything is written if the key cannot sign or does not match the trusted key.
    _, kid = signing.sign_bytes(key_path, b"", passphrase)
    if cfg.baseline.public_key:
        _, trusted_kid = signing.load_public(cfg.baseline.public_key)
        if kid != trusted_kid:
            raise TrustError(
                f"signing key {kid} does not match baseline.public_key {trusted_kid}; "
                "rotate the public key in the config first (see docs/user-guide.md)"
            )

    def signer(data: bytes) -> tuple[str, str]:
        return signing.sign_bytes(key_path, data, passphrase)

    return signer


def require_signer_if_needed(cfg: Config, signer: Signer | None) -> None:
    if cfg.baseline.public_key and signer is None:
        raise ConfigError(
            "baseline.public_key is configured, so new baselines must be signed: pass --sign-key"
        )


def scan_now(cfg: Config, roots: list[str] | None = None) -> ScanResult:
    return Scanner(cfg.scan).scan(roots)


def resolve_scope(cfg: Config, roots: list[str] | None) -> list[str] | None:
    """Validate a ``--root`` subset: every entry must lie inside a configured root."""
    if not roots:
        return None
    out = []
    for r in roots:
        p = validate_abs_path(os.path.abspath(r), what="--root")
        if not any(is_within(p, c) for c in cfg.scan.roots):
            raise ConfigError(f"--root {p} is not inside any configured scan root")
        out.append(p)
    return out


def run_scan(cfg: Config, trusted: Trusted, roots: list[str] | None = None) -> tuple[Report, ScanResult]:
    scope = resolve_scope(cfg, roots)
    result = scan_now(cfg, scope)
    scan_id = new_scan_id()
    events = compare(cfg, trusted.baseline, result, scan_id=scan_id, scope=scope or list(cfg.scan.roots))
    report = build_report(
        cfg, trusted.baseline, result, events, scan_id=scan_id, mode="partial" if scope else "full"
    )
    return report, result


def change_counts(report: Report) -> dict[str, int]:
    keys = (EventType.ADDED, EventType.MODIFIED, EventType.DELETED)
    return {k.value: report.summary.counts_by_type.get(k.value, 0) for k in keys}


def baseline_from_scan(
    store: BaselineStore,
    cfg: Config,
    result: ScanResult,
    *,
    action: str,
    reason: str,
    signer: Signer | None,
    detail: dict[str, object] | None = None,
) -> Baseline:
    if not reason.strip():
        raise BaselineError("a non-empty --reason is required for baseline changes")
    return store.commit(
        entries=result.entries,
        roots=cfg.scan.roots,
        exclude=cfg.scan.exclude,
        symlinks=cfg.scan.symlinks,
        complete=result.complete,
        issues=result.issues,
        action=action,
        reason=reason.strip(),
        signer=signer,
        audit_detail=detail,
    )
