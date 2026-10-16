"""Selected file metadata/hashes and executables in world-writable staging directories."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..context import Context
from ..models import CollectorResult
from ..utils.paths import file_metadata

NAME = "files"
DESCRIPTION = "Metadata+SHA-256 of selected config files; executables in /private/tmp, /private/var/tmp, /Users/Shared"
PRIVILEGE_NOTE = "Only readable files. Keychains, private keys and home directories are never collected."
HASHED = [
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/sudo",
    "/etc/paths",
    "/etc/zshrc",
    "/etc/profile",
    "/Library/Preferences/com.apple.alf.plist",
]
METADATA_ONLY = ["/etc/sudoers", "/etc/master.passwd"]
STAGING = ["/private/tmp", "/private/var/tmp", "/Users/Shared"]
MAX_DEPTH = 3
MACHO_MAGIC = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}


def plan(ctx: Context) -> list[str]:
    return [
        "metadata + SHA-256: " + ", ".join(HASHED),
        "metadata only (contents never read): " + ", ".join(METADATA_ONLY),
        f"bounded walk (depth {MAX_DEPTH}, ≤{ctx.limit('max_walk_entries')} entries, symlinks not followed): "
        + ", ".join(STAGING),
    ]


def _is_macho_or_script(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head in MACHO_MAGIC or head[:2] == b"#!"


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    for path, hashed in [(p, True) for p in HASHED] + [(p, False) for p in METADATA_ONLY]:
        p = ctx.path(path)
        try:
            meta = file_metadata(p, path)
        except FileNotFoundError:
            continue
        except PermissionError:
            res.error(path, "permission_denied", "cannot stat")
            continue
        meta["kind"] = "sensitive_file"
        if hashed and meta["type"] == "file":
            digest, err = ctx.hash_file(p)
            meta["sha256"] = digest
            if err:
                res.error(path, "permission_denied" if err == "permission denied" else "other", f"hash: {err}")
        res.records.append(meta)
        res.sources.append(path)
    cap = ctx.limit("max_walk_entries")
    seen = 0
    for base in STAGING:
        root = ctx.path(base)
        if not root.is_dir():
            continue
        res.sources.append(base)
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(
            root,
            followlinks=False,
            onerror=lambda e: res.error(str(e.filename), "permission_denied", "cannot list (permissions or TCC)"),
        ):
            if len(Path(dirpath).parts) - base_depth >= MAX_DEPTH:
                dirnames[:] = []
            for fn in filenames:
                seen += 1
                if seen > cap:
                    res.error(base, "truncated", f"walk stopped after {cap} entries; listing is incomplete")
                    res.finalize()
                    return res
                fp = Path(dirpath) / fn
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                executable = bool(st.st_mode & 0o111)
                if not (executable or _is_macho_or_script(fp)):
                    continue
                meta = file_metadata(fp, ctx.display(fp))
                digest, err = ctx.hash_file(fp)
                meta.update(kind="writable_dir_exec", sha256=digest, executable_bit=executable, staging_dir=base)
                if err:
                    meta["hash_error"] = err
                res.records.append(meta)
    res.finalize()
    return res
