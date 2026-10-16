"""Read-only inspection of macOS persistence locations. All content is untrusted and never executed.

Covers launchd agents/daemons, user cron, periodic scripts, legacy StartupItems/emond rules, login-item
artifact metadata and shell startup files. Modern protections (SIP, TCC, the Background Task Management database)
mean some mechanisms cannot be enumerated without privileges; those gaps are reported, not bypassed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers import cron as cronp
from ..parsers.launchd import PlistError, parse_plist, summarize_launchd
from ..parsers.system import parse_codesign
from ..utils.paths import file_metadata

NAME = "persistence"
DESCRIPTION = "LaunchAgents/Daemons, cron, periodic scripts, StartupItems/emond, login-item artifacts, shell startup"
PRIVILEGE_NOTE = (
    "/Library and ~/Library launch items are readable unprivileged. /var/at/tabs (cron), the Background Task "
    "Management database and some /System paths require root and/or Full Disk Access: reported as inaccessible."
)
MAX_FILE_BYTES = 262_144
LAUNCH_DIRS_BASIC = ["/Library/LaunchDaemons", "/Library/LaunchAgents"]
LAUNCH_DIRS_DEEP = ["/System/Library/LaunchDaemons", "/System/Library/LaunchAgents"]
USER_LAUNCH = "Library/LaunchAgents"
LEGACY_DIRS = {
    "/Library/StartupItems": "startup_item",
    "/etc/emond.d/rules": "emond_rule",
    "/etc/periodic/daily": "periodic_script",
    "/etc/periodic/weekly": "periodic_script",
    "/etc/periodic/monthly": "periodic_script",
}
LOGIN_ITEM_PATHS = [
    "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
    "Library/Preferences/com.apple.loginitems.plist",
]
SYSTEM_SHELL = ["/etc/profile", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/bashrc"]
USER_SHELL = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"]
_ASSIGN = re.compile(r"^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*=")
APPLE_PREFIXES = ("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/Applications/", "/opt/homebrew/")


def plan(ctx: Context) -> list[str]:
    dirs = LAUNCH_DIRS_BASIC + ["~/" + USER_LAUNCH] + (LAUNCH_DIRS_DEEP if ctx.deep else [])
    steps = [
        "parse launchd plists in: " + ", ".join(dirs),
        "run: crontab -l (lists the current user's crontab; read-only)",
        "list legacy locations: " + ", ".join(LEGACY_DIRS),
        "metadata of login-item artifacts in the current user's Library (contents not parsed)",
        "shell startup files: /etc/{profile,zshrc,...} and ~/.zshrc, ~/.zprofile, ~/.bash_profile ...",
    ]
    if ctx.deep:
        steps.append(
            f"codesign -dv (read-only signature inspection) for up to {ctx.limit('max_codesign_checks')} "
            "launch-item executables; signing is context, not a verdict"
        )
    steps.append("NEVER executes discovered programs, scripts or plist commands")
    return steps


def _read(ctx: Context, res: CollectorResult, p: Path, disp: str) -> bytes | None:
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None
    except PermissionError:
        res.error(disp, "permission_denied", "cannot read (permissions, SIP or TCC)")
        return None
    except OSError as exc:
        res.error(disp, "other", str(exc))
        return None
    if len(data) > MAX_FILE_BYTES:
        res.error(disp, "truncated", f"file larger than {MAX_FILE_BYTES} bytes; only the start was parsed")
        data = data[:MAX_FILE_BYTES]
    return data


def _artifact(ctx: Context, res: CollectorResult, p: Path, kind: str, hash_it: bool = True) -> dict[str, Any] | None:
    disp = ctx.display(p)
    try:
        meta = file_metadata(p, disp)
    except FileNotFoundError:
        return None
    except PermissionError:
        res.error(disp, "permission_denied", "cannot stat")
        return None
    except OSError as exc:
        res.error(disp, "other", str(exc))
        return None
    meta["kind"] = kind
    meta["collection_status"] = "ok"
    meta["group_writable"] = bool(int(meta["mode"], 8) & 0o020)
    if hash_it and meta["type"] == "file":
        digest, err = ctx.hash_file(p)
        meta["sha256"] = digest
        if err:
            meta["collection_status"] = "partial"
            meta["hash_error"] = err
            res.error(disp, "permission_denied" if err == "permission denied" else "other", f"hash: {err}")
    return meta


def _list_dir(ctx: Context, res: CollectorResult, p: Path) -> list[Path]:
    disp = ctx.display(p)
    try:
        names = sorted(os.listdir(p))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except PermissionError:
        res.error(disp, "permission_denied", "cannot list directory (permissions, SIP or TCC)")
        return []
    except OSError as exc:
        res.error(disp, "other", str(exc))
        return []
    res.sources.append(disp)
    return [p / n for n in names]


def _collect_launchd(ctx: Context, res: CollectorResult) -> None:
    dirs = [(ctx.path(d), "system") for d in LAUNCH_DIRS_BASIC]
    dirs.append((ctx.user_home / USER_LAUNCH, "user"))
    if ctx.deep:
        dirs += [(ctx.path(d), "apple") for d in LAUNCH_DIRS_DEEP]
    codesign_budget = ctx.limit("max_codesign_checks") if ctx.deep else 0
    checked: dict[str, dict[str, Any]] = {}
    for d, scope in dirs:
        for p in _list_dir(ctx, res, d):
            if not p.name.endswith(".plist"):
                if p.name != ".DS_Store":
                    rec = _artifact(ctx, res, p, "launchd_unexpected_file")
                    if rec:
                        res.records.append(rec)
                continue
            rec = _artifact(ctx, res, p, "launchd_plist")
            if rec is None:
                continue
            rec["scope"] = scope
            data = _read(ctx, res, p, rec["path"]) if rec["type"] == "file" else None
            if data is not None:
                try:
                    summ = summarize_launchd(parse_plist(data))
                except PlistError as exc:
                    res.error(rec["path"], "parse_error", str(exc))
                    rec["collection_status"] = "partial"
                else:
                    summ["program_arguments"] = [ctx.redactor.text(a) for a in summ["program_arguments"]]
                    rec.update(summ)
                    binary = summ["exec_binary"]
                    rec["exec_exists"] = (
                        os.path.lexists(ctx.path(binary)) if binary and binary.startswith("/") else None
                    )
                    if rec["exec_exists"]:
                        rec["exec_sha256"], _ = ctx.hash_file(ctx.path(binary))
                        if codesign_budget > 0 and binary not in checked:
                            codesign_budget -= 1
                            cs = ctx.run(["codesign", "-dv", "--verbose=2", binary])
                            if cs.error_kind:
                                checked[binary] = {"signed": None}
                                res.error(f"codesign {binary}", cs.error_kind, cs.error or "codesign failed")
                            else:
                                checked[binary] = parse_codesign(cs.stderr, cs.returncode)
                        if binary in checked:
                            rec["signing"] = checked[binary]
                            rec["signed"] = checked[binary].get("signed")
                    rec["standard_location"] = bool(binary and binary.startswith(APPLE_PREFIXES))
            res.records.append(rec)


def _collect_cron(ctx: Context, res: CollectorResult) -> None:
    r = ctx.run(["crontab", "-l"])
    if r.error_kind:
        res.error("crontab -l", r.error_kind, r.error or "crontab failed")
        return
    res.sources.append("crontab -l")
    if r.returncode != 0:
        if "no crontab" not in r.stderr.lower():
            res.error("crontab -l", "other", r.stderr.strip()[:200] or f"exit {r.returncode}")
        return
    for entry in cronp.parse_crontab(r.stdout, system=False):
        if entry.get("parse_error"):
            res.error("crontab -l", "parse_error", f"line {entry['line_no']} not parseable")
            continue
        entry["command"] = ctx.redactor.text(entry["command"])[:500]
        binary = entry.get("exec_binary")
        res.records.append(
            {
                **entry,
                "kind": "cron_entry",
                "path": "crontab -l (current user)",
                "exec_exists": os.path.lexists(ctx.path(binary)) if binary and binary.startswith("/") else None,
            }
        )
    res.notes.append("only the current user's crontab was listed; other users' crontabs (/var/at/tabs) need root")


def _commands(text: str, ctx: Context) -> list[str]:
    cmds: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or _ASSIGN.match(s):
            continue
        cmds.append(ctx.redactor.text(s)[:300])
        if len(cmds) >= 200:
            break
    return cmds


def _collect_misc(ctx: Context, res: CollectorResult) -> None:
    for d, kind in LEGACY_DIRS.items():
        for p in _list_dir(ctx, res, ctx.path(d)):
            rec = _artifact(ctx, res, p, kind)
            if rec:
                res.records.append(rec)
    for rel in LOGIN_ITEM_PATHS:
        rec = _artifact(ctx, res, ctx.user_home / rel, "login_item_artifact", hash_it=True)
        if rec:
            res.records.append(rec)
    res.notes.append(
        "Login Items / Background Task Management entries are stored in a protected database "
        "(`sfltool dumpbtm` needs root); only artifact file metadata is recorded."
    )
    files = [ctx.path(p) for p in SYSTEM_SHELL] + [ctx.user_home / n for n in USER_SHELL]
    for p in files:
        rec = _artifact(ctx, res, p, "shell_startup")
        if rec is None or rec["type"] != "file":
            continue
        data = _read(ctx, res, p, rec["path"])
        if data is not None:
            rec["commands"] = _commands(data.decode("utf-8", errors="replace"), ctx)
        res.records.append(rec)
    for p in _list_dir(ctx, res, ctx.path("/etc/paths.d")):
        rec = _artifact(ctx, res, p, "paths_d")
        if rec:
            res.records.append(rec)


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    _collect_launchd(ctx, res)
    _collect_cron(ctx, res)
    _collect_misc(ctx, res)
    res.finalize()
    return res
