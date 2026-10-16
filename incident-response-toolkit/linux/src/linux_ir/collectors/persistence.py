"""Read-only persistence inspection: systemd, cron, shell startup, rc.local, SSH, kernel modules.

All discovered content is untrusted and is parsed statically; nothing is executed.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from ..context import Context
from ..models import CollectorResult
from ..parsers import cron as cronp
from ..parsers import systemd_unit as su
from ..utils.paths import file_metadata

NAME = "persistence"
DESCRIPTION = "systemd units/timers/drop-ins, cron, shell startup, rc.local, init.d, SSH keys metadata, kernel modules"
PRIVILEGE_NOTE = "Most locations are world-readable; user crontabs, /root files and at jobs need root."

MAX_FILE_BYTES = 262_144
MAX_UNITS = 3000
SYSTEMD_BASIC = ["/etc/systemd/system", "/run/systemd/system"]
SYSTEMD_DEEP = ["/usr/lib/systemd/system", "/lib/systemd/system"]
SYSTEMD_USER = ["/etc/systemd/user"]
CRON_DIRS = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]
CRON_SPOOLS = ["/var/spool/cron/crontabs", "/var/spool/cron"]
AT_SPOOLS = ["/var/spool/cron/atjobs", "/var/spool/at"]
SYSTEM_SHELL = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/environment", "/etc/zsh/zshrc"]
USER_SHELL = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout", ".zshrc", ".zprofile"]
SSHD_KEYS = {
    "permitrootlogin",
    "passwordauthentication",
    "pubkeyauthentication",
    "permitemptypasswords",
    "authorizedkeysfile",
    "authorizedkeyscommand",
    "forcecommand",
    "port",
    "permituserenvironment",
}
_STARTUP_ASSIGN = re.compile(r"^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*=")


def plan(ctx: Context) -> list[str]:
    dirs = SYSTEMD_BASIC + (SYSTEMD_DEEP if ctx.deep else [])
    return [
        "parse systemd units/timers/drop-ins in: " + ", ".join(dirs + SYSTEMD_USER + ["~/.config/systemd/user"]),
        "run: systemctl list-unit-files / list-timers (read-only, bounded)",
        "parse /etc/crontab, " + ", ".join(CRON_DIRS) + " and list crontab/at spool metadata",
        "metadata+commands of shell startup files for the current user and /etc",
        "inspect /etc/rc.local, /etc/init.d (metadata), selected sshd_config keys, authorized_keys fingerprints",
        "read /proc/modules (no module loading)",
        "NEVER read private keys, shadow files, or execute discovered content",
    ]


def _read_text(ctx: Context, res: CollectorResult, p: Path, disp: str) -> str | None:
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None
    except PermissionError:
        res.error(disp, "permission_denied", "cannot read file")
        return None
    except OSError as exc:
        res.error(disp, "other", str(exc))
        return None
    if len(data) > MAX_FILE_BYTES:
        res.error(disp, "truncated", f"file larger than {MAX_FILE_BYTES} bytes; only the start was parsed")
        data = data[:MAX_FILE_BYTES]
    return data.decode("utf-8", errors="replace")


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
    if hash_it and meta["type"] == "file":
        digest, err = ctx.hash_file(p)
        meta["sha256"] = digest
        if err:
            meta["collection_status"] = "partial"
            meta["hash_error"] = err
            res.error(disp, "permission_denied" if err == "permission denied" else "other", f"hash: {err}")
    return meta


def _exec_info(ctx: Context, binary: str | None) -> dict[str, Any]:
    if not binary:
        return {"exec_binary": None, "exec_exists": None}
    if not binary.startswith("/"):
        return {"exec_binary": binary, "exec_exists": None}  # resolved via PATH / specifiers: unknown
    p = ctx.path(binary)
    try:
        exists = os.path.lexists(p)
    except OSError:
        exists = False
    return {"exec_binary": binary, "exec_exists": exists}


def _list_dir(ctx: Context, res: CollectorResult, d: str) -> list[Path]:
    p = ctx.path(d)
    try:
        names = sorted(os.listdir(p))
    except FileNotFoundError:
        return []
    except NotADirectoryError:
        return []
    except PermissionError:
        res.error(d, "permission_denied", "cannot list directory")
        return []
    except OSError as exc:
        res.error(d, "other", str(exc))
        return []
    res.sources.append(d)
    return [p / n for n in names]


def _collect_systemd(ctx: Context, res: CollectorResult, dirs: list[str], scope: str) -> None:
    for d in dirs:
        entries = _list_dir(ctx, res, d)
        for e in entries:
            if len(res.records) >= ctx.limit("max_records_per_artifact"):
                res.error(d, "truncated", "record cap reached")
                return
            name = e.name
            if e.is_dir() and not e.is_symlink() and name.endswith((".wants", ".requires")):
                for link in _list_dir(ctx, res, ctx.display(e)):
                    res.records.append(
                        {
                            "kind": "systemd_enablement",
                            "scope": scope,
                            "target_unit": name,
                            "unit": link.name,
                            "path": ctx.display(link),
                            "symlink_target": os.readlink(link) if link.is_symlink() else None,
                        }
                    )
                continue
            if e.is_dir() and not e.is_symlink() and name.endswith(".d"):
                for conf in _list_dir(ctx, res, ctx.display(e)):
                    if not conf.name.endswith(".conf"):
                        continue
                    rec = _artifact(ctx, res, conf, "systemd_dropin")
                    if rec is None:
                        continue
                    text = _read_text(ctx, res, conf, rec["path"])
                    if text is not None:
                        summ = su.summarize(su.parse_unit(text))
                        rec.update(
                            unit=name[:-2],
                            scope=scope,
                            **{k: summ[k] for k in ("exec_start", "user")},
                            **_exec_info(ctx, summ["exec_binary"]),
                        )
                    res.records.append(rec)
                continue
            if not name.endswith((".service", ".timer", ".socket", ".path")):
                continue
            rec = _artifact(ctx, res, e, "systemd_unit")
            if rec is None:
                continue
            rec.update(unit=name, unit_type=name.rsplit(".", 1)[1], scope=scope)
            if rec["type"] == "symlink":
                rec["masked"] = rec.get("symlink_target") == "/dev/null"
            elif rec["type"] == "file":
                text = _read_text(ctx, res, e, rec["path"])
                if text is None:
                    rec["collection_status"] = "partial"
                else:
                    summ = su.summarize(su.parse_unit(text))
                    rec.update(summ)
                    rec.update(_exec_info(ctx, summ["exec_binary"]))
                    if rec["exec_exists"]:
                        digest, _ = ctx.hash_file(ctx.path(summ["exec_binary"]))
                        rec["exec_sha256"] = digest
            res.records.append(rec)


def _collect_cron(ctx: Context, res: CollectorResult) -> None:
    def parse_file(p: Path, system: bool, kind: str) -> None:
        rec = _artifact(ctx, res, p, kind)
        if rec is None or rec["type"] != "file":
            return
        text = _read_text(ctx, res, p, rec["path"])
        if text is None:
            return
        for entry in cronp.parse_crontab(text, system):
            entry = dict(entry)
            if "command" in entry:
                entry["command"] = ctx.redactor.text(entry["command"])[:500]
            if entry.get("parse_error"):
                res.error(rec["path"], "parse_error", f"line {entry['line_no']} not parseable")
                continue
            entry.update(
                kind="cron_entry",
                path=rec["path"],
                owner=rec["owner"],
                mode=rec["mode"],
                file_sha256=rec.get("sha256"),
                mtime=rec["mtime"],
                **_exec_info_cron(ctx, entry),
            )
            res.records.append(entry)

    parse_file(ctx.path("/etc/crontab"), True, "cron_file")
    for d in CRON_DIRS:
        for p in _list_dir(ctx, res, d):
            if d == "/etc/cron.d":
                parse_file(p, True, "cron_file")
            else:
                rec = _artifact(ctx, res, p, "cron_script")
                if rec:
                    res.records.append(rec)
    for d in CRON_SPOOLS:
        for p in _list_dir(ctx, res, d):
            if p.is_dir():
                continue
            rec = _artifact(ctx, res, p, "cron_spool_file", hash_it=False)
            if rec:
                res.records.append(rec)
                parse_file(p, False, "cron_user_file") if os.access(p, os.R_OK) else None
    for d in AT_SPOOLS:
        for p in _list_dir(ctx, res, d):
            rec = _artifact(ctx, res, p, "at_job", hash_it=False)  # content intentionally not read
            if rec:
                res.records.append(rec)


def _exec_info_cron(ctx: Context, entry: dict[str, Any]) -> dict[str, Any]:
    info = _exec_info(ctx, entry.get("exec_binary"))
    info.pop("exec_binary", None)
    return info


def _startup_commands(text: str, ctx: Context) -> list[str]:
    cmds = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or _STARTUP_ASSIGN.match(s):
            continue
        cmds.append(ctx.redactor.text(s)[:300])
        if len(cmds) >= 200:
            break
    return cmds


def _collect_startup(ctx: Context, res: CollectorResult) -> None:
    files = [ctx.path(p) for p in SYSTEM_SHELL] + [ctx.user_home / n for n in USER_SHELL]
    files += _list_dir(ctx, res, "/etc/profile.d")
    for p in files:
        rec = _artifact(ctx, res, p, "shell_startup")
        if rec is None or rec["type"] != "file":
            continue
        text = _read_text(ctx, res, p, rec["path"])
        if text is not None:
            rec["commands"] = _startup_commands(text, ctx)
        res.records.append(rec)
    rc = ctx.path("/etc/rc.local")
    rec = _artifact(ctx, res, rc, "rc_local")
    if rec and rec["type"] == "file":
        text = _read_text(ctx, res, rc, rec["path"])
        rec["commands"] = [c for c in _startup_commands(text or "", ctx) if not c.startswith("exit ")]
        res.records.append(rec)
    for p in _list_dir(ctx, res, "/etc/init.d"):
        rec = _artifact(ctx, res, p, "init_script")
        if rec:
            res.records.append(rec)


def _collect_ssh(ctx: Context, res: CollectorResult) -> None:
    cfg = ctx.path("/etc/ssh/sshd_config")
    rec = _artifact(ctx, res, cfg, "sshd_config")
    if rec and rec["type"] == "file":
        text = _read_text(ctx, res, cfg, rec["path"]) or ""
        sel: dict[str, str] = {}
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in SSHD_KEYS:
                sel.setdefault(parts[0].lower(), parts[1].strip()[:200])
        rec["settings"] = sel
        res.records.append(rec)
    homes = [ctx.user_home]
    root_home = ctx.path("/root")
    if root_home != ctx.user_home:
        homes.append(root_home)
    for home in homes:
        ak = home / ".ssh" / "authorized_keys"
        rec = _artifact(ctx, res, ak, "authorized_keys", hash_it=False)
        if rec is None or rec["type"] != "file":
            continue
        text = _read_text(ctx, res, ak, rec["path"]) or ""
        keys = []
        for ln in text.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            m = re.search(r"(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)\s+([A-Za-z0-9+/=]+)", s)
            if not m:
                continue
            opts = s[: m.start()].strip()
            try:
                fp = "SHA256:" + base64.b64encode(
                    hashlib.sha256(base64.b64decode(m.group(2))).digest()
                ).decode().rstrip("=")
            except ValueError:
                fp = None
            keys.append(
                {
                    "type": m.group(1),
                    "fingerprint": fp,
                    "has_command_option": "command=" in opts,
                    "has_from_option": "from=" in opts,
                }
            )
        rec["keys"] = keys
        rec["key_count"] = len(keys)
        rec["has_command_option"] = any(k["has_command_option"] for k in keys)
        res.records.append(rec)


def _collect_modules(ctx: Context, res: CollectorResult) -> None:
    try:
        text = ctx.path("/proc/modules").read_text(errors="replace")
    except OSError as exc:
        res.error("/proc/modules", "not_found" if isinstance(exc, FileNotFoundError) else "other", str(exc))
        return
    res.sources.append("/proc/modules")
    for line in text.splitlines()[:2000]:
        f = line.split()
        if len(f) >= 3 and f[1].isdigit():
            res.records.append(
                {"kind": "kernel_module", "name": f[0], "size": int(f[1]), "used_by": f[3] if len(f) > 3 else None}
            )


def _systemctl_state(ctx: Context, res: CollectorResult) -> None:
    for argv, kind in (
        (["systemctl", "list-unit-files", "--no-pager", "--no-legend"], "unit_file_state"),
        (["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"], "timer_state"),
    ):
        r = ctx.run(argv)
        if r.error_kind:
            res.error(" ".join(argv), r.error_kind, r.error or "systemctl failed")
            continue
        res.sources.append(" ".join(argv))
        for line in r.stdout.splitlines()[:3000]:
            f = line.split()
            if kind == "unit_file_state" and len(f) >= 2:
                res.records.append({"kind": kind, "unit": f[0], "state": f[1]})
            elif kind == "timer_state" and f:
                units = [t for t in f if t.endswith(".timer")]
                if units:
                    res.records.append({"kind": kind, "unit": units[0], "raw": line.strip()[:200]})


def collect(ctx: Context) -> CollectorResult:
    res = CollectorResult(NAME)
    from ..platform_info import detect_init

    init = detect_init(ctx.root)
    if init["systemd"]:
        _collect_systemd(ctx, res, SYSTEMD_BASIC + (SYSTEMD_DEEP if ctx.deep else []), "system")
        _collect_systemd(ctx, res, SYSTEMD_USER + [str(ctx.user_home / ".config/systemd/user")], "user")
        if ctx.root == type(ctx.root)("/"):
            _systemctl_state(ctx, res)
    else:
        res.notes.append(
            f"init system is {init['name']!r}, not systemd: systemd collection skipped; "
            "only cron/startup/SSH/init.d/kernel-module sources were examined."
        )
    _collect_cron(ctx, res)
    _collect_startup(ctx, res)
    _collect_ssh(ctx, res)
    _collect_modules(ctx, res)
    res.finalize()
    return res
