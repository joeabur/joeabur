"""Exports: JSON, CSV, human text, and syslog (RFC 5424 / CEF) formatting and delivery."""

from __future__ import annotations

import csv
import errno
import io
import socket
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from fim.baseline import atomic_write
from fim.config import SyslogConfig
from fim.errors import FimError
from fim.models import Event, Report, Severity

CSV_EVENT_COLUMNS = [
    "timestamp", "scan_id", "severity", "event_type", "path", "rule", "baseline_version",
    "changed_fields", "old_sha256", "new_sha256", "old_size", "new_size", "old_mode", "new_mode",
    "old_uid", "new_uid", "old_gid", "new_gid", "risk_flags",
]  # fmt: skip
CSV_ISSUE_COLUMNS = ["scan_id", "kind", "path", "detail"]
_CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


# ---------------------------------------------------------------- files
def write_output(path: str | Path, data: bytes, *, overwrite: bool = False) -> None:
    """Write an export with mode 0600; never silently replace an existing file."""
    p = Path(path)
    if not p.parent.is_dir():
        raise FimError(f"output directory {p.parent} does not exist")
    if p.is_symlink():
        raise FimError(f"refusing to write through symlink {p}")
    try:
        atomic_write(p.parent, p.name, data, overwrite=overwrite)
    except FileExistsError:
        raise FimError(f"{p} already exists; use --overwrite to replace it") from None


# ---------------------------------------------------------------- JSON
def report_json(report: Report) -> bytes:
    return (report.model_dump_json(indent=2) + "\n").encode()


# ---------------------------------------------------------------- CSV
def _csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection (OWASP CSV injection) in string cells."""
    if isinstance(value, str) and value.startswith(_CSV_DANGEROUS):
        return "'" + value
    return value


def _event_row(e: Event) -> list[object]:
    b, a = e.before, e.after
    row: list[object] = [
        e.timestamp, e.scan_id, e.severity.value, e.event_type.value, e.path, e.rule,
        e.baseline_version, ";".join(c.field for c in e.changes),
        b.sha256 if b else "", a.sha256 if a else "",
        b.size if b else "", a.size if a else "",
        b.mode if b else "", a.mode if a else "",
        b.uid if b else "", a.uid if a else "",
        b.gid if b else "", a.gid if a else "",
        ";".join(e.risk_flags),
    ]  # fmt: skip
    return [_csv_safe(v) if v is not None else "" for v in row]


def events_csv(report: Report) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_EVENT_COLUMNS)
    for e in report.events:
        w.writerow(_event_row(e))
    return buf.getvalue().encode()


def issues_csv(report: Report) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_ISSUE_COLUMNS)
    for i in report.issues:
        w.writerow([_csv_safe(v) for v in (report.summary.scan_id, i.kind.value, i.path, i.detail)])
    return buf.getvalue().encode()


def issues_path_for(csv_path: str | Path) -> Path:
    p = Path(csv_path)
    return p.with_name(p.stem + ".issues" + p.suffix)


# ---------------------------------------------------------------- text
def verdict(report: Report) -> str:
    s = report.summary
    if not s.complete:
        return "INCOMPLETE"
    return "ALERT" if s.alert else ("CHANGES" if s.event_count else "CLEAN")


def render_text(report: Report, *, threshold: Severity | None = None) -> str:
    s = report.summary
    lines = [
        f"FIM scan {s.scan_id}  baseline v{s.baseline_version}  host={s.hostname}",
        f"Roots: {', '.join(s.roots)}",
        f"Scan mode: {s.mode}",
        f"Scan status: {'COMPLETE' if s.complete else 'INCOMPLETE'}",
        f"Entries scanned: {s.entries_scanned}  Bytes hashed: {s.bytes_hashed}",
        f"Events: {s.event_count}" + (f"  (alert threshold: {threshold.value})" if threshold else ""),
    ]
    if report.events:
        lines.append("")
        lines.append(f"  {'SEVERITY':<9} {'EVENT':<19} PATH")
        for e in report.events:
            extra = ",".join(c.field for c in e.changes)
            flags = f" risk={'+'.join(e.risk_flags)}" if e.risk_flags else ""
            suffix = f"  [{extra}]" if extra else ""
            lines.append(f"  {e.severity.value:<9} {e.event_type.value:<19} {e.path}{suffix}{flags}")
    if report.issues:
        lines.append("")
        lines.append("Scan issues (these paths were NOT fully verified):")
        for i in report.issues:
            lines.append(f"  {i.kind.value:<22} {i.path}  {i.detail}".rstrip())
    lines.append("")
    lines.append(f"Result: {verdict(report)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- syslog
_SYSLOG_SEV = {
    Severity.INFO: 6, Severity.LOW: 5, Severity.MEDIUM: 4, Severity.HIGH: 3, Severity.CRITICAL: 2,
}  # fmt: skip
_CEF_SEV = {
    Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 5, Severity.HIGH: 8, Severity.CRITICAL: 10,
}  # fmt: skip
# 32473 is the example enterprise number reserved for documentation by RFC 5612.
# Replace it with your organisation's IANA PEN before production use.
SD_ID = "fim@32473"


def _sd_escape(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _cef_hdr(v: str) -> str:
    return v.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def _epoch_ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


def format_rfc5424(e: Event, hostname: str, cfg: SyslogConfig) -> str:
    pri = cfg.facility * 8 + _SYSLOG_SEV[e.severity]
    params = {
        "scan_id": e.scan_id, "event": e.event_type.value, "severity": e.severity.value,
        "path": e.path, "rule": e.rule, "baseline": e.baseline_version,
        "fields": ",".join(c.field for c in e.changes),
        "old_sha256": e.before.sha256 if e.before and e.before.sha256 else "",
        "new_sha256": e.after.sha256 if e.after and e.after.sha256 else "",
        "risk": ",".join(e.risk_flags),
    }  # fmt: skip
    sd = "".join(f' {k}="{_sd_escape(v)}"' for k, v in params.items() if v != "")
    msg = f"{e.event_type.value} {e.path}"
    return f"<{pri}>1 {e.timestamp} {hostname} {cfg.app_name} - {e.event_type.value} [{SD_ID}{sd}] {msg}"


def format_cef(e: Event, hostname: str, version: str) -> str:
    ext = {
        "rt": _epoch_ms(e.timestamp), "dvchost": hostname, "externalId": e.scan_id,
        "filePath": e.path,
        "fileHash": e.after.sha256 if e.after and e.after.sha256 else "",
        "oldFileHash": e.before.sha256 if e.before and e.before.sha256 else "",
        "fsize": e.after.size if e.after else "",
        "oldFileSize": e.before.size if e.before else "",
        "filePermission": e.after.mode if e.after else "",
        "oldFilePermission": e.before.mode if e.before else "",
        "cs1Label": "rule", "cs1": e.rule,
        "cs2Label": "riskFlags", "cs2": ",".join(e.risk_flags),
    }  # fmt: skip
    if not e.risk_flags:
        del ext["cs2Label"], ext["cs2"]  # no dangling label without a value
    ext_s = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != "")
    name = f"File {e.event_type.value.replace('_', ' ')}"
    return (
        f"CEF:0|FIM|fim|{_cef_hdr(version)}|{_cef_hdr(e.event_type.value)}|{_cef_hdr(name)}|"
        f"{_CEF_SEV[e.severity]}|{ext_s}"
    )


def _issue_message(report: Report, cfg: SyslogConfig) -> str:
    s = report.summary
    pri = cfg.facility * 8 + 4
    kinds = ",".join(sorted({i.kind.value for i in report.issues}))
    sd = f'[{SD_ID} scan_id="{s.scan_id}" issues="{len(report.issues)}" kinds="{_sd_escape(kinds)}"]'
    return (
        f"<{pri}>1 {s.finished_at} {s.hostname} {cfg.app_name} - scan_incomplete {sd} "
        f"scan incomplete: {len(report.issues)} path(s) could not be verified"
    )


def syslog_messages(report: Report, cfg: SyslogConfig) -> list[str]:
    s = report.summary
    msgs = []
    for e in report.events:
        if e.severity.rank < cfg.min_severity.rank:
            continue
        if cfg.format == "cef":
            msgs.append(format_cef(e, s.hostname, s.tool_version))
        else:
            msgs.append(format_rfc5424(e, s.hostname, cfg))
    if not s.complete and cfg.format == "rfc5424":
        msgs.append(_issue_message(report, cfg))
    elif not s.complete:
        sev = _CEF_SEV[Severity.MEDIUM]
        msgs.append(
            f"CEF:0|FIM|fim|{s.tool_version}|scan_incomplete|Scan incomplete|{sev}|"
            f"dvchost={_cef_ext(s.hostname)} externalId={s.scan_id} cnt={len(report.issues)}"
        )
    return msgs


def send_syslog(messages: list[str], address: str, *, timeout: float = 5.0) -> None:
    """Deliver messages. UDP/unix: one datagram each. TCP: RFC 6587 octet-counting framing."""
    if not messages:
        return
    try:
        if address.startswith("/"):
            _send_unix(messages, address, timeout)
            return
        u = urlsplit(address)
        host, port = u.hostname or "", u.port or 514
        if u.scheme == "udp":
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                for m in messages:
                    s.sendto(m.encode(), (host, port))
        elif u.scheme == "tcp":
            with socket.create_connection((host, port), timeout=timeout) as s:
                for m in messages:
                    b = m.encode()
                    s.sendall(str(len(b)).encode() + b" " + b)
        else:
            raise FimError(f"unsupported syslog address {address!r}")
    except OSError as exc:
        raise FimError(f"syslog delivery to {address} failed: {exc.strerror or exc}") from exc


def _send_unix(messages: list[str], path: str, timeout: float) -> None:
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        try:
            with socket.socket(socket.AF_UNIX, kind) as s:
                s.settimeout(timeout)
                s.connect(path)
                for m in messages:
                    s.send(m.encode() + (b"\n" if kind == socket.SOCK_STREAM else b""))
            return
        except OSError as exc:
            if exc.errno == errno.EPROTOTYPE and kind == socket.SOCK_DGRAM:
                continue
            raise
