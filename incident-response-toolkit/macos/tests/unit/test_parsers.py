from mac_ir.parsers import launchd, system, unified_log
from mac_ir.platform_info import parse_sw_vers


def test_sw_vers():
    d = parse_sw_vers("ProductName:\t\tmacOS\nProductVersion:\t\t14.4.1\nBuildVersion:\t\t23E224\n")
    assert d["ProductVersion"] == "14.4.1" and d["BuildVersion"] == "23E224"


def test_ps_parse_paths_with_spaces_and_junk():
    text = "  10   1 501 bob S Mon Mar  9 10:00:00 2026 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\ngarbage\n x y z\n"
    rows, bad = system.parse_ps(text)
    assert rows[0]["comm"].endswith("Google Chrome") and rows[0]["start_time"] == "2026-03-09T10:00:00Z" and bad == 2
    assert system.parse_lstart(["not", "a", "date", "at", "all"]) is None


def test_ps_args():
    assert system.parse_ps_args("  5 /bin/ls -l\n  6\nxx y\n") == {5: "/bin/ls -l", 6: ""}


def test_lsof_f_listening_and_established():
    text = "p10\ncfoo\nLbob\nf3\nPTCP\nn[::1]:631\nTST=LISTEN\nf4\nPTCP\nn10.0.0.1:5->198.51.100.1:443\nTST=ESTABLISHED\nf5\nPUDP\nn*:5353\n"
    rows = system.parse_lsof_f(text)
    assert [(r["proto"], r["local_port"], r["state"]) for r in rows] == [
        ("tcp", 631, "LISTEN"),
        ("tcp", 5, "ESTABLISHED"),
        ("udp", 5353, "UNCONN"),
    ]
    assert rows[1]["remote_addr"] == "198.51.100.1" and rows[0]["local_addr"] == "::1" and rows[0]["process"] == "foo"
    assert system.parse_lsof_f("garbage\n\nzzz") == []


def test_netstat_and_ifconfig_and_boottime_and_df():
    rows = system.parse_netstat_an(
        "tcp4  0  0  *.22  *.*  LISTEN\ntcp4 0 0 10.0.0.5.51234 203.0.113.50.443 ESTABLISHED\nbogus\n"
    )
    assert rows[0]["local_port"] == 22 and rows[1]["remote_addr"] == "203.0.113.50" and rows[1]["remote_port"] == 443
    assert (
        system.parse_ifconfig("en0: flags=8863<UP>\n\tinet 10.0.0.5 netmask 0xffffff00\n")[0]["address"] == "10.0.0.5"
    )
    assert system.parse_boottime("{ sec = 1772900000, usec = 5 } Mon") == 1772900000
    assert system.parse_boottime("junk") is None
    df = system.parse_df(
        "Filesystem 1024-blocks Used Available Capacity iused ifree %iused Mounted on\n/dev/disk3s1 100 50 40 55% 1 2 0% /Volumes/Data Disk\n"
    )
    assert df[0]["mountpoint"] == "/Volumes/Data Disk" and df[0]["free_bytes"] == 40 * 1024


def test_codesign_parse():
    assert system.parse_codesign("x: code object is not signed at all", 1)["signed"] is False
    ok = system.parse_codesign("Authority=Developer ID Application: A (T1)\nTeamIdentifier=T1\n", 0)
    assert ok["signed"] is True and ok["team_id"] == "T1"
    assert system.parse_codesign("Signature=adhoc\nTeamIdentifier=not set\nidentifier=x", 0)["adhoc"] is True
    assert system.parse_codesign("weird failure", 1)["signed"] is None


def test_plist_parse_summary_and_malformed():
    import plistlib

    data = plistlib.dumps({"Label": "x", "ProgramArguments": ["/bin/a", "b"], "KeepAlive": {"SuccessfulExit": False}})
    s = launchd.summarize_launchd(launchd.parse_plist(data))
    assert s["exec_binary"] == "/bin/a" and s["keep_alive"] is True and s["run_at_load"] is False
    assert launchd.summarize_launchd({"Label": 5, "ProgramArguments": "str"})["program_arguments"] == []
    for bad in (b"<plist><dict>", b"", b"\x00\x01", plistlib.dumps([1, 2]), b"x" * 2_000_000):
        try:
            launchd.parse_plist(bad)
        except launchd.PlistError:
            continue
        raise AssertionError("expected PlistError")


def test_plist_binary_format_supported():
    import plistlib

    data = plistlib.dumps({"Label": "b", "Program": "/bin/x"}, fmt=plistlib.FMT_BINARY)
    assert launchd.summarize_launchd(launchd.parse_plist(data))["program"] == "/bin/x"


def test_unified_log_events():
    ssh = '{"timestamp":"2026-03-10 11:00:00.123456+0000","processImagePath":"/usr/sbin/sshd","processID":1,"eventMessage":"Failed password for root from 192.0.2.1 port 5 ssh2"}'
    ev, st = unified_log.parse_event(ssh, "t")
    assert st == "event" and ev["event_type"] == "ssh_failed_login" and ev["ts"] == "2026-03-10T11:00:00Z"
    redacted = ssh.replace("root", "<private>")
    ev2, _ = unified_log.parse_event(redacted, "t")
    assert ev2["redacted"] is True
    assert unified_log.parse_event("not json", "t") == (None, "malformed")
    assert unified_log.parse_event('{"a":1}', "t") == (None, "malformed")
    other = '{"processImagePath":"/usr/bin/x","eventMessage":"hello"}'
    assert unified_log.parse_event(other, "t") == (None, "ignored")
