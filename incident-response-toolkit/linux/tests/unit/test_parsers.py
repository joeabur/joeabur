from datetime import UTC, datetime

from linux_ir.parsers import authlog, cron, procfs, ss, systemd_unit
from linux_ir.utils.timeutil import parse_log_timestamp

REF = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)


def test_stat_with_parentheses_in_name():
    stat = "5 (weird) name)) S 1 " + " ".join(["0"] * 17) + " 4242 " + " ".join(["0"] * 10)
    parsed = procfs.parse_stat(stat)
    assert parsed and parsed["comm"] == "weird) name)" and parsed["ppid"] == 1 and parsed["starttime_ticks"] == 4242


def test_stat_malformed():
    assert procfs.parse_stat("garbage") is None
    assert procfs.parse_stat("1 (x) S") is None


def test_cmdline_bounds():
    assert procfs.parse_cmdline(b"a\0b\0") == ["a", "b"]
    assert len(procfs.parse_cmdline(b"x\0" * 1000)) == 256


def test_proc_net_ipv6_and_ipv4():
    v4 = "h\n 0: 0100007F:0035 00000000:0000 0A 0:0 0:0 0 0 0 1 1\n"
    assert procfs.parse_proc_net(v4, "tcp")[0]["local_addr"] == "127.0.0.1"
    v6 = "h\n 0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 1 1\n"
    assert procfs.parse_proc_net(v6, "tcp6")[0]["local_addr"] == "::1"
    assert procfs.parse_proc_net("h\nnot a row\n", "tcp") == []


def test_ss_parse_ipv6_and_junk():
    rows, bad = ss.parse_ss('tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1,fd=3))\njunk line\n')
    assert rows[0]["local_port"] == 22 and rows[0]["process"] == "sshd" and bad == 1


def test_unit_parser_continuation_and_prefixes():
    sec = systemd_unit.parse_unit("[Service]\nExecStart=-/usr/bin/foo \\\n  --bar\nExecStart=/x\n# c\n")
    assert sec["Service"]["ExecStart"][0].startswith("-/usr/bin/foo --bar")
    assert systemd_unit.exec_binary("@+/usr/bin/foo arg") == "/usr/bin/foo"
    assert systemd_unit.exec_binary("") is None


def test_cron_parser():
    rows = cron.parse_crontab("MAILTO=x\n@reboot root /bin/a\n* * * * * root /bin/b -x\nbroken\n", system=True)
    assert [r.get("exec_binary") for r in rows if "command" in r] == ["/bin/a", "/bin/b"]
    assert rows[-1].get("parse_error")
    user = cron.parse_crontab("5 4 * * * /bin/c", system=False)
    assert user[0]["user"] is None


def test_authlog_formats():
    iso = "2026-03-10T11:00:00+0000 host sshd[9]: Failed password for root from 192.0.2.1 port 5 ssh2"
    ev = authlog.parse_line(iso, REF, "t")
    assert ev and ev["ts"] == "2026-03-10T11:00:00Z" and ev["event_type"] == "ssh_failed_login"
    sudo = authlog.parse_line("Mar 10 11:00:00 h sudo:   bob : TTY=pts/1 ; COMMAND=/bin/ls", REF, "t")
    assert sudo and sudo["event_type"] == "sudo_command"
    assert authlog.parse_line("", REF, "t") is None
    assert authlog.parse_line("Mar 10 11:00:00 h cron[1]: nothing", REF, "t") is None


def test_timestamp_normalisation_and_year_rollover():
    assert parse_log_timestamp("2026-03-10T14:00:00+02:00", REF).hour == 12  # type: ignore[union-attr]
    dec = parse_log_timestamp("Dec 31 23:00:00", datetime(2026, 1, 1, 1, 0, tzinfo=UTC))
    assert dec and dec.year == 2025
    assert parse_log_timestamp("not a time", REF) is None
    assert parse_log_timestamp("Feb 31 10:00:00", REF) is None
