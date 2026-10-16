import os

from linux_ir.collectors import files as files_c
from linux_ir.collectors import inventory, logs, network, persistence, processes
from linux_ir.platform_info import detect_init, detect_platform, parse_os_release
from linux_ir.utils.run import CommandResult


def by(recs, **kw):
    return [r for r in recs if all(r.get(k) == v for k, v in kw.items())]


def test_parse_os_release_quotes_and_comments():
    d = parse_os_release('# c\nNAME="Fedora Linux"\nVERSION_ID=40\nBAD LINE\nID=fedora\n')
    assert d == {"NAME": "Fedora Linux", "VERSION_ID": "40", "ID": "fedora"}


def test_platform_detection_from_fake_root(rootfs):
    info = detect_platform(rootfs)
    assert info["distribution_id"] == "ubuntu" and info["version"] == "22.04"
    assert info["init"]["systemd"] is True


def test_non_systemd_init_detected(tmp_path):
    (tmp_path / "proc/1").mkdir(parents=True)
    (tmp_path / "proc/1/comm").write_text("runit\n")
    assert detect_init(tmp_path) == {"name": "runit", "systemd": False, "pid1_comm": "runit"}


def test_inventory(ctx):
    res = inventory.collect(ctx)
    host = by(res.records, kind="host")[0]
    assert host["hostname"] == "synthetic-host" and host["uptime_seconds"] == 86400
    assert host["security_settings"]["kernel.randomize_va_space"] == "2"
    assert by(res.records, kind="session")[0]["user"] == "analyst"


def test_processes_parse_and_redact(ctx):
    res = processes.collect(ctx)
    procs = {r["pid"]: r for r in res.records}
    assert procs[977]["exe"] == "/tmp/.cache/kworker-upd" and procs[977]["exe_sha256"]
    assert procs[1203]["exe_deleted"] is True and "exe_sha256" not in procs[1203]
    joined = " ".join(procs[1310]["cmdline"])
    assert "hunter2" not in joined and "[REDACTED]" in joined
    assert procs[412]["uid_real"] == 0 and procs[977]["uid_real"] == 1000


def test_processes_disappearing_and_permission(ctx, rootfs, monkeypatch):
    real_read_text = type(rootfs).read_text

    def fake_read_text(self, *a, **k):
        if self.parts[-2:] == ("412", "stat"):
            raise FileNotFoundError  # process exited mid-collection
        if self.parts[-2:] == ("977", "stat"):
            raise PermissionError
        return real_read_text(self, *a, **k)

    monkeypatch.setattr(type(rootfs), "read_text", fake_read_text)
    res = processes.collect(ctx)
    pids = {r["pid"] for r in res.records}
    assert 412 not in pids and 977 not in pids and 1 in pids
    assert any("exited during collection" in n for n in res.notes)
    assert any("limited visibility" in n for n in res.notes)


def test_processes_proc_missing(make_ctx, tmp_path):
    res = processes.collect(make_ctx(root=tmp_path))
    assert res.status == "failed" and res.errors[0].kind == "unavailable"


def test_network_ss_and_routes(ctx):
    res = network.collect(ctx)
    socks = by(res.records, kind="socket")
    assert {(s["proto"], s["local_port"]) for s in socks} >= {("tcp", 22), ("tcp", 4444), ("udp", 53)}
    assert by(socks, local_port=4444)[0]["process"] == "kworker-upd"
    assert by(res.records, kind="route")[0]["via"] == "10.0.0.1"
    assert any(e.collector == "network" and "nft" in e.source for e in res.errors)  # firewall tools absent


def test_network_procfs_fallback(make_ctx):
    ctx = make_ctx(runner=lambda argv, t, m: CommandResult(argv=argv, error_kind="not_found", error="nope"))
    res = network.collect(ctx)
    socks = by(res.records, kind="socket")
    assert any(s["local_port"] == 4444 and s["state"] == "LISTEN" for s in socks)
    assert any(s["remote_addr"] == "203.0.113.50" and s["state"] == "ESTAB" for s in socks)
    assert res.status == "partial" and all(s["process"] is None for s in socks)


def test_persistence_systemd_and_cron(ctx):
    res = persistence.collect(ctx)
    units = {r["unit"]: r for r in by(res.records, kind="systemd_unit")}
    assert units["evil-updater.service"]["exec_binary"] == "/tmp/.cache/kworker-upd"
    assert units["evil-updater.service"]["exec_exists"] is True and units["evil-updater.service"]["exec_sha256"]
    assert units["backup.service"]["exec_exists"] is False
    assert by(res.records, kind="systemd_enablement")[0]["unit"] == "evil-updater.service"
    cron = by(res.records, kind="cron_entry")
    assert any("curl" in c["command"] and c["user"] == "root" for c in cron)
    assert not any(c.get("command", "").startswith("MAILTO") for c in cron)  # env lines skipped
    ak = by(res.records, kind="authorized_keys")[0]
    assert ak["key_count"] == 1 and ak["has_command_option"] and ak["keys"][0]["fingerprint"].startswith("SHA256:")
    assert "synthetic-comment" not in str(ak)  # key comments are not stored
    assert by(res.records, kind="sshd_config")[0]["settings"]["permitemptypasswords"] == "yes"
    assert by(res.records, kind="kernel_module")


def test_persistence_non_systemd(make_ctx, rootfs):
    (rootfs / "run/systemd/system/.keep").unlink()
    (rootfs / "run/systemd/system").rmdir()
    (rootfs / "run/systemd").rmdir()
    (rootfs / "proc/1/comm").write_text("openrc-init\n")
    res = persistence.collect(make_ctx())
    assert not by(res.records, kind="systemd_unit")
    assert any("not systemd" in n for n in res.notes)
    assert by(res.records, kind="cron_entry")  # other sources still examined


def test_persistence_permission_denied(ctx, rootfs, monkeypatch):
    real = os.listdir

    def fake_listdir(p="."):
        if str(p).endswith("etc/cron.d"):
            raise PermissionError
        return real(p)

    monkeypatch.setattr(os, "listdir", fake_listdir)
    res = persistence.collect(ctx)
    assert any(e.kind == "permission_denied" and e.source == "/etc/cron.d" for e in res.errors)
    assert res.status == "partial"


def test_systemd_symlink_not_followed(ctx, rootfs):
    os.symlink("/dev/null", rootfs / "etc/systemd/system/masked.service")
    res = persistence.collect(ctx)
    masked = by(res.records, unit="masked.service")[0]
    assert masked["masked"] is True and "exec_start" not in masked


def test_logs_parse_window_and_malformed(ctx):
    res = logs.collect(ctx)
    ev = by(res.records, kind="auth_event")
    assert len([e for e in ev if e["event_type"] == "ssh_failed_login"]) == 12
    assert by(ev, event_type="ssh_accepted")[0]["user"] == "root"
    assert by(ev, event_type="ssh_accepted")[0]["ts"] == "2026-03-10T11:50:30Z"
    stats = by(res.records, kind="log_stats")[0]
    assert stats["unrecognized"] >= 1 and stats["outside_window"] == 1  # malformed + January line
    assert not any(e["ts"].startswith("2026-01") for e in ev if e["ts"])


def test_logs_missing_sources_reported(make_ctx, tmp_path):
    res = logs.collect(make_ctx(root=tmp_path))
    assert any("NOT available" in n for n in res.notes)


def test_logs_permission_denied(ctx, rootfs):
    # simulate unreadable log through a directory in place of the file
    (rootfs / "var/log/secure").mkdir()
    res = logs.collect(ctx)
    assert any(e.source == "/var/log/secure" for e in res.errors)


def test_logs_import_and_gzip(make_ctx, tmp_path, rootfs):
    import gzip

    p = tmp_path / "exported.log.gz"
    with gzip.open(p, "wb") as fh:
        fh.write(b"Mar 10 11:00:00 h sshd[1]: Failed password for bob from 192.0.2.7 port 22 ssh2\n")
    res = logs.collect(make_ctx(import_logs=[p]))
    assert any(e.get("src_ip") == "192.0.2.7" for e in res.records)


def test_files_collector(ctx):
    res = files_c.collect(ctx)
    shadow = by(res.records, path="/etc/shadow")[0]
    assert shadow["world_readable"] is True and "sha256" not in shadow  # contents never hashed/read
    assert by(res.records, kind="writable_dir_exec")[0]["path"].endswith("kworker-upd")


def test_files_walk_cap(ctx, rootfs, cfg):
    for i in range(10):
        (rootfs / "tmp" / f"f{i}").write_text("x")
    cfg["limits"]["max_walk_entries"] = 3
    res = files_c.collect(ctx)
    assert any(e.kind == "truncated" for e in res.errors)


def test_runner_timeout_and_missing():
    from linux_ir.utils.run import run_command

    r = run_command(["definitely-not-a-real-binary-xyz"])
    assert r.error_kind == "not_found"
    r = run_command(["sleep", "5"], timeout=0.3)
    assert r.timed_out and r.error_kind == "timeout"
    r = run_command(["python3", "-c", "print('A'*100000)"], max_bytes=1000)
    assert r.truncated and len(r.stdout) <= 1000
    r = run_command(["echo", "$(touch /tmp/should-not-exist-ir)"])
    assert not os.path.exists("/tmp/should-not-exist-ir")  # no shell interpretation
