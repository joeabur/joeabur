import os
import plistlib

from mac_ir.collectors import files as files_c
from mac_ir.collectors import inventory, logs, network, persistence, processes
from mac_ir.utils.run import CommandResult


def by(recs, **kw):
    return [r for r in recs if all(r.get(k) == v for k, v in kw.items())]


def no_commands(argv, timeout, max_bytes):
    return CommandResult(argv=list(argv), error_kind="not_found", error=f"{argv[0]}: not found")


def test_inventory(ctx):
    res = inventory.collect(ctx)
    host = by(res.records, kind="host")[0]
    assert host["product_version"] == "14.4.1" and host["build"] == "23E224" and host["architecture"] == "arm64"
    assert host["hostname"] == "synthetic-mac.local" and host["boot_time"] == "2026-03-07T16:13:20Z"
    assert host["security_settings"]["sip"].endswith("enabled.")
    assert "Firewall is disabled" in host["security_settings"]["application_firewall"]
    assert by(res.records, kind="session") and by(res.records, kind="volume")[0]["mountpoint"] == "/"


def test_inventory_missing_commands_degrades(make_ctx):
    res = inventory.collect(make_ctx(runner=no_commands))
    assert res.status in ("partial", "failed") and {e.kind for e in res.errors} == {"not_found"}
    assert res.records[0]["kind"] == "host"  # still returns what it knows


def test_processes_join_args_hash_and_redact(ctx):
    res = processes.collect(ctx)
    procs = {r["pid"]: r for r in res.records}
    assert procs[977]["exe"] == "/private/tmp/.cache/kworker-upd" and procs[977]["exe_sha256"]
    assert procs[977]["name"] == "kworker-upd" and procs[977]["user"] == "analyst" and procs[977]["uid"] == 501
    cmd = " ".join(procs[1310]["cmdline"])
    assert "hunter2" not in cmd and "[REDACTED]" in cmd
    assert procs[1]["start_time"] == "2026-03-09T10:00:00Z"
    assert procs[602]["exe_sha256"] and procs[1]["exe_sha256"]


def test_processes_ps_missing_and_args_missing(make_ctx):
    res = processes.collect(make_ctx(runner=no_commands))
    assert res.status == "failed" and res.errors[0].kind == "not_found"
    from rootfs_builder import fake_runner

    def partial(argv, t, m):
        if argv[:2] == ["ps", "-axww"]:
            return CommandResult(argv=list(argv), error_kind="permission_denied", error="denied")
        return fake_runner(argv, t, m)

    res = processes.collect(make_ctx(runner=partial))
    assert res.status == "partial" and all(r["visibility"] == "limited" and r["cmdline"] is None for r in res.records)


def test_processes_timeout_is_reported(make_ctx):
    def slow(argv, t, m):
        return CommandResult(argv=list(argv), timed_out=True, error_kind="timeout", error="ps exceeded 15s")

    res = processes.collect(make_ctx(runner=slow))
    assert res.errors[0].kind == "timeout" and res.status == "failed"


def test_network_lsof(ctx):
    res = network.collect(ctx)
    socks = by(res.records, kind="socket")
    assert by(socks, local_port=4444)[0]["process"] == "kworker-upd" and by(socks, remote_port=443)
    assert by(res.records, kind="interface") and by(res.records, kind="route")[0]["destination"] == "default"
    assert any("lsof without root" in n for n in res.notes)


def test_network_netstat_fallback(make_ctx):
    from rootfs_builder import fake_runner

    def runner(argv, t, m):
        if argv[0] == "lsof":
            return CommandResult(argv=list(argv), error_kind="permission_denied", error="lsof: permission denied")
        if argv[:2] == ["netstat", "-an"]:
            return CommandResult(argv=list(argv), returncode=0, stdout="tcp4 0 0 *.22 *.* LISTEN\n")
        return fake_runner(argv, t, m)

    res = network.collect(make_ctx(runner=runner))
    socks = by(res.records, kind="socket")
    assert socks and socks[0]["source"] == "netstat" and socks[0]["process"] is None
    assert any(e.source == "lsof" for e in res.errors) and res.status == "partial"


def test_persistence_launchd(ctx):
    res = persistence.collect(ctx)
    plists = {r["label"]: r for r in by(res.records, kind="launchd_plist") if r.get("label")}
    up = plists["com.example.updater"]
    assert up["exec_binary"] == "/private/tmp/.cache/kworker-upd" and up["exec_exists"] and up["signed"] is False
    assert up["run_at_load"] and up["keep_alive"] and up["standard_location"] is False
    assert plists["com.example.backup"]["exec_exists"] is False
    assert plists["com.example.sshd"]["signed"] is True and plists["com.example.sshd"]["standard_location"] is True
    assert plists["com.example.loose"]["mode"] == "0666"
    agent = plists["com.example.agent"]  # binary plist in a user LaunchAgents dir
    assert agent["scope"] == "user" and "curl" in " ".join(agent["program_arguments"])
    assert any(e.kind == "parse_error" and "broken.plist" in e.source for e in res.errors)
    assert by(res.records, kind="launchd_unexpected_file")
    assert by(res.records, kind="startup_item") and by(res.records, kind="cron_entry")[0]["exec_binary"] == "curl"


def test_persistence_never_executes_and_basic_skips_codesign(make_ctx):
    calls = []

    def spy(argv, t, m):
        calls.append(argv)
        return no_commands(argv, t, m)

    persistence.collect(make_ctx(deep=False, runner=spy))
    assert all(a[0] in ("crontab",) for a in calls)  # no codesign in basic; no program from a plist is ever run


def test_persistence_permission_denied(ctx, monkeypatch):
    real = os.listdir

    def fake(p="."):
        if str(p).endswith("Library/LaunchDaemons"):
            raise PermissionError
        return real(p)

    monkeypatch.setattr(os, "listdir", fake)
    res = persistence.collect(ctx)
    assert any(e.kind == "permission_denied" and e.source == "/Library/LaunchDaemons" for e in res.errors)
    assert res.status == "partial"


def test_symlinked_plist_not_followed(ctx, rootfs):
    os.symlink("/etc/hosts", rootfs / "Library/LaunchDaemons/link.plist")
    res = persistence.collect(ctx)
    link = by(res.records, path="/Library/LaunchDaemons/link.plist")[0]
    assert link["type"] == "symlink" and "label" not in link


def test_cron_no_crontab_is_not_an_error(make_ctx):
    from rootfs_builder import fake_runner

    def runner(argv, t, m):
        if argv == ["crontab", "-l"]:
            return CommandResult(argv=list(argv), returncode=1, stderr="crontab: no crontab for analyst")
        return fake_runner(argv, t, m)

    res = persistence.collect(make_ctx(runner=runner))
    assert not by(res.records, kind="cron_entry") and not any(e.source == "crontab -l" for e in res.errors)


def test_logs_ndjson(ctx):
    res = logs.collect(ctx)
    ev = by(res.records, kind="auth_event")
    assert len(by(ev, event_type="ssh_failed_login")) == 13  # 12 + one <private> redacted event
    assert by(ev, event_type="ssh_accepted")[0]["user"] == "root"
    stats = by(res.records, kind="log_stats")[0]
    assert stats["malformed"] == 1 and stats["outside_window"] == 1 and stats["ignored"] >= 1
    assert stats["redacted_events"] == 1 and any("<private>" in n for n in res.notes)
    assert "predicate" in stats


def test_logs_command_is_an_argument_array(make_ctx):
    seen = []

    def spy(argv, t, m):
        seen.append(list(argv))
        return no_commands(argv, t, m)

    ctx = make_ctx(runner=spy)
    ctx.config["logs"]["predicate"] = 'process == "sshd"; touch /tmp/pwned'
    logs.collect(ctx)
    argv = seen[0]
    assert argv[:2] == ["log", "show"] and argv[argv.index("--predicate") + 1].endswith("touch /tmp/pwned")


def test_logs_unavailable_and_permission(make_ctx):
    res = logs.collect(make_ctx(runner=no_commands))
    assert any("NOT available" in n for n in res.notes) and res.errors

    def denied(argv, t, m):
        return CommandResult(
            argv=list(argv), returncode=1, stderr="log: permission denied; administrator privileges required"
        )

    res = logs.collect(make_ctx(runner=denied))
    assert res.errors[0].kind == "permission_denied"


def test_logs_import_and_archive(make_ctx, tmp_path):
    from rootfs_builder import LOG_NDJSON

    exported = tmp_path / "export.ndjson"
    exported.write_text(LOG_NDJSON)
    arc = tmp_path / "case.logarchive"
    arc.mkdir()
    res = logs.collect(make_ctx(import_logs=[exported], import_archives=[arc]))
    assert any(s.startswith("import:") for s in res.sources) and any("--archive" in s for s in res.sources)
    bad = tmp_path / "notarchive"
    bad.mkdir()
    res = logs.collect(make_ctx(import_archives=[bad]))
    assert any("not a .logarchive" in e.message for e in res.errors)


def test_files_collector(ctx):
    res = files_c.collect(ctx)
    sudoers = by(res.records, path="/etc/sudoers")[0]
    assert sudoers["world_writable"] is True and "sha256" not in sudoers
    ex = by(res.records, kind="writable_dir_exec")
    assert len(ex) == 1 and ex[0]["path"].endswith("kworker-upd")  # notes.txt (not executable) skipped


def test_files_walk_cap(ctx, rootfs, cfg):
    for i in range(10):
        (rootfs / "private/tmp" / f"f{i}").write_text("x")
    cfg["limits"]["max_walk_entries"] = 3
    assert any(e.kind == "truncated" for e in files_c.collect(ctx).errors)


def test_plist_content_is_not_executed(ctx, rootfs):
    marker = rootfs / "executed"
    data = plistlib.dumps(
        {"Label": "evil", "ProgramArguments": ["/bin/sh", "-c", f"touch {marker}"], "RunAtLoad": True}
    )
    (rootfs / "Library/LaunchDaemons/evil.plist").write_bytes(data)
    persistence.collect(ctx)
    assert not marker.exists()
