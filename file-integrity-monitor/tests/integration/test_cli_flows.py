from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fim import cli, signing
from fim.baseline import BaselineStore
from fim.models import Report
from tests.conftest import Workspace


def out(r) -> str:  # type: ignore[no-untyped-def]
    return r.output + (r.stderr if getattr(r, "stderr_bytes", None) else "")


def tree_digest(path: Path) -> dict[str, bytes]:
    return {str(p): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


class TestBasicFlow:
    def test_clean_changes_exit_codes(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        r = run("baseline", "create")
        assert r.exit_code == 0, r.output
        r = run("scan")
        assert r.exit_code == cli.EXIT_OK and "Result: CLEAN" in r.output
        (ws.data / "a.txt").write_text("tampered")
        r = run("scan")
        assert r.exit_code == cli.EXIT_CHANGES and "modified" in r.output and "ALERT" in r.output

    def test_scan_never_modifies_baseline_or_data(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "a.txt").write_text("tampered")
        before_b, before_d = tree_digest(ws.state), tree_digest(ws.data)
        run("scan")
        assert tree_digest(ws.state) == before_b  # scanning is read-only for the baseline too
        assert tree_digest(ws.data) == before_d

    def test_create_refuses_existing_baseline(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        assert run("baseline", "create").exit_code == 0
        r = run("baseline", "create")
        assert r.exit_code == cli.EXIT_OPERATIONAL and "already exists" in r.output
        assert BaselineStore(ws.state / "baselines").versions() == [1]
        assert run("baseline", "create", "--force", "--reason", "post-incident").exit_code == 0
        assert BaselineStore(ws.state / "baselines").versions() == [1, 2]

    def test_scan_without_baseline(self, run) -> None:  # type: ignore[no-untyped-def]
        r = run("scan")
        assert r.exit_code == cli.EXIT_OPERATIONAL and "does not exist" in r.output

    def test_json_csv_exports_and_no_overwrite(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "new").write_text("n")
        j, c = ws.root / "r.json", ws.root / "r.csv"
        r = run("scan", "--json", str(j), "--csv", str(c), "-q")
        assert r.exit_code == 1 and "Result:" not in r.output
        rep = Report.model_validate_json(j.read_text())
        assert rep.summary.event_count == 1 and rep.events[0].event_type.value == "added"
        assert c.exists() and (ws.root / "r.issues.csv").exists()
        r = run("scan", "--json", str(j))
        assert r.exit_code == cli.EXIT_EXPORT or "already exists" in r.output
        assert run("scan", "--json", str(j), "--overwrite", "-q").exit_code == 1

    def test_partial_scan_and_path_traversal(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "a.txt").write_text("changed")
        (ws.data / "sub" / "b.txt").write_text("changed")
        r = run("scan", "--root", str(ws.data / "sub"))
        assert "b.txt" in r.output and "a.txt" not in r.output and "Scan mode: partial" in r.output
        for bad in (str(ws.data / ".." / "state"), "/etc", str(ws.root)):
            r = run("scan", "--root", bad)
            assert r.exit_code == cli.EXIT_USAGE, bad

    def test_report_convert(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "a.txt").write_text("changed")
        j = ws.root / "r.json"
        run("scan", "--json", str(j), "-q")
        for fmt, needle in (
            ("text", "Result: ALERT"),
            ("csv", "event_type"),
            ("cef", "CEF:0|FIM"),
            ("rfc5424", "fim@32473"),
        ):
            r = run("report", "convert", str(j), "--format", fmt)
            assert r.exit_code == 0 and needle in r.output, (fmt, r.output)
        assert run("report", "convert", str(j), "--format", "xml").exit_code == cli.EXIT_USAGE
        j.write_text("{not json")
        assert run("report", "convert", str(j)).exit_code == cli.EXIT_USAGE


class TestIncompleteScans:
    def test_incomplete_is_never_clean(self, ws: Workspace, run, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        for i in range(5):
            (ws.data / f"f{i}").write_text("x")
        cfg = ws.config_path
        cfg.write_text(cfg.read_text() + "max_files = 3\n")
        r = run("scan")
        assert r.exit_code == cli.EXIT_INCOMPLETE
        assert "INCOMPLETE" in r.output and "limit_reached" in r.output and "CLEAN" not in r.output

    def test_missing_root_exit_code(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        for p in sorted(ws.data.rglob("*"), reverse=True):
            p.unlink() if not p.is_dir() else p.rmdir()
        ws.data.rmdir()
        r = run("scan")
        assert r.exit_code == cli.EXIT_INCOMPLETE and "root_missing" in r.output
        assert "deleted" in r.output  # and the known entries are still reported gone

    def test_baseline_create_refuses_incomplete_unless_allowed(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        (ws.data / "big").write_bytes(b"x" * 5000)
        ws.config_path.write_text(ws.config_path.read_text() + "max_file_bytes = 1000\n")
        r = run("baseline", "create")
        assert r.exit_code == cli.EXIT_INCOMPLETE and "refusing" in r.output
        assert BaselineStore(ws.state / "baselines").versions() == []
        r = run("baseline", "create", "--allow-incomplete")
        assert r.exit_code == cli.EXIT_INCOMPLETE  # still signalled
        assert "complete: false" in r.output
        r = run("scan")
        assert "created from an INCOMPLETE scan" in r.output

    def test_interrupt_during_update_leaves_baseline_untouched(  # type: ignore[no-untyped-def]
        self, ws: Workspace, run, monkeypatch
    ) -> None:
        from fim.scanner import Scanner

        run("baseline", "create")
        before = tree_digest(ws.state)
        (ws.data / "a.txt").write_text("changed")
        real_tick = Scanner._tick
        calls = {"n": 0}

        def interrupt(self, path):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
            return real_tick(self, path)

        monkeypatch.setattr(Scanner, "_tick", interrupt)
        r = run("baseline", "update", "--reason", "x", "--yes")
        assert r.exit_code != 0
        assert tree_digest(ws.state) == before


class TestBaselineUpdateConfirmation:
    def test_requires_reason(self, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        assert run("baseline", "update", "--yes").exit_code == cli.EXIT_USAGE

    def test_non_interactive_without_yes_is_refused(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "a.txt").write_text("changed")
        r = run("baseline", "update", "--reason", "r")
        assert r.exit_code == cli.EXIT_USAGE and "confirmation required" in r.output
        assert BaselineStore(ws.state / "baselines").versions() == [1]

    def test_interactive_decline_and_accept(self, ws: Workspace, run, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "a.txt").write_text("changed")
        monkeypatch.setattr(cli, "_is_interactive", lambda: True)
        r = run("baseline", "update", "--reason", "r", input="no\n")
        assert r.exit_code == cli.EXIT_USAGE and "aborted" in r.output
        assert BaselineStore(ws.state / "baselines").versions() == [1]
        r = run("baseline", "update", "--reason", "approved change #42", input="yes\n")
        assert r.exit_code == 0 and "v1 -> v2" in r.output
        assert run("scan").exit_code == 0

    def test_update_is_audited(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.data / "a.txt").write_text("changed")
        run("baseline", "update", "--reason", "CHG-1234", "--yes")
        recs = BaselineStore(ws.state / "baselines").read_audit()
        assert [r["action"] for r in recs] == ["create", "update"]
        assert recs[1]["reason"] == "CHG-1234"
        assert recs[1]["detail"]["accepted_events"] == {"added": 0, "modified": 1, "deleted": 0}
        assert recs[1]["detail"]["previous_version"] == 1
        r = run("audit", "show")
        assert "CHG-1234" in r.output
        assert run("audit", "verify").exit_code == 0

    def test_cannot_update_on_untrusted_baseline(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        p = BaselineStore(ws.state / "baselines").path_for(1)
        p.write_text(p.read_text().replace("alpha", "x") + " ")
        p.write_bytes(p.read_bytes()[:-30])
        r = run("baseline", "update", "--reason", "x", "--yes")
        assert r.exit_code == cli.EXIT_UNTRUSTED


class TestTrustFailures:
    def test_corrupt_baseline_exit_4(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        p = BaselineStore(ws.state / "baselines").path_for(1)
        doc = json.loads(p.read_text())
        doc["entries"][next(iter(doc["entries"]))]["size"] = 999
        p.write_text(json.dumps(doc))
        for cmd in (["scan"], ["baseline", "verify"]):
            r = run(*cmd)
            assert r.exit_code == cli.EXIT_UNTRUSTED and "NOT trusted" in r.output

    def test_unsafe_state_dir_permissions(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        run("baseline", "create")
        (ws.state / "baselines").chmod(0o755)
        r = run("scan")
        assert r.exit_code == cli.EXIT_OPERATIONAL and "chmod 700" in r.output

    def test_config_errors_exit_2(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        ws.config_path.write_text("[baseline]\ndir='relative'\n[scan]\nroots=['/x']\n")
        r = run("scan")
        assert r.exit_code == cli.EXIT_USAGE and "must be absolute" in r.output
        assert run("config", "check", config=ws.root / "missing.toml").exit_code == cli.EXIT_USAGE

    def test_baseline_inside_monitored_dir_rejected(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        ws.config_path.write_text(f'[baseline]\ndir="{ws.data}/b"\n[scan]\nroots=["{ws.data}"]\n')
        r = run("config", "check")
        assert r.exit_code == cli.EXIT_USAGE and "overlaps" in r.output


class TestSignedWorkflow:
    def test_end_to_end(self, ws: Workspace, run, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        keys = ws.root / "keys"
        keys.mkdir()
        r = run("keygen", "--private", str(keys / "k.pem"), "--public", str(keys / "k.pub"))
        assert r.exit_code == 0 and "key id: sha256:" in r.output
        ws.config_path.write_text(
            ws.config_path.read_text().replace("[scan]", f'public_key = "{keys}/k.pub"\n[scan]')
        )
        assert run("baseline", "create").exit_code == cli.EXIT_USAGE  # unsigned create refused
        r = run("baseline", "create", "--sign-key", str(keys / "k.pem"))
        assert r.exit_code == 0 and "signed: true" in r.output
        assert run("scan").exit_code == 0
        assert "verified (sha256:" in run("baseline", "verify").output
        (ws.data / "a.txt").write_text("changed")
        r = run("baseline", "update", "--reason", "ok", "--yes", "--sign-key", str(keys / "k.pem"))
        assert r.exit_code == 0
        assert run("scan").exit_code == 0
        # tamper with the signature
        sig = BaselineStore(ws.state / "baselines").sig_path_for(2)
        sig.write_text(sig.read_text().replace("signature: ", "signature: AAAA"))
        r = run("scan")
        assert r.exit_code == cli.EXIT_UNTRUSTED

    def test_keygen_refuses_monitored_and_baseline_locations(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        for d in (ws.data, ws.state / "baselines"):
            d.mkdir(exist_ok=True, mode=0o700)
            r = run("keygen", "--private", str(d / "k.pem"), "--public", str(ws.root / "k.pub"))
            assert r.exit_code == cli.EXIT_USAGE and "outside" in r.output
            assert not (d / "k.pem").exists()

    def test_keygen_never_overwrites(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        args = ["keygen", "--private", str(ws.root / "k.pem"), "--public", str(ws.root / "k.pub")]
        assert run(*args).exit_code == 0
        before = (ws.root / "k.pem").read_bytes()
        assert run(*args).exit_code == cli.EXIT_OPERATIONAL
        assert (ws.root / "k.pem").read_bytes() == before

    def test_passphrase_via_environment_only(self, ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
        env = {"FIM_KEY_PASSPHRASE": "s3cret"}
        r = run("keygen", "--private", str(ws.root / "e.pem"), "--public", str(ws.root / "e.pub"), env=env)
        assert "encrypted: true" in r.output
        assert b"ENCRYPTED" in (ws.root / "e.pem").read_bytes()
        assert signing.load_public(str(ws.root / "e.pub"))


class TestSubprocessEntryPoint:
    def test_module_invocation_and_exit_codes(self, ws: Workspace) -> None:
        env = {**os.environ, "FIM_CONFIG": str(ws.config_path)}
        cmd = [sys.executable, "-m", "fim.cli"]
        assert subprocess.run([*cmd, "version"], env=env, capture_output=True).returncode == 0
        assert subprocess.run([*cmd, "baseline", "create"], env=env, capture_output=True).returncode == 0
        (ws.data / "a.txt").write_text("x")
        p = subprocess.run([*cmd, "scan"], env=env, capture_output=True, text=True)
        assert p.returncode == 1 and "modified" in p.stdout
        assert subprocess.run([*cmd, "bogus"], env=env, capture_output=True).returncode == 2


def test_syslog_flag_requires_section(ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
    run("baseline", "create")
    assert run("scan", "--syslog").exit_code == cli.EXIT_USAGE


def test_syslog_delivery_failure_sets_exit_5(ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
    ws.config_path.write_text(ws.config_path.read_text() + f'[export.syslog]\naddress = "{ws.root}/nosock"\n')
    run("baseline", "create")
    r = run("scan", "--syslog")
    assert r.exit_code == 0  # clean scan => nothing to send
    (ws.data / "a.txt").write_text("changed")
    r = run("scan", "--syslog")
    assert r.exit_code == cli.EXIT_CHANGES  # findings take precedence...
    assert "syslog delivery" in r.output and "failed" in r.output  # ...but the failure is loud


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_fifo_in_tree_does_not_hang(ws: Workspace, run) -> None:  # type: ignore[no-untyped-def]
    os.mkfifo(ws.data / "pipe")
    assert run("baseline", "create").exit_code == 0
    assert run("scan").exit_code == 0
