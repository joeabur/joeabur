from __future__ import annotations

import csv
import io
import json
import os
import re
import socket
import sys
import threading
from pathlib import Path

import pytest

from fim import integrity, reporting, service, signing
from fim.baseline import BaselineStore
from fim.config import SyslogConfig
from fim.errors import DependencyError, FimError, TrustError
from fim.models import Report
from fim.scanner import Scanner
from tests.conftest import Workspace


# ------------------------------------------------------------------ signing
@pytest.fixture
def keys(tmp_path: Path) -> tuple[str, str]:
    d = tmp_path / "keys"
    d.mkdir()
    priv, pub = str(d / "k.pem"), str(d / "k.pub")
    signing.generate_keypair(priv, pub)
    return priv, pub


class TestSigning:
    def test_roundtrip_and_permissions(self, keys: tuple[str, str]) -> None:
        priv, pub = keys
        assert (os.stat(priv).st_mode & 0o777) == 0o600
        text, kid = signing.sign_bytes(priv, b"payload")
        assert signing.verify_signature(pub, b"payload", text) == kid
        assert kid.startswith("sha256:") and len(kid) == 71

    def test_tampered_data_fails(self, keys: tuple[str, str]) -> None:
        priv, pub = keys
        text, _ = signing.sign_bytes(priv, b"payload")
        with pytest.raises(TrustError, match="does not match"):
            signing.verify_signature(pub, b"payload!", text)

    def test_wrong_key_fails(self, keys: tuple[str, str], tmp_path: Path) -> None:
        priv, _ = keys
        signing.generate_keypair(str(tmp_path / "o.pem"), str(tmp_path / "o.pub"))
        text, _ = signing.sign_bytes(priv, b"x")
        with pytest.raises(TrustError, match="trusted key"):
            signing.verify_signature(str(tmp_path / "o.pub"), b"x", text)

    @pytest.mark.parametrize(
        "text",
        ["", "garbage", "fim-signature-v1\nalgorithm: rsa\nkey-id: x\nsignature: AAAA\n",
         "fim-signature-v1\nalgorithm: ed25519\nkey-id: x\nsignature: !!!notb64\n"],
    )  # fmt: skip
    def test_malformed_signature_files(self, keys: tuple[str, str], text: str) -> None:
        with pytest.raises(TrustError):
            signing.verify_signature(keys[1], b"x", text)

    def test_signature_is_domain_separated(self, keys: tuple[str, str]) -> None:
        # A signature over the raw bytes (no FIM prefix) must not verify as a baseline signature.
        import base64

        from cryptography.hazmat.primitives import serialization

        priv, pub = keys
        key = serialization.load_pem_private_key(Path(priv).read_bytes(), password=None)
        _, kid = signing.load_public(pub)
        sig = base64.b64encode(key.sign(b"payload")).decode()  # type: ignore[union-attr]
        text = f"fim-signature-v1\nalgorithm: ed25519\nkey-id: {kid}\nsignature: {sig}\n"
        with pytest.raises(TrustError):
            signing.verify_signature(pub, b"payload", text)

    def test_never_overwrites_keys(self, keys: tuple[str, str], tmp_path: Path) -> None:
        priv, pub = keys
        with pytest.raises(FileExistsError):
            signing.generate_keypair(priv, str(tmp_path / "new.pub"))
        assert not (tmp_path / "new.pub").exists()
        before = Path(priv).read_bytes()
        with pytest.raises(FileExistsError):
            signing.generate_keypair(str(tmp_path / "new.pem"), pub)
        assert not (tmp_path / "new.pem").exists()  # no orphan private key
        assert Path(priv).read_bytes() == before

    def test_passphrase_protected_key(self, tmp_path: Path) -> None:
        priv, pub = str(tmp_path / "e.pem"), str(tmp_path / "e.pub")
        signing.generate_keypair(priv, pub, b"correct horse")
        assert b"ENCRYPTED" in Path(priv).read_bytes()
        text, _ = signing.sign_bytes(priv, b"d", b"correct horse")
        signing.verify_signature(pub, b"d", text)
        with pytest.raises(TrustError):
            signing.sign_bytes(priv, b"d", b"wrong")
        with pytest.raises(TrustError):
            signing.sign_bytes(priv, b"d", None)

    def test_group_readable_private_key_refused(self, keys: tuple[str, str]) -> None:
        os.chmod(keys[0], 0o640)
        with pytest.raises(TrustError, match="chmod 600"):
            signing.sign_bytes(keys[0], b"x")

    def test_missing_cryptography_gives_actionable_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives", None)
        with pytest.raises(DependencyError, match=r"fim-tool\[signing\]"):
            signing.generate_keypair("/nonexistent/a", "/nonexistent/b")


class TestSignedBaselineFlow:
    def _setup(self, ws: Workspace, keys: tuple[str, str]):  # type: ignore[no-untyped-def]
        cfg = ws.config(baseline={"public_key": keys[1]}) if False else None
        from tests.conftest import make_config

        cfg = make_config(ws, baseline={"public_key": keys[1]})
        store = service.store_for(cfg)
        signer = service.make_signer(cfg, keys[0], None)
        service.baseline_from_scan(
            store, cfg, Scanner(cfg.scan).scan(), action="create", reason="t", signer=signer
        )
        return cfg, store, signer

    def test_valid_signature_accepted(self, ws: Workspace, keys: tuple[str, str]) -> None:
        cfg, store, _ = self._setup(ws, keys)
        t = service.load_trusted(cfg, store)
        assert t.signature.startswith("verified (sha256:")

    def test_modified_baseline_fails_signature_even_with_recomputed_hash(
        self, ws: Workspace, keys: tuple[str, str]
    ) -> None:
        from fim.baseline import compute_content_hash

        cfg, store, _ = self._setup(ws, keys)
        p = store.path_for(1)
        doc = json.loads(p.read_text())
        doc["entries"][next(iter(doc["entries"]))]["mode"] = "0777"
        doc["content_sha256"] = compute_content_hash(doc)  # attacker fixes the self-hash
        p.write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")
        store.load()  # the self-hash alone is satisfied...
        with pytest.raises(TrustError, match="signature"):  # ...the signature is not
            service.load_trusted(cfg, store)

    def test_deleted_signature_rejected(self, ws: Workspace, keys: tuple[str, str]) -> None:
        cfg, store, _ = self._setup(ws, keys)
        store.sig_path_for(1).unlink()
        with pytest.raises(TrustError, match="missing"):
            service.load_trusted(cfg, store)

    def test_unsigned_commit_refused_when_key_configured(self, ws: Workspace, keys: tuple[str, str]) -> None:
        cfg, _, _ = self._setup(ws, keys)
        from fim.errors import ConfigError

        with pytest.raises(ConfigError, match="--sign-key"):
            service.require_signer_if_needed(cfg, None)

    def test_signing_key_must_match_trusted_public_key(
        self, ws: Workspace, keys: tuple[str, str], tmp_path: Path
    ) -> None:
        cfg, _, _ = self._setup(ws, keys)
        other = str(tmp_path / "other.pem")
        signing.generate_keypair(other, str(tmp_path / "other.pub"))
        with pytest.raises(TrustError, match="does not match"):
            service.make_signer(cfg, other, None)

    def test_signing_key_inside_baseline_dir_or_root_refused(
        self, ws: Workspace, keys: tuple[str, str]
    ) -> None:
        cfg, store, _ = self._setup(ws, keys)
        for d in (store.dir, ws.data):
            p = d / "k.pem"
            p.write_bytes(Path(keys[0]).read_bytes())
            p.chmod(0o600)
            with pytest.raises(TrustError, match="must not be stored"):
                service.make_signer(cfg, str(p), None)

    def test_key_rotation(self, ws: Workspace, keys: tuple[str, str], tmp_path: Path) -> None:
        from tests.conftest import make_config

        cfg, store, _ = self._setup(ws, keys)
        new_priv, new_pub = str(tmp_path / "n.pem"), str(tmp_path / "n.pub")
        signing.generate_keypair(new_priv, new_pub)
        cfg2 = make_config(ws, baseline={"public_key": new_pub})
        with pytest.raises(TrustError):  # old signature no longer trusted under the new key
            service.load_trusted(cfg2, store)
        sig, kid = service.make_signer(cfg2, new_priv, None)(store.load().raw)
        store.write_signature(1, sig, reason="rotate", key_id=kid)
        assert service.load_trusted(cfg2, store).signature.startswith("verified")
        assert store.verify_audit() == 2


# ------------------------------------------------------------------ reporting
@pytest.fixture
def sample_report(ws: Workspace) -> Report:
    cfg = ws.config()
    store = BaselineStore(cfg.baseline.dir)
    service.baseline_from_scan(store, cfg, Scanner(cfg.scan).scan(), action="create", reason="t", signer=None)
    (ws.data / "a.txt").write_text("changed")
    (ws.data / '=HYPERLINK("evil")').write_text("x")
    (ws.data / "sub" / "b.txt").unlink()
    trusted = service.load_trusted(cfg, store)
    report, _ = service.run_scan(cfg, trusted)
    return report


class TestExports:
    def test_json_roundtrips_through_schema(self, sample_report: Report) -> None:
        again = Report.model_validate_json(reporting.report_json(sample_report))
        assert again == sample_report

    def test_csv_columns_and_rows(self, sample_report: Report) -> None:
        rows = list(csv.reader(io.StringIO(reporting.events_csv(sample_report).decode())))
        assert rows[0] == reporting.CSV_EVENT_COLUMNS
        assert len(rows) == 1 + len(sample_report.events)
        assert all(len(r) == len(rows[0]) for r in rows)

    def test_csv_formula_injection_neutralised(self, sample_report: Report) -> None:
        rows = list(csv.DictReader(io.StringIO(reporting.events_csv(sample_report).decode())))
        evil = [r["path"] for r in rows if "HYPERLINK" in r["path"]]
        assert evil and all(p.startswith("'") or p.startswith("/") for p in evil)
        for r in rows:
            for v in r.values():
                assert not v.startswith(("=", "+", "-", "@"))

    def test_issues_csv(self, ws: Workspace) -> None:
        cfg = ws.config()
        cfg.scan.roots.append(str(ws.root / "ghost"))
        res = Scanner(cfg.scan).scan()
        assert not res.complete
        report = integrity.build_report(
            cfg, service.store_for(cfg) and _empty_baseline(cfg), res, [], scan_id="x"
        )
        data = reporting.issues_csv(report).decode()
        assert "root_missing" in data and data.splitlines()[0] == "scan_id,kind,path,detail"

    def test_text_report_flags_incomplete(self, ws: Workspace) -> None:
        cfg = ws.config()
        cfg.scan.roots.append(str(ws.root / "ghost"))
        res = Scanner(cfg.scan).scan()
        report = integrity.build_report(cfg, _empty_baseline(cfg), res, [], scan_id="x")
        text = reporting.render_text(report)
        assert "INCOMPLETE" in text and "root_missing" in text
        assert "CLEAN" not in text

    def test_write_output_refuses_overwrite_and_symlinks(self, tmp_path: Path) -> None:
        out = tmp_path / "r.json"
        reporting.write_output(out, b"1")
        assert (out.stat().st_mode & 0o777) == 0o600
        with pytest.raises(FimError, match="already exists"):
            reporting.write_output(out, b"2")
        reporting.write_output(out, b"3", overwrite=True)
        assert out.read_bytes() == b"3"
        link = tmp_path / "l.json"
        link.symlink_to(out)
        with pytest.raises(FimError, match="symlink"):
            reporting.write_output(link, b"x", overwrite=True)
        with pytest.raises(FimError, match="does not exist"):
            reporting.write_output(tmp_path / "nodir" / "x", b"x")


def _empty_baseline(cfg):  # type: ignore[no-untyped-def]
    from fim.baseline import compute_content_hash
    from fim.models import Baseline

    body = {
        "format": "fim-baseline", "schema_version": 1, "version": 1, "created_at": "x", "hostname": "h",
        "tool_version": "t", "roots": cfg.scan.roots, "exclude": [], "symlinks": "record", "complete": True,
        "issues": [], "prev_sha256": None, "entries": {},
    }  # fmt: skip
    body["content_sha256"] = compute_content_hash(body)
    return Baseline.model_validate(body)


RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) - (?P<msgid>\S+) \[fim@32473(?P<sd>(?: \w+=\"(?:[^\"\\]|\\.)*\")*)\] (?P<msg>.*)$"
)


class TestSyslogFormats:
    def test_rfc5424_structure(self, sample_report: Report) -> None:
        cfg = SyslogConfig()
        msgs = reporting.syslog_messages(sample_report, cfg)
        assert len(msgs) == len(sample_report.events)
        for m, e in zip(msgs, sample_report.events, strict=True):
            g = RFC5424_RE.match(m)
            assert g, m
            sev = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}[e.severity.value]
            assert int(g["pri"]) == 13 * 8 + sev
            assert g["msgid"] == e.event_type.value

    def test_rfc5424_escapes_structured_data(self, sample_report: Report) -> None:
        e = sample_report.events[0].model_copy(update={"path": '/x/"quote"]bracket\\slash'})
        m = reporting.format_rfc5424(e, "host", SyslogConfig())
        assert RFC5424_RE.match(m)
        assert 'path="/x/\\"quote\\"\\]bracket\\\\slash"' in m

    def test_cef_format_and_escaping(self, sample_report: Report) -> None:
        e = sample_report.events[0].model_copy(update={"path": "/x/a=b|c\nd"})
        m = reporting.format_cef(e, "host", "0.1.0")
        header = m.split("|")
        assert header[0] == "CEF:0" and header[1] == "FIM"
        assert "filePath=/x/a\\=b|c\\nd" in m
        assert "\n" not in m

    def test_min_severity_filter(self, sample_report: Report) -> None:
        cfg = SyslogConfig(min_severity="critical")
        assert reporting.syslog_messages(sample_report, cfg) == []

    def test_incomplete_scan_emits_message(self, ws: Workspace) -> None:
        cfg = ws.config()
        cfg.scan.roots.append(str(ws.root / "ghost"))
        res = Scanner(cfg.scan).scan()
        report = integrity.build_report(cfg, _empty_baseline(cfg), res, [], scan_id="x")
        msgs = reporting.syslog_messages(report, SyslogConfig())
        assert len(msgs) == 1 and "scan_incomplete" in msgs[0]


class TestSyslogDelivery:
    def test_udp(self, sample_report: Report) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(5)
        port = srv.getsockname()[1]
        msgs = reporting.syslog_messages(sample_report, SyslogConfig())
        reporting.send_syslog(msgs, f"udp://127.0.0.1:{port}")
        got = [srv.recv(65535).decode() for _ in msgs]
        srv.close()
        assert got == msgs

    def test_tcp_octet_counting(self, sample_report: Report) -> None:
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        buf = bytearray()

        def serve() -> None:
            c, _ = srv.accept()
            while chunk := c.recv(4096):
                buf.extend(chunk)
            c.close()

        t = threading.Thread(target=serve)
        t.start()
        msgs = reporting.syslog_messages(sample_report, SyslogConfig())
        reporting.send_syslog(msgs, f"tcp://127.0.0.1:{port}")
        t.join(5)
        srv.close()
        parsed, i = [], 0
        while i < len(buf):
            sp = buf.index(b" ", i)
            n = int(buf[i:sp])
            parsed.append(bytes(buf[sp + 1 : sp + 1 + n]).decode())
            i = sp + 1 + n
        assert parsed == msgs

    def test_unix_datagram(self, sample_report: Report, tmp_path: Path) -> None:
        path = str(tmp_path / "log.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        srv.bind(path)
        srv.settimeout(5)
        msgs = reporting.syslog_messages(sample_report, SyslogConfig())
        reporting.send_syslog(msgs, path)
        assert [srv.recv(65535).decode() for _ in msgs] == msgs
        srv.close()

    def test_delivery_failure_is_an_error_not_silence(self, tmp_path: Path) -> None:
        with pytest.raises(FimError, match="failed"):
            reporting.send_syslog(["<13>1 x"], str(tmp_path / "no-such.sock"))
        with pytest.raises(FimError, match="failed"):
            reporting.send_syslog(["<13>1 x"], "tcp://127.0.0.1:1")
