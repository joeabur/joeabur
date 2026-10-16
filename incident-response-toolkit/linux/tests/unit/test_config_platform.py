import pytest

from linux_ir.config import ConfigError, load_config
from linux_ir.platform_info import doctor_checks


def write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return p


def test_defaults_load():
    cfg = load_config()
    assert cfg["profiles"]["basic"]["deep"] is False and "files" in cfg["profiles"]["extended"]["collectors"]


def test_override_and_invalid(tmp_path):
    assert load_config(write(tmp_path, "logs: {window_hours: 6}"))["logs"]["window_hours"] == 6
    for bad in (
        "nonsense: 1",
        "limits: {nope: 1}",
        "limits: {max_processes: -5}",
        "limits: {max_processes: true}",
        "logs: {window_hours: 99999}",
        "redaction: {extra_patterns: [{pattern: '['}]}",
        "- list",
        "limits: 3",
        "profiles: {x: {collectors: [bogus]}}",
        "profiles: {x: {collectors: []}}",
        "{bad yaml",
    ):
        with pytest.raises(ConfigError):
            load_config(write(tmp_path, bad))
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")


def test_custom_profile(tmp_path):
    cfg = load_config(write(tmp_path, "profiles: {auth: {collectors: [logs], deep: false}}"))
    assert cfg["profiles"]["auth"]["collectors"] == ["logs"]


def test_doctor_non_linux_and_missing_tools():
    info = {
        "is_linux": False,
        "system": "Darwin",
        "pretty_name": None,
        "architecture": "x86_64",
        "architecture_supported": True,
        "init": {"name": "launchd", "systemd": False},
        "is_root": False,
        "container": "docker",
        "tools": {"ss": None, "ip": "/sbin/ip"},
    }
    status = {c[1]: c[0] for c in doctor_checks(info)}
    assert status["operating system"] == "FAIL" and status["tool:ss"] == "WARN" and status["tool:ip"] == "OK"
    assert status["container"] == "WARN" and status["init system"] == "WARN"


def test_default_redaction_patterns_cover_common_secret_shapes():
    from linux_ir.config import DEFAULT_REDACTION_PATTERNS
    from linux_ir.utils.redact import Redactor

    r = Redactor(DEFAULT_REDACTION_PATTERNS)
    secrets = {
        "tool --password=hunter2": "hunter2",
        "tool -password hunter2": "hunter2",
        "curl https://user:s3cret@host/x": "s3cret",
        "Authorization: Bearer abcdefghijklmnop": "abcdefghijklmnop",
        "Authorization: Basic dXNlcjpwYXNz": "dXNlcjpwYXNz",
        "key AKIAABCDEFGHIJKLMNOP here": "AKIAABCDEFGHIJKLMNOP",
        "api_key=abc123": "abc123",
    }
    for text, secret in secrets.items():
        assert secret not in r.text(text), text
    assert r.text("ls -l /tmp") == "ls -l /tmp"
