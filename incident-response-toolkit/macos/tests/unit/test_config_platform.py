import pytest

from mac_ir.config import ConfigError, load_config
from mac_ir.platform_info import doctor_checks


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


def test_predicate_validation(tmp_path):
    for bad in ("logs: {predicate: ''}", 'logs: {predicate: "a\\nb"}', "logs: {predicate: " + repr("x" * 600) + "}"):
        with pytest.raises(ConfigError):
            load_config(write(tmp_path, bad))
    assert "sshd" in load_config()["logs"]["predicate"]


def test_ioc_paths_case_insensitive_by_default_on_macos():
    assert load_config()["ioc"]["case_insensitive_paths"] is True


def test_doctor_unsupported_os_and_missing_tools():
    info = {
        "is_macos": False,
        "system": "Linux",
        "pretty_name": None,
        "architecture": "x86_64",
        "architecture_supported": True,
        "product_version": None,
        "version_supported": False,
        "is_root": False,
        "tools": {"lsof": None, "ps": "/bin/ps"},
    }
    status = {c[1]: c[0] for c in doctor_checks(info)}
    assert status["operating system"] == "FAIL" and status["tool:lsof"] == "WARN" and status["tool:ps"] == "OK"


def test_doctor_old_macos_and_root():
    info = {
        "is_macos": True,
        "system": "Darwin",
        "pretty_name": "macOS 10.15",
        "architecture": "arm64",
        "architecture_supported": True,
        "product_version": "10.15",
        "version_supported": False,
        "is_root": True,
        "tools": {},
    }
    status = {c[1]: c[0] for c in doctor_checks(info)}
    assert status["macOS version"] == "WARN" and status["privileges"] == "WARN" and status["full disk access"] == "OK"


def test_default_redaction_patterns_cover_common_secret_shapes():
    from mac_ir.config import DEFAULT_REDACTION_PATTERNS
    from mac_ir.utils.redact import Redactor

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
