from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fim.config import load_config, parse_config
from fim.errors import ConfigError
from fim.pathutil import glob_to_regex, is_within, matches_any, validate_abs_path, validate_glob


class TestPaths:
    @pytest.mark.parametrize("bad", ["", "relative/path", "/etc/../root", "/a/\x00b", "../x"])
    def test_rejects_unsafe_paths(self, bad: str) -> None:
        with pytest.raises(ConfigError):
            validate_abs_path(bad)

    def test_normalises(self) -> None:
        assert validate_abs_path("/etc//ssh/") == "/etc/ssh"
        assert validate_abs_path("/") == "/"

    def test_is_within_is_not_prefix_match(self) -> None:
        assert is_within("/etc/ssh", "/etc")
        assert is_within("/etc", "/etc")
        assert not is_within("/etcetera", "/etc")
        assert is_within("/anything", "/")

    def test_glob_semantics(self) -> None:
        assert matches_any("/var/log/syslog", ["/var/log/**"])
        assert matches_any("/var/log/a/b/c", ["/var/log/**"])
        assert not matches_any("/var/logs/x", ["/var/log/**"])
        assert matches_any("/etc/a.bak", ["/etc/*.bak"])
        assert not matches_any("/etc/sub/a.bak", ["/etc/*.bak"])
        assert matches_any("/etc/sub/a.bak", ["/etc/**/*.bak"])
        assert matches_any("/etc/a.bak", ["/etc/**/*.bak"])  # '**/' may match nothing
        assert matches_any("/a/b", ["/a/?"])
        assert not matches_any("/a/bc", ["/a/?"])
        assert matches_any("/a/bc", ["/a/b?"])

    def test_directory_pruning_pattern(self) -> None:
        assert matches_any("/var/log", ["/var/log/**"], is_dir=True)
        assert not matches_any("/var/log", ["/var/log/**"], is_dir=False)

    @pytest.mark.parametrize("bad", ["relative/*", "/a/../b/*", "/a/\x00"])
    def test_validate_glob_rejects(self, bad: str) -> None:
        with pytest.raises(ConfigError):
            validate_glob(bad)

    @given(
        st.text(
            alphabet=st.characters(blacklist_characters="*?\x00", blacklist_categories=("Cs",)), min_size=1
        )
    )
    def test_literal_glob_matches_only_itself(self, name: str) -> None:
        path = "/" + name.replace("/", "_")
        assert glob_to_regex(path).fullmatch(path)
        assert not glob_to_regex(path).fullmatch(path + "x")

    @given(st.text(alphabet="abc/", max_size=12))
    def test_single_star_never_crosses_slash(self, tail: str) -> None:
        assert bool(glob_to_regex("/r/*").fullmatch("/r/" + tail)) == ("/" not in tail)


GOOD = {"baseline": {"dir": "/var/lib/fim-x"}, "scan": {"roots": ["/opt/app"]}}


class TestConfig:
    def test_valid_minimal(self) -> None:
        cfg = parse_config(GOOD)
        assert cfg.scan.symlinks == "record"
        assert cfg.scan.one_file_system is True
        assert cfg.policy.alert_threshold.value == "medium"

    def test_unknown_keys_rejected(self) -> None:
        with pytest.raises(ConfigError, match="Extra inputs"):
            parse_config({**GOOD, "typo": 1})
        with pytest.raises(ConfigError):
            parse_config({"baseline": GOOD["baseline"], "scan": {"roots": ["/opt"], "recursive": True}})

    @pytest.mark.parametrize(
        "scan",
        [
            {"roots": []},
            {"roots": ["relative"]},
            {"roots": ["/a/../b"]},
            {"roots": ["/opt"], "symlinks": "sometimes"},
            {"roots": ["/opt"], "exclude": ["not-absolute/*"]},
            {"roots": ["/opt"], "max_files": 0},
            {"roots": ["/opt"], "chunk_size": 1},
        ],
    )
    def test_bad_scan_sections(self, scan: dict) -> None:
        with pytest.raises(ConfigError):
            parse_config({"baseline": GOOD["baseline"], "scan": scan})

    def test_baseline_inside_root_rejected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        root = tmp_path / "mon"
        root.mkdir()
        with pytest.raises(ConfigError, match="overlaps"):
            parse_config({"baseline": {"dir": str(root / "b")}, "scan": {"roots": [str(root)]}})

    def test_root_inside_baseline_rejected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(ConfigError, match="overlaps"):
            parse_config({"baseline": {"dir": str(tmp_path)}, "scan": {"roots": [str(tmp_path / "x")]}})

    def test_symlinked_baseline_dir_into_root_rejected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        root = tmp_path / "mon"
        root.mkdir()
        (tmp_path / "link").symlink_to(root)
        with pytest.raises(ConfigError, match="overlaps"):
            parse_config({"baseline": {"dir": str(tmp_path / "link")}, "scan": {"roots": [str(root)]}})

    def test_rules_and_severity_override(self) -> None:
        cfg = parse_config(
            {
                **GOOD,
                "policy": {
                    "alert_threshold": "high",
                    "severities": {"added": "low"},
                    "rules": [{"name": "ssh", "paths": ["/etc/ssh/**"], "severity": "critical"}],
                },
            }
        )
        assert cfg.severity_for(cfg.policy.rules[0].events[0]).value in {"low", "high", "medium", "info"}
        assert cfg.policy.rules[0].severity.value == "critical"

    def test_bad_severity_and_event_names(self) -> None:
        with pytest.raises(ConfigError):
            parse_config({**GOOD, "policy": {"alert_threshold": "urgent"}})
        with pytest.raises(ConfigError):
            parse_config({**GOOD, "policy": {"severities": {"exploded": "low"}}})

    @pytest.mark.parametrize(
        "addr,ok",
        [
            ("/dev/log", True),
            ("udp://siem.example:514", True),
            ("tcp://10.0.0.1:6514", True),
            ("udp://siem.example", False),
            ("http://x:1", False),
            ("relative/sock", False),
        ],
    )
    def test_syslog_address(self, addr: str, ok: bool) -> None:
        data = {**GOOD, "export": {"syslog": {"address": addr}}}
        if ok:
            parse_config(data)
        else:
            with pytest.raises(ConfigError):
                parse_config(data)

    def test_load_malformed_toml(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        p = tmp_path / "bad.toml"
        p.write_text("[baseline\ndir = ")
        with pytest.raises(ConfigError, match="TOML"):
            load_config(p)

    def test_load_missing_and_binary(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(ConfigError, match="cannot read"):
            load_config(tmp_path / "nope.toml")
        p = tmp_path / "bin.toml"
        p.write_bytes(b"\xff\xfe\x00")
        with pytest.raises(ConfigError):
            load_config(p)
