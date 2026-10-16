from __future__ import annotations

from pathlib import Path

import pytest

from reposcan.config import Config, load_config
from reposcan.errors import ConfigError


def write(tmp_path: Path, text: str) -> str:
    p = tmp_path / "reposcan.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_defaults() -> None:
    cfg = Config()
    assert cfg.policy.fail_on == "high"
    assert cfg.scanners.osv.enabled is False
    assert cfg.scan.version_policy == "enforce"
    assert cfg.scanners.semgrep.allow_remote_rules is False


def test_load_valid_config(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, '[policy]\nfail_on = "medium"\n[scan]\noffline = true\n'))
    assert cfg.policy.fail_on == "medium" and cfg.scan.offline and cfg.base_dir == tmp_path.resolve()


@pytest.mark.parametrize(
    "text",
    [
        "[policy\nbroken",
        '[policy]\nfail_on = "severe"\n',
        "[unknown]\nx = 1\n",
        "[scan]\ntimeout_seconds = 0\n",
        '[scan]\nenv_passthrough = ["--evil"]\n',
        '[[suppressions]]\nowner = "a"\nreason = "because"\n',
        '[[suppressions]]\nrule_id = "x"\nowner = ""\nreason = "because"\n',
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


def test_missing_config_file() -> None:
    with pytest.raises(ConfigError):
        load_config("/no/such/reposcan.toml")


def test_suppressions_parse(tmp_path: Path) -> None:
    cfg = load_config(
        write(
            tmp_path,
            '[[suppressions]]\nrule_id = "reposcan.python.weak-hash"\npath = "app/*.py"\n'
            'owner = "team-a"\nreason = "hash is used for cache keys"\nexpires = 2027-01-31\n',
        )
    )
    assert cfg.suppressions[0].expires.isoformat() == "2027-01-31"  # type: ignore[union-attr]
