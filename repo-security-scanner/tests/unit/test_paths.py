from __future__ import annotations

from pathlib import Path

import pytest

from reposcan.errors import ConfigError
from reposcan.paths import (
    read_source_line,
    relative_to_root,
    summarize_scope,
    validate_file_arg,
    validate_image_ref,
    validate_output_dir,
    validate_target,
)


def test_validate_target_accepts_directory(tmp_path: Path) -> None:
    assert validate_target(str(tmp_path)) == tmp_path.resolve()


@pytest.mark.parametrize("bad", ["", "   ", "a\x00b", "x" * 5000, "/definitely/not/here"])
def test_validate_target_rejects_bad_input(bad: str) -> None:
    with pytest.raises(ConfigError):
        validate_target(bad)


def test_validate_target_refuses_filesystem_root() -> None:
    with pytest.raises(ConfigError, match="root"):
        validate_target("/")


def test_validate_target_resolves_symlinks_and_traversal(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    assert validate_target(str(tmp_path / "link" / ".." / "real")) == (tmp_path / "real").resolve()


def test_dash_prefixed_names_cannot_become_options(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "--config").mkdir()
    monkeypatch.chdir(tmp_path)
    # Resolution to an absolute path means the scanner never sees a leading dash.
    assert validate_target("--config").is_absolute()


def test_output_dir_rules(tmp_path: Path) -> None:
    _out, warnings = validate_output_dir(str(tmp_path / "out"), target=tmp_path)
    assert warnings and "inside the scan target" in warnings[0]
    _out, warnings = validate_output_dir(str(tmp_path.parent / "elsewhere-out"), target=tmp_path)
    assert not warnings
    file = tmp_path / "f"
    file.write_text("x")
    with pytest.raises(ConfigError):
        validate_output_dir(str(file), target=tmp_path)
    link = tmp_path / "ln"
    link.symlink_to(tmp_path)
    with pytest.raises(ConfigError, match="symbolic link"):
        validate_output_dir(str(link), target=tmp_path)


def test_validate_file_arg(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text("x" * 20)
    assert validate_file_arg(str(f), "config") == f.resolve()
    with pytest.raises(ConfigError, match="larger"):
        validate_file_arg(str(f), "config", max_bytes=10)
    with pytest.raises(ConfigError):
        validate_file_arg(str(tmp_path), "config")
    with pytest.raises(ConfigError, match="not found"):
        validate_file_arg(str(tmp_path / "nope"), "config")


@pytest.mark.parametrize(
    "ref", ["alpine:3.20", "ghcr.io/org/app@sha256:" + "a" * 64, "registry.local:5000/x/y:tag"]
)
def test_image_refs_accepted(ref: str) -> None:
    assert validate_image_ref(ref) == ref


@pytest.mark.parametrize("ref", ["--config=x", "-v", "a b", "a;b", "$(id)", "../x", "", "a\nb"])
def test_image_refs_rejected(ref: str) -> None:
    with pytest.raises(ConfigError):
        validate_image_ref(ref)


def test_relative_to_root(tmp_path: Path) -> None:
    assert relative_to_root(str(tmp_path / "a" / "b.py"), tmp_path) == "a/b.py"
    assert relative_to_root("a/b.py", tmp_path) == "a/b.py"
    assert relative_to_root("/etc/passwd", tmp_path) is None
    assert relative_to_root("../x", tmp_path) is None
    assert "\x1b" not in (relative_to_root("a/\x1b[31mred.py", tmp_path) or "")


def test_read_source_line_blocks_escape_via_symlink(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("TOP SECRET\n")
    (root / "ok.py").write_text("one\ntwo\n")
    (root / "evil.py").symlink_to(outside)
    assert read_source_line(root, "ok.py", 2) == "two"
    assert read_source_line(root, "evil.py", 1) is None
    assert read_source_line(root, "../secret.txt", 1) is None
    assert read_source_line(root, "ok.py", 99) is None


def test_scope_summary_does_not_follow_symlinks(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.md").write_text("yy")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "obj").write_text("ignored")
    (tmp_path / "loop").symlink_to(tmp_path)
    scope = summarize_scope(tmp_path)
    assert (scope.file_count, scope.total_bytes, scope.symlinks_skipped) == (2, 3, 1)
    assert scope.is_git_repository and scope.top_extensions == {".md": 1, ".py": 1}
