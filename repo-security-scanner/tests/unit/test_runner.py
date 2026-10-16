from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from reposcan.errors import (
    CommandCancelledError,
    CommandTimeoutError,
    ExecutableNotFoundError,
    OutputLimitExceededError,
)
from reposcan.runner import build_env, read_bounded_file, resolve_executable, run_command


def py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def run(code: str, tmp_path: Path, **kw: object):  # type: ignore[no-untyped-def]
    params = {"cwd": tmp_path, "env": build_env(), "timeout": 10, "max_output_bytes": 100_000}
    params.update(kw)
    return run_command(py(code), **params)  # type: ignore[arg-type]


def test_captures_output_and_exit_code(tmp_path: Path) -> None:
    result = run("import sys; print('out'); sys.stderr.write('err'); sys.exit(7)", tmp_path)
    assert (result.returncode, result.stdout.strip(), result.stderr) == (7, "out", "err")


def test_no_shell_interpretation(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    result = run_command(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            f"x; touch {marker}; $(touch {marker})",
        ],
        cwd=tmp_path,
        env=build_env(),
        timeout=10,
        max_output_bytes=10_000,
    )
    assert not marker.exists()
    assert "touch" in result.stdout  # passed through verbatim as data


def test_timeout_kills_process(tmp_path: Path) -> None:
    started = time.monotonic()
    with pytest.raises(CommandTimeoutError):
        run("import time; time.sleep(30)", tmp_path, timeout=0.5)
    assert time.monotonic() - started < 10


def test_timeout_kills_child_processes(tmp_path: Path) -> None:
    pidfile = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(60)\n"
    )
    with pytest.raises(CommandTimeoutError):
        run(code, tmp_path, timeout=1.5)
    import os

    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    pytest.fail("grandchild process survived the timeout")


def test_output_limit_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(OutputLimitExceededError):
        run(
            "import sys\nwhile True:\n    sys.stdout.write('A' * 65536)\n    sys.stdout.flush()",
            tmp_path,
            max_output_bytes=100_000,
        )


def test_stderr_flood_is_bounded_too(tmp_path: Path) -> None:
    with pytest.raises(OutputLimitExceededError):
        run(
            "import sys\nwhile True:\n    sys.stderr.write('E' * 65536)\n    sys.stderr.flush()",
            tmp_path,
            max_output_bytes=100_000,
        )


def test_cancellation_stops_the_process(tmp_path: Path) -> None:
    cancel = threading.Event()
    threading.Timer(0.3, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(CommandCancelledError):
        run("import time; time.sleep(30)", tmp_path, cancel=cancel)
    assert time.monotonic() - started < 10


def test_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(ExecutableNotFoundError):
        run_command(
            ["definitely-not-installed-xyz"],
            cwd=tmp_path,
            env=build_env(),
            timeout=5,
            max_output_bytes=1000,
        )


def test_rejects_empty_and_nul_argv(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="argv"):
        run_command([], cwd=tmp_path, env={}, timeout=1, max_output_bytes=10)
    with pytest.raises(ValueError, match="NUL"):
        run_command(["echo", "a\x00b"], cwd=tmp_path, env={}, timeout=1, max_output_bytes=10)


def test_environment_is_allow_listed() -> None:
    parent = {
        "PATH": "/bin",
        "HOME": "/h",
        "GITHUB_TOKEN": "ghs_secret",
        "AWS_SECRET_ACCESS_KEY": "x",
        "HTTPS_PROXY": "http://p",
    }
    env = build_env(source=parent)
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["HTTPS_PROXY"] == "http://p" and env["NO_COLOR"] == "1"


def test_explicit_passthrough_is_honoured() -> None:
    env = build_env(["MY_VAR"], source={"PATH": "/bin", "MY_VAR": "1", "OTHER": "2"})
    assert env["MY_VAR"] == "1" and "OTHER" not in env


def test_child_does_not_inherit_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LEAKY_TOKEN", "should-not-be-seen")
    result = run("import os; print(os.environ.get('LEAKY_TOKEN', 'absent'))", tmp_path)
    assert result.stdout.strip() == "absent"


def test_resolve_executable_refuses_binaries_inside_target(tmp_path: Path) -> None:
    exe = tmp_path / "repo" / "tool"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    with pytest.raises(ExecutableNotFoundError, match="inside the scan target"):
        resolve_executable("tool", {"PATH": str(exe.parent)}, forbidden_root=exe.parent)


def test_resolve_executable_rejects_path_separators() -> None:
    with pytest.raises(ExecutableNotFoundError):
        resolve_executable("../evil", {"PATH": "/bin"})


def test_read_bounded_file_limits_and_symlinks(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("x" * 100)
    assert read_bounded_file(report, 100) == b"x" * 100
    with pytest.raises(OutputLimitExceededError):
        read_bounded_file(report, 99)
    link = tmp_path / "link.json"
    link.symlink_to(report)
    with pytest.raises(FileNotFoundError):
        read_bounded_file(link, 1000)
    with pytest.raises(FileNotFoundError):
        read_bounded_file(tmp_path / "missing.json", 10)
