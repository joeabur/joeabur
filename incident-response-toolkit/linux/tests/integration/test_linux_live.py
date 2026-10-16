"""Integration tests that touch the real host (read-only). Skipped on non-Linux systems."""

import sys

import pytest

from linux_ir.collectors import inventory, processes
from linux_ir.config import load_config, redaction_patterns
from linux_ir.context import Context
from linux_ir.utils.redact import Redactor

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")


def live_ctx():
    cfg = load_config()
    return Context(config=cfg, redactor=Redactor(redaction_patterns(cfg), True))


def test_live_inventory():
    res = inventory.collect(live_ctx())
    host = res.records[0]
    assert host["kind"] == "host" and host["system"] == "Linux" and host["architecture"]


def test_live_processes_include_self():
    import os

    res = processes.collect(live_ctx())
    me = [r for r in res.records if r["pid"] == os.getpid()]
    assert me and me[0]["exe"]
