"""Read-only integration tests against a real Mac. Skipped on every other OS."""

import os
import sys

import pytest

from mac_ir.collectors import inventory, processes
from mac_ir.config import load_config, redaction_patterns
from mac_ir.context import Context
from mac_ir.utils.redact import Redactor

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")


def live_ctx():
    cfg = load_config()
    return Context(config=cfg, redactor=Redactor(redaction_patterns(cfg), True))


def test_live_inventory_has_version_and_build():
    host = inventory.collect(live_ctx()).records[0]
    assert host["kind"] == "host" and host["product_version"] and host["build"] and host["architecture"]


def test_live_processes_include_self():
    res = processes.collect(live_ctx())
    assert any(r["pid"] == os.getpid() for r in res.records)
