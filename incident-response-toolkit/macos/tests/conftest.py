import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

from rootfs_builder import HOME, NOW, build_rootfs, fake_runner  # noqa: E402

from mac_ir.config import load_config, redaction_patterns  # noqa: E402
from mac_ir.context import Context  # noqa: E402
from mac_ir.utils.redact import Redactor  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "examples"


@pytest.fixture()
def cfg():
    return load_config()


@pytest.fixture()
def rootfs(tmp_path):
    return build_rootfs(tmp_path / "rootfs")


@pytest.fixture()
def make_ctx(cfg, rootfs):
    def _make(**kw):
        base = dict(
            config=cfg,
            redactor=Redactor(redaction_patterns(cfg), True),
            deep=True,
            root=rootfs,
            runner=fake_runner,
            now=NOW,
            home=rootfs / HOME,
            hostname="synthetic-mac",
        )
        base.update(kw)
        return Context(**base)

    return _make


@pytest.fixture()
def ctx(make_ctx):
    return make_ctx()
