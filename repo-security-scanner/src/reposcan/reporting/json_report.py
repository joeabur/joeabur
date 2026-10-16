"""Deterministic JSON report."""

from __future__ import annotations

import json

from ..schemas import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
