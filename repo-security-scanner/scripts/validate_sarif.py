#!/usr/bin/env python3
"""Validate a SARIF file against the official OASIS SARIF 2.1.0 JSON schema (offline).

python scripts/validate_sarif.py reposcan-output/reposcan.sarif
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

SCHEMA = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sarif-schema-2.1.0.json"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_sarif.py FILE.sarif", file=sys.stderr)
        return 2
    document = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(document), key=lambda e: list(e.path))
    if errors:
        for err in errors[:10]:
            print(f"invalid: {'/'.join(map(str, err.path))}: {err.message[:200]}", file=sys.stderr)
        return 1
    results = sum(len(run.get("results", [])) for run in document.get("runs", []))
    print(f"valid SARIF 2.1.0: {len(document.get('runs', []))} run(s), {results} result(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
