"""Write the JSON Schema of the report format to docs/schemas/report.schema.json.

Usage: python scripts/generate_schema.py [--check]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fim.models import Report

TARGET = Path(__file__).resolve().parent.parent / "docs" / "schemas" / "report.schema.json"


def render() -> str:
    return json.dumps(Report.model_json_schema(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        sys.exit(0 if TARGET.read_text() == text else "report.schema.json is out of date")
    TARGET.write_text(text)
    print(f"wrote {TARGET}")
