#!/usr/bin/env python3
"""Generate docs/report-schema.json from the Pydantic model.

python scripts/generate_schema.py          # write the file
python scripts/generate_schema.py --check  # exit 1 if the committed file is stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from reposcan.schemas import ScanResult  # noqa: E402

TARGET = ROOT / "docs" / "report-schema.json"


def render() -> str:
    schema = ScanResult.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "reposcan JSON report"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != text:
            print("docs/report-schema.json is stale; run scripts/generate_schema.py", file=sys.stderr)
            return 1
        print("report schema is up to date")
        return 0
    TARGET.write_text(text)
    print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
