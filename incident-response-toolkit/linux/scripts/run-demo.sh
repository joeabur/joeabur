#!/usr/bin/env bash
# Fully synthetic end-to-end demo. No root, no network, no access to the live host's evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(mktemp -d "${TMPDIR:-/tmp}/linux-ir-demo.XXXXXX")"
trap 'echo "Demo output kept in: $OUT (delete it when done: rm -rf $OUT)"' EXIT
CASE=examples/synthetic-evidence/case-001
BASE=examples/synthetic-evidence/baseline

echo "== 1. Verify the synthetic evidence manifest"
python -m linux_ir verify-manifest --input "$CASE"
echo; echo "== 2. Scan with IOCs and baseline"
python -m linux_ir scan --input "$CASE" --iocs examples/iocs.json --baseline "$BASE" > "$OUT/scan.txt"
head -40 "$OUT/scan.txt"; echo "... (full output: $OUT/scan.txt)"
echo; echo "== 3. Generate reports"
python -m linux_ir report --input "$CASE" --iocs examples/iocs.json --baseline "$BASE" --output "$OUT/reports"
echo; echo "== 4. Compare with expected results"
python - "$OUT/reports/report.json" <<'PY'
import json, sys
rep = json.load(open(sys.argv[1]))
exp = json.load(open("examples/expected-results/scan-findings.json"))
got = len(rep["heuristic_findings"]) + len(rep["ioc_matches"])
print(f"findings in report: {got}; expected: {len(exp)}")
sys.exit(0 if got == len(exp) else 1)
PY
echo "Demo OK"
