#!/usr/bin/env bash
# Regenerate sample-data/ from a REAL demo run. The temporary workspace path is rewritten to the
# stable placeholder /tmp/fim-demo so the files are readable; everything else is untouched output.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
OUT="$REPO_DIR/sample-data"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/fim-samples.XXXXXX")"
trap 'rm -rf -- "${TMP:?}"' EXIT

"$SCRIPT_DIR/demo.sh" --keep --export "$TMP/reports" >"$TMP/demo.log"
WORKSPACE="$(sed -n 's/^Workspace kept at: //p' "$TMP/demo.log")"
[[ -d "$WORKSPACE" && "$(basename -- "$WORKSPACE")" == fim-demo.* ]] || { echo "demo workspace not found" >&2; exit 1; }

mkdir -p "$OUT"
for f in report.json report.csv report.cef report.syslog; do
    sed "s#$WORKSPACE#/tmp/fim-demo#g" "$TMP/reports/$f" >"$OUT/sample-$f"
done
sed "s#$WORKSPACE#/tmp/fim-demo#g" "$TMP/reports/report.issues.csv" >"$OUT/sample-report.issues.csv" 2>/dev/null || true
sed -e "s#$WORKSPACE#/tmp/fim-demo#g" "$WORKSPACE/fim.toml" >"$OUT/sample-fim.toml"
rm -rf -- "${WORKSPACE:?}"
echo "samples written to $OUT"
