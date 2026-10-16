#!/usr/bin/env bash
# Demonstration of the three distinguishable outcomes, using only bundled fixtures.
#
#   clean scan        -> exit 0
#   finding scan      -> exit 1  (policy failure on new findings)
#   scanner failure   -> exit 3  (incomplete results; never reported as "clean")
#
# Default path: Gitleaks + Semgrep only. No network access, no external services.
# Optional:     --with-trivy   adds Trivy (downloads its vulnerability DB on first use).
#
# Usage: scripts/demo.sh [--with-trivy] [--keep]
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/demo-output"
SCANNERS="gitleaks,semgrep"
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --with-trivy) SCANNERS="gitleaks,semgrep,trivy" ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if command -v reposcan >/dev/null 2>&1; then
  RS=(reposcan)
elif [ -x "$ROOT/.venv/bin/reposcan" ]; then
  RS=("$ROOT/.venv/bin/reposcan")
else
  RS=(python3 -m reposcan)
fi

status=0
expect() { # expect <label> <wanted exit> <actual exit>
  if [ "$3" -eq "$2" ]; then
    printf '  OK   %-22s exit %s (expected %s)\n' "$1" "$3" "$2"
  else
    printf '  FAIL %-22s exit %s (expected %s)\n' "$1" "$3" "$2"
    status=1
  fi
}

rm -rf "$OUT"
mkdir -p "$OUT"

echo "== 0. scanner discovery"
"${RS[@]}" doctor
echo

echo "== 1. clean repository"
"${RS[@]}" scan "$ROOT/sample-data/clean-repo" --scanners "$SCANNERS" --output-dir "$OUT/clean"
clean=$?
echo

echo "== 2. intentionally vulnerable repository"
"${RS[@]}" scan "$ROOT/sample-data/demo-repo" --scanners "$SCANNERS" --output-dir "$OUT/findings"
findings=$?
echo

echo "== 3. scanner failure (remote Semgrep rules are refused by default)"
"${RS[@]}" scan "$ROOT/sample-data/clean-repo" --scanners semgrep \
  --config "$ROOT/examples/configs/broken-remote-rules.toml" --output-dir "$OUT/failure"
failure=$?
echo

echo "== summary"
expect "clean repo" 0 "$clean"
expect "vulnerable repo" 1 "$findings"
expect "scanner failure" 3 "$failure"
echo "reports: $OUT"

if [ "$KEEP" -eq 0 ]; then
  echo "(run scripts/cleanup.sh to remove generated files)"
fi
exit "$status"
