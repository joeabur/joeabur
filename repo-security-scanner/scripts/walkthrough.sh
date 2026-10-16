#!/usr/bin/env bash
# Runs every command of docs/walkthrough.md in order, against bundled fixtures only.
# Default path needs Gitleaks + Semgrep (no network). Pass --with-trivy to include Trivy.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SCANNERS="gitleaks,semgrep"
[ "${1:-}" = "--with-trivy" ] && SCANNERS="gitleaks,semgrep,trivy"
W=walkthrough-output
rm -rf "$W"; mkdir -p "$W"
step() { printf '\n$'; printf ' %q' "$@"; printf '\n'; "$@"; rc=$?; echo "[exit code: $rc]"; }

echo "### Step 1 - install check"
step reposcan version
step reposcan doctor

echo; echo "### Step 2 - scan the bundled demo repository"
step reposcan scan sample-data/demo-repo --scanners "$SCANNERS" --output-dir "$W/exercise1"

echo; echo "### Step 3 - interpret findings"
step reposcan report show --input "$W/exercise1/reposcan-report.json"

echo; echo "### Step 4 - reports"
step reposcan scan sample-data/demo-repo --scanners "$SCANNERS" --format json,html,sarif --output-dir "$W/exercise2"
step python scripts/validate_sarif.py "$W/exercise2/reposcan.sarif"
ls -l "$W/exercise2"

echo; echo "### Step 5 - baseline"
cp -r sample-data/demo-repo "$W/work-repo"
EXPIRY="$(python3 -c 'import datetime;print(datetime.date.today()+datetime.timedelta(days=90))')"
step reposcan baseline create "$W/work-repo" --scanners "$SCANNERS" --owner team-appsec --reason "Legacy demo code, tracked in TICKET-1" --expires "$EXPIRY" --baseline-file "$W/baseline.json"
step reposcan baseline review "$W/baseline.json"
step reposcan scan "$W/work-repo" --scanners "$SCANNERS" --baseline "$W/baseline.json" --output-dir "$W/exercise3-pass"
cat >> "$W/work-repo/app/server.py" <<'PY'


def load_config(text: str):
    # NEW vulnerability introduced after the baseline was created.
    return eval(text)
PY
step reposcan scan "$W/work-repo" --scanners "$SCANNERS" --baseline "$W/baseline.json" --output-dir "$W/exercise3-fail"
step reposcan report show --input "$W/exercise3-fail/reposcan-report.json" --status new

echo; echo "### Step 6 - severity policy in CI"
step reposcan scan sample-data/demo-repo --scanners "$SCANNERS" --fail-on critical --output-dir "$W/exercise4-critical"
step reposcan scan sample-data/demo-repo --scanners "$SCANNERS" --fail-on none --output-dir "$W/exercise4-none"
step reposcan scan sample-data/clean-repo --scanners semgrep --config examples/configs/broken-remote-rules.toml --output-dir "$W/exercise4-failure"
