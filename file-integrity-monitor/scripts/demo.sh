#!/usr/bin/env bash
# Self-contained, repeatable FIM demo.
#
# Creates its own temporary workspace with synthetic files, runs the whole baseline -> change ->
# detect -> authorised update cycle, and removes ONLY the workspace it created. It never scans or
# modifies anything outside that workspace.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'USAGE'
Usage: demo.sh [--keep] [--export DIR] [-h]

  --keep        do not delete the workspace afterwards (its path is printed)
  --export DIR  copy the generated JSON/CSV reports into DIR (must not exist yet)

Environment: FIM_BIN overrides the command used to run fim (default: fim, else python3 -m fim.cli).
USAGE
}

KEEP=0
EXPORT_DIR=""
while (($#)); do
    case "$1" in
        --keep)    KEEP=1; shift ;;
        --export)  [[ $# -ge 2 ]] || die "--export needs a directory" 2; EXPORT_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *)         usage >&2; die "unknown option: $1" 2 ;;
    esac
done

if [[ -n "$EXPORT_DIR" ]]; then
    [[ "$EXPORT_DIR" == /* ]] || EXPORT_DIR="$PWD/$EXPORT_DIR"
    [[ ! -e "$EXPORT_DIR" ]] || die "--export target already exists: $EXPORT_DIR" 2
fi

if [[ -n "${FIM_BIN:-}" ]]; then
    read -r -a FIM <<<"$FIM_BIN"
elif command -v fim >/dev/null 2>&1; then
    FIM=(fim)
else
    FIM=(python3 -m fim.cli)
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fim-demo.XXXXXX")"
TOKEN="fim-demo-$$-$RANDOM-$RANDOM"
printf '%s' "$TOKEN" >"$WORK/.fim-demo-marker"
cleanup() {
    local rc=$?
    if ((KEEP)); then
        log "Workspace kept at: $WORK"
        log "Remove it with: rm -rf -- '$WORK'"
    else
        # Only ever deletes the directory created above, and only if its marker still matches.
        case "$(basename -- "$WORK")" in
            fim-demo.*) safe_remove_tree "$WORK" .fim-demo-marker "$TOKEN" && log "Cleaned up $WORK" ;;
            *) warn "unexpected workspace name; not deleting" ;;
        esac
    fi
    exit "$rc"
}
trap cleanup EXIT

TARGET="$WORK/target"
STATE="$WORK/state"
REPORTS="$WORK/reports"
mkdir -p "$TARGET/conf" "$TARGET/bin" "$TARGET/cache" "$REPORTS"
chmod 0700 "$STATE" 2>/dev/null || mkdir -m 0700 "$STATE"

printf 'listen_port=8080\nlog_level=info\n' >"$TARGET/conf/app.conf"
printf 'users:\n  - alice\n  - bob\n' >"$TARGET/conf/users.yaml"
printf '#!/bin/sh\necho "hello from the demo"\n' >"$TARGET/bin/run.sh"
chmod 0755 "$TARGET/bin/run.sh"
printf 'volatile cache entry\n' >"$TARGET/cache/entry.tmp"

cat >"$WORK/fim.toml" <<TOML
[baseline]
dir = "$STATE/baselines"

[scan]
roots = ["$TARGET"]
exclude = ["$TARGET/cache/**"]

[policy]
alert_threshold = "medium"
TOML

run_fim() { "${FIM[@]}" --config "$WORK/fim.toml" "$@"; }
# Run a command that may legitimately exit non-zero and report the code.
expect_code() {
    local want="$1" rc=0
    shift
    "$@" || rc=$?
    log "  -> exit code $rc (expected $want)"
    [[ "$rc" -eq "$want" ]] || die "unexpected exit code $rc from: $*" 10
}

log "== Demo workspace: $WORK"
log "== 1. Validate configuration";   run_fim config check
log "== 2. Create the baseline";      run_fim baseline create --reason "demo baseline"
log "== 3. Scan: nothing changed";    expect_code 0 run_fim scan

log "== 4. Simulate an incident: add, modify, delete, chmod, and touch an excluded file"
printf 'backdoor\n' >"$TARGET/bin/.hidden.sh"
printf 'listen_port=9999\nlog_level=debug\n' >"$TARGET/conf/app.conf"
rm -- "$TARGET/conf/users.yaml"
chmod 0777 "$TARGET/bin/run.sh"
printf 'excluded churn\n' >>"$TARGET/cache/entry.tmp"

log "== 5. Scan: findings expected (exit 1) and exported"
expect_code 1 run_fim scan --json "$REPORTS/report.json" --csv "$REPORTS/report.csv"

log "== 6. Convert the saved JSON report to other formats"
run_fim report convert "$REPORTS/report.json" --format cef --output "$REPORTS/report.cef"
run_fim report convert "$REPORTS/report.json" --format rfc5424 --output "$REPORTS/report.syslog"
log "   $(wc -l <"$REPORTS/report.cef") CEF line(s), $(wc -l <"$REPORTS/report.syslog") RFC 5424 line(s)"

log "== 7. Authorised baseline update (explicit reason + confirmation flag)"
run_fim baseline update --reason "demo: accepted the simulated changes" --yes
log "== 8. Scan again: clean";        expect_code 0 run_fim scan
log "== 9. Verify baseline integrity and the audit trail"; run_fim baseline verify; run_fim audit show

if [[ -n "$EXPORT_DIR" ]]; then
    mkdir -p -- "$EXPORT_DIR"
    cp -- "$REPORTS"/report.* "$EXPORT_DIR"/
    log "Reports copied to $EXPORT_DIR"
fi
log "== Demo finished successfully."
