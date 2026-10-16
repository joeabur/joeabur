#!/usr/bin/env bash
# Scheduled scan wrapper (used by systemd/fim-scan.service, also fine from cron).
# Writes timestamped JSON + CSV reports (mode 0600) and propagates fim's exit code:
#   0 clean, 1 findings, 3 incomplete scan, 4 untrusted baseline, 5 export failure, 6 operational error
set -euo pipefail
umask 077

FIM_BIN="${FIM_BIN:-fim}"
FIM_CONFIG="${FIM_CONFIG:-/etc/fim/fim.toml}"
REPORT_DIR="${REPORT_DIR:-/var/lib/fim/reports}"
RETENTION_DAYS="${REPORT_RETENTION_DAYS:-30}"

[[ "$REPORT_DIR" == /* ]] || { echo "error: REPORT_DIR must be absolute" >&2; exit 2; }
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { echo "error: REPORT_RETENTION_DAYS must be a number" >&2; exit 2; }

mkdir -p -- "$REPORT_DIR"
chmod 0700 -- "$REPORT_DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
args=(--config "$FIM_CONFIG" scan --json "$REPORT_DIR/scan-$stamp.json" --csv "$REPORT_DIR/scan-$stamp.csv")
if [[ "${FIM_SYSLOG:-0}" == "1" ]]; then
    args+=(--syslog)
fi

rc=0
"$FIM_BIN" "${args[@]}" || rc=$?

# Prune old reports; only files this script creates (scan-*.json / scan-*.csv) in REPORT_DIR.
find "$REPORT_DIR" -maxdepth 1 -type f \( -name 'scan-*.json' -o -name 'scan-*.csv' \) \
    -mtime "+$RETENTION_DAYS" -delete

if command -v logger >/dev/null 2>&1; then
    logger -t fim-scan -p authpriv.notice "scan finished with exit code $rc (report: $REPORT_DIR/scan-$stamp.json)"
fi
exit "$rc"
