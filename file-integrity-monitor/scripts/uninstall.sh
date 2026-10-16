#!/usr/bin/env bash
# Remove what install.sh created. Baselines and configuration are kept unless --purge-data.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'USAGE'
Usage: uninstall.sh [--prefix DIR] [--bin-dir DIR] [--systemd-dir DIR] [--dry-run]

Removes the virtualenv (only if it carries the installer's marker), the `fim` link (only if it
points into the prefix) and installed systemd units. Configuration and baselines are NEVER
removed by this script; delete them yourself once you are sure you no longer need the evidence.
USAGE
}

DRY_RUN=0
if [[ $EUID -eq 0 ]]; then PREFIX=/opt/fim BIN_DIR=/usr/local/bin; else PREFIX="$HOME/.local/share/fim" BIN_DIR="$HOME/.local/bin"; fi
SYSTEMD_DIR=""

while (($#)); do
    case "$1" in
        --prefix)      [[ $# -ge 2 ]] || die "--prefix needs a value" 2; PREFIX="$2"; shift 2 ;;
        --bin-dir)     [[ $# -ge 2 ]] || die "--bin-dir needs a value" 2; BIN_DIR="$2"; shift 2 ;;
        --systemd-dir) [[ $# -ge 2 ]] || die "--systemd-dir needs a value" 2; SYSTEMD_DIR="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown option: $1" 2 ;;
    esac
done

if [[ -L "$BIN_DIR/fim" && "$(readlink -- "$BIN_DIR/fim")" == "$PREFIX/bin/fim" ]]; then
    if ((DRY_RUN)); then log "+ rm $BIN_DIR/fim"; else rm -f -- "$BIN_DIR/fim"; fi
else
    log "Not removing $BIN_DIR/fim (absent or not pointing into $PREFIX)"
fi

if [[ -n "$SYSTEMD_DIR" ]]; then
    for unit in fim-scan.service fim-scan.timer fim-watch.service; do
        if [[ -f "$SYSTEMD_DIR/$unit" ]]; then
            if ((DRY_RUN)); then log "+ rm $SYSTEMD_DIR/$unit"; else rm -f -- "${SYSTEMD_DIR:?}/$unit"; fi
        fi
    done
fi

if ((DRY_RUN)); then
    log "+ remove $PREFIX (if marker present)"
elif [[ -e "$PREFIX" ]]; then
    safe_remove_tree "$PREFIX" .fim-install fim-install || die "left $PREFIX in place" 3
    log "Removed $PREFIX"
fi
log "Configuration and baselines were left untouched."
