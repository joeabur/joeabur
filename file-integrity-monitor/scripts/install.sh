#!/usr/bin/env bash
# Install FIM into an isolated virtual environment.
#
# Supported: Ubuntu/Debian and RHEL-compatible (RHEL, Rocky, AlmaLinux, CentOS Stream, Fedora).
# Dependencies are installed from requirements.lock with hash checking (pip --require-hashes).
# Existing configuration and baselines are never overwritten.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'USAGE'
Usage: install.sh [options]

  --prefix DIR        virtualenv location        (default: /opt/fim as root, ~/.local/share/fim otherwise)
  --bin-dir DIR       where to link the `fim` command (default: /usr/local/bin as root, ~/.local/bin)
  --etc-dir DIR       configuration directory    (default: /etc/fim as root, ~/.config/fim)
  --state-dir DIR     baseline/report storage    (default: /var/lib/fim as root, ~/.local/state/fim)
  --systemd-dir DIR   install systemd units here (default: not installed; /etc/systemd/system with --with-systemd)
  --with-systemd      also install the units from systemd/ (never enables or starts them)
  --no-extras         skip the optional signing/watch dependencies
  --dry-run           print what would be done without changing anything
  -h, --help          show this help

Environment: FIM_PYTHON selects the interpreter (must be >= 3.11).
USAGE
}

DRY_RUN=0
WITH_SYSTEMD=0
EXTRAS=1
PREFIX="" BIN_DIR="" ETC_DIR="" STATE_DIR="" SYSTEMD_DIR=""

while (($#)); do
    case "$1" in
        --prefix)      [[ $# -ge 2 ]] || die "--prefix needs a value" 2; PREFIX="$2"; shift 2 ;;
        --bin-dir)     [[ $# -ge 2 ]] || die "--bin-dir needs a value" 2; BIN_DIR="$2"; shift 2 ;;
        --etc-dir)     [[ $# -ge 2 ]] || die "--etc-dir needs a value" 2; ETC_DIR="$2"; shift 2 ;;
        --state-dir)   [[ $# -ge 2 ]] || die "--state-dir needs a value" 2; STATE_DIR="$2"; shift 2 ;;
        --systemd-dir) [[ $# -ge 2 ]] || die "--systemd-dir needs a value" 2; SYSTEMD_DIR="$2"; shift 2 ;;
        --with-systemd) WITH_SYSTEMD=1; shift ;;
        --no-extras)   EXTRAS=0; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown option: $1" 2 ;;
    esac
done

if [[ $EUID -eq 0 ]]; then
    : "${PREFIX:=/opt/fim}" "${BIN_DIR:=/usr/local/bin}" "${ETC_DIR:=/etc/fim}" "${STATE_DIR:=/var/lib/fim}"
else
    : "${PREFIX:=$HOME/.local/share/fim}" "${BIN_DIR:=$HOME/.local/bin}" "${ETC_DIR:=$HOME/.config/fim}" "${STATE_DIR:=$HOME/.local/state/fim}"
fi
if ((WITH_SYSTEMD)) && [[ -z "$SYSTEMD_DIR" ]]; then
    SYSTEMD_DIR=/etc/systemd/system
fi

for p in "$PREFIX" "$BIN_DIR" "$ETC_DIR" "$STATE_DIR" ${SYSTEMD_DIR:+"$SYSTEMD_DIR"}; do
    [[ "$p" == /* ]] || die "paths must be absolute: $p" 2
    case "/$p/" in */../*) die "paths must not contain '..': $p" 2 ;; *) ;; esac
done

run() {
    if ((DRY_RUN)); then
        printf '+ %s\n' "$*"
    else
        "$@"
    fi
}

FAMILY="$(detect_family /etc/os-release)"
log "Detected distribution family: $FAMILY"

if PYTHON="$(find_python)"; then
    log "Using Python: $PYTHON ($("$PYTHON" -c 'import sys; print(sys.version.split()[0])'))"
elif ((DRY_RUN)); then
    PYTHON=python3
    warn "no Python >= 3.11 found; a real install would stop here. $(python_install_hint "$FAMILY")"
else
    die "Python >= 3.11 is required. $(python_install_hint "$FAMILY")"
fi

if ! ((DRY_RUN)); then
    "$PYTHON" -c 'import venv, ensurepip' 2>/dev/null \
        || die "the venv/ensurepip module is missing. $(python_install_hint "$FAMILY")"
fi

if [[ -e "$PREFIX" && ! -f "$PREFIX/.fim-install" ]] && [[ -n "$(ls -A "$PREFIX" 2>/dev/null || true)" ]]; then
    die "$PREFIX exists and was not created by this installer; choose another --prefix" 3
fi

run mkdir -p -- "$PREFIX" "$BIN_DIR"
run "$PYTHON" -m venv "$PREFIX"
if ((EXTRAS)); then
    run "$PREFIX/bin/pip" install --quiet --disable-pip-version-check --require-hashes -r "$REPO_DIR/requirements.lock"
else
    warn "--no-extras: signing and filesystem watching will be unavailable"
    run "$PREFIX/bin/pip" install --quiet --disable-pip-version-check "pydantic>=2.6,<3" "typer>=0.12,<1"
fi
run "$PREFIX/bin/pip" install --quiet --disable-pip-version-check --no-deps "$REPO_DIR"
if ! ((DRY_RUN)); then
    printf 'fim-install\n' >"$PREFIX/.fim-install"
else
    printf '+ write marker %s/.fim-install\n' "$PREFIX"
fi
run ln -sfn -- "$PREFIX/bin/fim" "$BIN_DIR/fim"

# Configuration: create the directory, never overwrite an existing file.
run mkdir -p -- "$ETC_DIR"
run chmod 0750 -- "$ETC_DIR"
if [[ -e "$ETC_DIR/fim.toml" ]]; then
    log "Keeping existing $ETC_DIR/fim.toml"
else
    run install -m 0640 -- "$REPO_DIR/config/fim.example.toml" "$ETC_DIR/fim.toml"
    log "Installed example configuration at $ETC_DIR/fim.toml (review it before creating a baseline)"
fi

# Baseline/report storage: private to the installing user.
run mkdir -p -- "$STATE_DIR"
run chmod 0700 -- "$STATE_DIR"

if ((WITH_SYSTEMD)); then
    run mkdir -p -- "$SYSTEMD_DIR"
    for unit in "$REPO_DIR"/systemd/*.service "$REPO_DIR"/systemd/*.timer; do
        run install -m 0644 -- "$unit" "$SYSTEMD_DIR/$(basename -- "$unit")"
    done
    run install -m 0755 -- "$REPO_DIR/scripts/run-scan.sh" "$PREFIX/bin/fim-run-scan"
    log "systemd units installed but NOT enabled. After creating a baseline:"
    log "  systemctl daemon-reload && systemctl enable --now fim-scan.timer"
fi

if ((DRY_RUN)); then
    log "Dry run complete: nothing was changed."
else
    log "Installed. Verify with: $BIN_DIR/fim version"
    log "Next: edit $ETC_DIR/fim.toml, then: fim -c $ETC_DIR/fim.toml baseline create"
fi
