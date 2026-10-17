#!/usr/bin/env bash
# Shared helpers for the FIM helper scripts. Source this file; do not execute it.
# shellcheck shell=bash

if [[ -n "${FIM_COMMON_SH_LOADED:-}" ]]; then
    return 0
fi
FIM_COMMON_SH_LOADED=1

log()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit "${2:-1}"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# detect_family [os-release-file]
# Prints one of: debian | rhel | unknown. Uses ID and ID_LIKE from os-release(5).
detect_family() {
    local file="${1:-/etc/os-release}" id="" id_like=""
    [[ -r "$file" ]] || { echo unknown; return 0; }
    # Parse instead of sourcing: never execute content from a data file.
    id="$(sed -n 's/^ID=//p' "$file" | head -n1 | tr -d '"'"'")"
    id_like="$(sed -n 's/^ID_LIKE=//p' "$file" | head -n1 | tr -d '"'"'")"
    local token
    for token in $id $id_like; do
        case "$token" in
            debian|ubuntu) echo debian; return 0 ;;
            rhel|centos|rocky|almalinux|fedora|ol) echo rhel; return 0 ;;
            *) ;;
        esac
    done
    echo unknown
}

# python_ok <python-executable>: succeeds when it is CPython/PyPy >= 3.11.
python_ok() {
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null
}

# find_python: print the first suitable interpreter (>= 3.11) found on PATH.
find_python() {
    local cand
    for cand in "${FIM_PYTHON:-}" python3.13 python3.12 python3.11 python3; do
        [[ -n "$cand" ]] || continue
        if command -v "$cand" >/dev/null 2>&1 && python_ok "$cand"; then
            command -v "$cand"
            return 0
        fi
    done
    return 1
}

# python_install_hint <family>
python_install_hint() {
    case "$1" in
        debian) echo "sudo apt-get install -y python3 python3-venv   (Debian 12 and Ubuntu 24.04 ship Python >= 3.11; on Ubuntu 22.04 (Python 3.10) install python3.11 python3.11-venv, a 3.11.0 release candidate, or a newer interpreter, then set FIM_PYTHON)" ;;
        rhel)   echo "sudo dnf install -y python3.11   (RHEL/Rocky/Alma 9 ship 3.9 by default; install the python3.11 or python3.12 package)" ;;
        *)      echo "install CPython >= 3.11 with venv support from your distribution" ;;
    esac
}

# safe_remove_tree <dir> <marker-file-name> [expected-content]
# Deletes <dir> only if it is an absolute, non-symlink directory (not "/" or a bare top-level
# directory), contains the marker file, and (when given) the marker content matches exactly.
safe_remove_tree() {
    local dir="$1" marker="$2" expected="${3:-}"
    [[ "$dir" == /* ]] || { warn "refusing to remove non-absolute path: $dir"; return 1; }
    [[ "$dir" != "/" && "$dir" != "//" ]] || { warn "refusing to remove /"; return 1; }
    [[ "$(printf '%s' "$dir" | tr -cd '/' | wc -c)" -ge 2 ]] || { warn "refusing to remove top-level path: $dir"; return 1; }
    [[ -d "$dir" && ! -L "$dir" ]] || { warn "not a real directory: $dir"; return 1; }
    [[ -f "$dir/$marker" && ! -L "$dir/$marker" ]] || { warn "marker $marker missing in $dir; refusing to remove"; return 1; }
    if [[ -n "$expected" && "$(cat "$dir/$marker")" != "$expected" ]]; then
        warn "marker content mismatch in $dir; refusing to remove"
        return 1
    fi
    rm -rf -- "$dir"
}
