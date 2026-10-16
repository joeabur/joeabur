#!/usr/bin/env bash
# Create a virtual environment and install the toolkit with development dependencies.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "Python 3.11+ is required (3.12 recommended)." >&2; exit 1; }
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -c requirements/constraints.txt -e ".[dev]"
echo "Done. Activate with: source .venv/bin/activate"
