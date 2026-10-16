# Getting started

## Prerequisites

- macOS 12–15 (Apple silicon or Intel) for live collection; any OS for the synthetic demo, analysis and tests.
- Python 3.11+ (3.12 recommended; `brew install python@3.12` or python.org), `git`.
- No administrator rights, Full Disk Access, or network access are needed (pip needs network once).

## Install

```bash
git clone <repository-url>
cd incident-response-toolkit/macos
./scripts/setup-dev.sh          # creates .venv and installs with pinned constraints (requirements/constraints.txt)
source .venv/bin/activate
```

Manual equivalent:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -c requirements/constraints.txt -e ".[dev]"
```

Use the editable install: detection rules are read from the repository's `rules/` directory (searched in `--rules`,
`$IR_TOOLKIT_RULES`, `./rules`, then next to the source tree).

## First successful run

```bash
pytest -q
python -m mac_ir info
python -m mac_ir doctor
bash scripts/run-demo.sh        # synthetic evidence → scan → reports
```

Next: the [walkthrough](walkthrough.md) or the [user guide](user-guide.md).
