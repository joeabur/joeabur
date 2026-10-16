# Getting started

## Prerequisites

- Linux (see [supported platforms](../README.md#supported-platforms)), Python 3.11+ (3.12 recommended), `git`.
- No root privileges and no network access are needed for setup, tests or the synthetic demo (pip needs network once
  to install dependencies).

## Install

```bash
git clone <repository-url>
cd incident-response-toolkit/linux
./scripts/setup-dev.sh          # creates .venv and installs with pinned constraints (requirements/constraints.txt)
source .venv/bin/activate
```

Manual equivalent:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -c requirements/constraints.txt -e ".[dev]"
```

The editable install matters: detection rules are read from the repository's `rules/` directory (searched in
`--rules`, `$IR_TOOLKIT_RULES`, `./rules`, then next to the source tree).

## First successful run

```bash
pytest -q                                  # unit + integration tests, no root needed
python -m linux_ir info
python -m linux_ir doctor
bash scripts/run-demo.sh                   # synthetic evidence → scan → reports
```

Next: [walkthrough](walkthrough.md) for the guided exercises, or the [user guide](user-guide.md) for the CLI reference.
