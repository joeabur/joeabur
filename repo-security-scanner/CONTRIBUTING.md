# Contributing

Thanks for helping. This project is security tooling, so the bar for changes that touch process
execution, parsing, redaction or reporting is deliberately high.

## Setup

```bash
git clone <your fork>
cd repo-security-scanner          # the project lives in this directory
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # or: uv sync --frozen --extra dev
reposcan doctor --all              # which real scanners do you have?
```

## Checks that must pass before a pull request

```bash
ruff check . && ruff format --check .
mypy                               # strict
pytest                             # unit tests + documentation checks; no network needed
pytest -m integration              # optional: real Gitleaks + Semgrep on the bundled fixtures
python scripts/generate_schema.py --check
python scripts/check_workflows.py .github/workflows
```

Network-backed integration tests (Trivy, OSV-Scanner) run with `REPOSCAN_ITEST_NETWORK=1`.

## Rules for changes

1. **No shell strings.** Subprocesses go through `reposcan.runner.run_command` with an argument list.
2. **Fail closed.** A non-zero scanner exit, a missing report, malformed JSON or a timeout must produce
   a non-`ok` scanner status, never an empty successful result. Add a test for each new failure mode.
3. **Redact at the boundary.** New fields that carry scanner or file content must pass through
   `reposcan.redaction.sanitize` (or `sanitize_evidence`), and report writers must escape on output.
4. **Never honour repository-controlled suppressions** (ignore files, inline allow comments, repo-local
   configs). If a scanner insists on reading one, detect it and fail closed, as done for `.gitleaksignore`.
5. **Fixtures:** scanner-output fixtures come from real runs (`scripts/capture_fixtures.py`) and are
   sanitised; credentials in tests are synthetic and assembled at runtime. Do not use `ruff format` or any
   formatter on `sample-data/`; line numbers there are asserted by tests.
6. **Docs are tested.** Commands, TOML examples, links and fixture paths in `docs/` and the README are
   checked by `tests/unit/test_docs.py`. Output blocks must be labelled *observed* or *illustrative*.
7. **Pin everything in CI** (full commit SHAs, locked dependencies) and keep workflow permissions minimal.

## Upgrading a supported scanner

See "Upgrading scanners" in `docs/user-guide.md`. In short: install the new version, run
`pytest -m integration` and `python scripts/capture_fixtures.py`, review the fixture diff, then widen
the adapter's `supported` range and update `tested`.

## Commit and review

Small, focused commits with a message that says *why*. Security-relevant changes need a second review.
By contributing you agree your work is licensed under the project's MIT licence and that you will follow
`CODE_OF_CONDUCT.md`.
