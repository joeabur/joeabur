# Contributing

Thanks for helping! This toolkit is read-only by design: contributions must not add remediation, process killing,
service changes, evidence upload, or any execution of discovered content.

## Development setup

```bash
./scripts/setup-dev.sh
source .venv/bin/activate
```

## Checks (run before opening a pull request)

```bash
ruff check . && ruff format --check .
mypy src
pytest
python -m mac_ir verify-manifest --input examples/synthetic-evidence/case-001
```

## Guidelines

- Add tests for every behaviour change. Use synthetic fixtures (`tests/fixtures/rootfs_builder.py`); never commit
  real logs, hostnames, credentials or IOCs. Use RFC 5737 IP ranges and `*.example.test` names.
- New detection rules must include `false_positives`, `next_steps`, severity **and** confidence, and an ATT&CK
  mapping only where it is justified.
- Collectors must degrade gracefully: record a `CollectionError`, never silently skip, never raise to the caller.
- Subprocesses: argument arrays only, with timeouts and output caps (`utils/run.py`).
- If you change collectors or the synthetic root filesystem, regenerate the fixtures with
  `python scripts/make-synthetic-evidence.py` and refresh `examples/expected-results/`.
- Keep documentation commands and paths accurate; `tests/test_docs.py` checks links and referenced paths.
