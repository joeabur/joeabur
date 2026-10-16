# Contributing

Thanks for helping improve FIM. By contributing you agree your work is released under the MIT
[LICENSE](LICENSE) and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security
issues privately ([SECURITY.md](SECURITY.md)).

## Development setup

```bash
cd file-integrity-monitor
uv sync --all-extras          # or: python3 -m venv .venv && .venv/bin/pip install -e '.[all]' pytest hypothesis ruff mypy
```

## Checks (all must pass; CI runs the same)

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest                              # unit + integration + docs (add -m "not watcher" without inotify)
shellcheck -x -P SCRIPTDIR scripts/*.sh scripts/lib/*.sh
bats tests/shell
uv export --format requirements-txt --no-dev --all-extras --no-emit-project --hashes -o requirements.lock   # after dependency changes
python scripts/generate_schema.py          # after changing models.py
scripts/generate-samples.sh                # after changing report formats
```

## Ground rules

* **Tests never touch real system paths.** Use the `ws`/`tmp_path` fixtures; an autouse guard
  fails any scan outside pytest's temp directory.
* New behavior needs tests, including the failure path. Anything that could make a scan *look
  clean when it was not* is treated as a bug.
* Do not add network access, auto-remediation, or file restoration: FIM is read-only on monitored data.
* Keep runtime dependencies minimal; new ones must be justified and hash-pinned.
* Never claim tamper resistance the code cannot deliver; update
  [docs/security-and-limitations.md](docs/security-and-limitations.md) with any new limitation.

## Documentation tests

Docs are executable. In Markdown files under `docs/`:

* `<!-- fim-test:run -->` immediately before a ` ```bash ` block makes the test-suite execute it
  (all such blocks of a file run, in order, in one shell, with `fim` on `PATH`).
* `<!-- fim-test:expect -->` before a ` ```text ` block asserts that its lines appear, in order, in the
  output of the preceding run block, after masking temp paths, IDs, timestamps, hashes and host names.
  Paste real output; mark deliberately abbreviated text as illustrative in the prose.
* TOML blocks containing `[baseline]` and `[scan]` are validated; commands starting with `fim` in any
  `bash` block must use existing subcommands and options; links, anchors and referenced repo paths
  must resolve.

## Pull requests

Small, focused PRs with a description of the behavior change and the tests added. Update docs and
`CHANGELOG`-worthy notes in the PR description.
