# reposcan: repository security scan orchestrator

reposcan runs established security scanners over a repository, **normalises their findings into one schema**,
applies a **severity policy and a reviewed baseline**, and writes **JSON, HTML and SARIF** reports with
**predictable exit codes** for CI. It deliberately does not reimplement any scanning engine.

| Scanner | Covers | Required | Supported range | Tested with | Licence |
|---|---|---|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | secrets | default | `>=8.19,<9` | 8.30.1 | MIT |
| [Semgrep](https://github.com/semgrep/semgrep) | static analysis (SAST) | default | `>=1.70,<2` | 1.181.0 | LGPL-2.1-or-later |
| [Trivy](https://github.com/aquasecurity/trivy) | dependencies, IaC, containers | default | `>=0.50,<1` | 0.76.0 | Apache-2.0 |
| [OSV-Scanner](https://github.com/google/osv-scanner) | dependencies (extra coverage) | optional | `>=2.0,<3` | 2.7.0 | Apache-2.0 |

Scanner versions outside the supported range are an error (exit 3), not a warning. Licences were checked
from the scanners' own sources/metadata on 2026-10-16. reposcan does not bundle or redistribute them.

## Why use an orchestrator

- **Fail closed.** A missing scanner, version mismatch, timeout, crash, truncated or malformed output is
  exit code **3**, never "no findings". A clean scan, a scan with findings and a broken scan are three
  different exit codes (0, 1, 3).
- **The repository is hostile input.** Repo-controlled suppression channels (`.gitleaksignore`,
  `gitleaks:allow`, `.semgrepignore`, `# nosemgrep`, `.trivyignore`, inline `trivy:ignore`,
  `osv-scanner.toml`, in-repo configs) are disabled or refused. Verified against the real tools.
- **Secrets are never printed.** Redaction at the source, at every boundary and in debug logs.
- **No code execution, no uploads.** Static analysis only; no network code of its own; the default
  scanners work in a network-less namespace (tested).
- **New vs accepted.** Baselines and suppressions carry owner, reason and optional expiry; they stay
  visible; expired ones turn back into new findings.

## Quick start

```bash
cd repo-security-scanner
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# install the scanners (see docs/getting-started.md), then:
reposcan doctor
reposcan scan sample-data/demo-repo --scanners gitleaks,semgrep --output-dir demo-output/first
echo "exit code: $?"          # 1: the demo repository is vulnerable on purpose
scripts/demo.sh               # clean (0), findings (1) and scanner failure (3) side by side
scripts/cleanup.sh
```

## Documentation

| Guide | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Prerequisites, installing reposcan and the scanners, version verification, what needs the network |
| [Walkthrough](docs/walkthrough.md) | Seven-step tour and four progressive exercises with exact commands and observed output |
| [User guide](docs/user-guide.md) | Command reference, orchestration and CI diagrams, scanners, baselines, policy, exit codes, offline use, upgrading |
| [Configuration reference](docs/configuration.md) | Every TOML key, defaults, presets |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms and fixes by exit code |
| [Security and limitations](docs/security-and-limitations.md) | Controls and where they are tested, baseline risks, isolation options, known limits |
| [Examples](docs/examples.md) | Configs, GitHub Actions, GitLab CI, scripting, containers |
| [Threat model](docs/threat-model.md) | Assets, actors, trust boundaries, threats and mitigations |
| [Report JSON schema](docs/report-schema.json) | Machine-readable schema of the JSON report |

Project policies: [LICENSE](LICENSE) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) ·
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; policy satisfied |
| 1 | Completed; new findings at or above `--fail-on` (default `high`) |
| 2 | Configuration or usage error |
| 3 | Scanner could not run or its result cannot be trusted |
| 4 | Internal error |
| 130 | Cancelled |

## Repository layout

```text
src/reposcan/        package: adapters/ (gitleaks, semgrep, trivy, osv), runner, redaction, schemas,
                     config, baseline, policy, orchestrator, reporting/ (json, html, sarif, md), cli
tests/unit/          mocked-subprocess, fixture and documentation tests (no network)
tests/integration/   opt-in tests that run the real scanners on safe fixtures
tests/fixtures/      sanitised real scanner output, SARIF schema
sample-data/         bundled intentionally vulnerable and clean repositories (synthetic secrets only)
policies/            preset configs (balanced, strict, report-only, offline) and self-scan config
examples/            annotated configs and a GitLab CI pipeline
docs/                guides, threat model, report schema
scripts/             demo, walkthrough, cleanup, schema/SARIF/workflow/diagram checks, fixture capture
.github/workflows/   ci, security-scan, release (SHA-pinned, least privilege)
```

## Development

```bash
pip install -e ".[dev]"            # or: uv sync --frozen --extra dev
ruff check . && ruff format --check . && mypy
pytest                             # unit tests and documentation checks, no network
pytest -m integration              # real Gitleaks + Semgrep (skips when not installed)
REPOSCAN_ITEST_NETWORK=1 pytest -m integration   # also Trivy and OSV-Scanner
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Test results

Observed on 2026-10-16 on Linux x86-64 in the authoring sandbox (reposcan 0.1.0; Gitleaks 8.30.1,
Semgrep 1.181.0, Trivy 0.76.0, OSV-Scanner 2.7.0, built from source with `go install`/`pip`):

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check .` / `ruff format --check .` | all checks passed / 56 files formatted |
| Types | `mypy` (strict, Pydantic plugin) | no issues in 24 source files |
| Unit + documentation tests | `pytest` | **324 passed** on Python 3.13, 3.12 and 3.11 each; 93 % line coverage (3.13) |
| Integration, offline scanners | `pytest -m integration` | 15 passed, 5 skipped (network-gated) |
| Integration, with network | `REPOSCAN_ITEST_NETWORK=1 pytest -m integration` | **20 passed** (adds Trivy, OSV-Scanner `local-db`, Trivy cold-cache failure, inline-ignore refusal) |
| Report schema | `python scripts/generate_schema.py --check` | up to date |
| Dependency audit | `pip-audit` on the locked runtime + dev dependencies | no known vulnerabilities |
| Workflow lint | `actionlint` v1.7.12 on all four workflows; `scripts/check_workflows.py` | no problems |
| Diagrams | `scripts/check_mermaid.sh` (Mermaid CLI 11.4.2 + Chromium) | all 5 diagrams render |
| Demo | `scripts/demo.sh` | clean → exit 0, vulnerable → exit 1, scanner failure → exit 3 |
| Walkthrough | `scripts/walkthrough.sh` | all 14 steps return the documented exit codes |
| Self-scan | `reposcan scan . --config policies/selfscan.toml --scanners gitleaks`, `reposcan scan src --scanners semgrep` | both exit 0 |

The integration tests also verify, against the real scanners, that repository-supplied suppressions
(`.semgrepignore`, `.gitignore`, `# nosemgrep`, `gitleaks:allow`, `.gitleaksignore`, `.gitleaks.toml`,
`osv-scanner.toml`, inline `trivy:ignore`) do not hide findings, that reports contain no secret value, that
SARIF validates against the official schema, and that the default path works with no network at all.

Not part of the numbers above: the CI workflows themselves have not run (see
[Outstanding validation](#outstanding-validation)).

## Known limitations

Details in [Security and limitations](docs/security-and-limitations.md). The important ones:

- A clean report is evidence, not proof; coverage is whatever the scanners provide.
- The **bundled Semgrep rules are a small, Python-only demonstration set.** Bring your own rules.
- Redaction is pattern-based; treat reports as sensitive anyway.
- Vulnerability data is only as fresh as the databases you updated; reports do not record DB age.
- POSIX only (Linux/macOS). `--history` runs `git` over repository data and needs a sandbox for untrusted
  repositories.

## Outstanding validation

Honest list of what was **not** verified during development:

- The GitHub Actions workflows and the GitLab pipeline were **linted** (`actionlint` 1.7.12, YAML parse, the
  project's own hygiene checker) but **never executed** on GitHub or GitLab.
- Action commit SHAs were resolved on 2026-10-16 from the Go module proxy's recorded tag commits because
  GitHub was not reachable from the authoring sandbox. **Verify each SHA against the upstream tag** before relying on
  them (Dependabot is configured to keep them current).
- Scanner installation via release binaries / Homebrew / container images was not exercised (blocked
  download hosts); installation via `pip` and `go install` was.
- Docker-based isolation is documented as illustrative; no Docker daemon was available.
- Only Linux x86-64 was tested; macOS is expected to work but is unverified.
- Container-image scanning (`--image`) and git-history scanning (`--history`) are implemented and unit
  tested through fake executables but were not exercised against real images or repositories.
- OSV-Scanner `api` mode could not reach `api.osv.dev` from the sandbox (observed exit 127, handled as a
  failure); `local-db` mode was run for real.
- The release workflow, protected environments and tag protection are described, not demonstrated.
