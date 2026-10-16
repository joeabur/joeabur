# Getting started

reposcan is a **orchestrator**: it runs mature scanners (Gitleaks, Semgrep, Trivy, optionally
OSV-Scanner) as subprocesses, normalises their output into one finding schema, applies your baseline and
severity policy, and writes JSON / HTML / SARIF reports. It does not reimplement any scanning engine.

> Convention used in these docs: **Observed** output was captured from a real run (date, versions and
> environment stated). **Illustrative** output shows the shape of a result but was not captured.
> Dependency-vulnerability counts drift as advisory databases change.

## Prerequisites

| Need | Version | Notes |
|---|---|---|
| Python | 3.11 or newer | unit suite run on 3.11, 3.12 and 3.13 (324 tests each) |
| Gitleaks | `>=8.19,<9` (tested 8.30.1) | secrets; no network needed |
| Semgrep | `>=1.70,<2` (tested 1.181.0) | SAST with bundled local rules; no network needed |
| Trivy | `>=0.50,<1` (tested 0.76.0) | dependencies / IaC; **needs its vulnerability DB** (≈1.6 GB observed) |
| OSV-Scanner | `>=2.0,<3` (tested 2.7.0) | optional; see [OSV modes](user-guide.md#osv-scanner-modes) |

You can start with only Gitleaks and Semgrep. Everything in the walkthrough marked *default path* works
with those two and no network access.

## 1. Install reposcan

```bash
cd repo-security-scanner
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"      # the "dev" extra adds pytest, ruff, mypy, jsonschema
reposcan version
```

For a reproducible install from the lockfile use `uv`:

```bash
pip install "uv==0.11.32"
uv sync --frozen --extra dev
```

## 2. Install the scanners

Install the scanners yourself; reposcan never downloads or updates them. Each command below is the
route that was **exercised while building this project (2026-10-16, Linux x86-64)**.

```bash
# Semgrep (Python package)
pip install "semgrep==1.181.0"

# Gitleaks (needs Go). The -ldflags value matters: a plain `go install` build reports
# "version is set by build process", which reposcan rejects because it cannot verify the version.
go install -ldflags "-X github.com/zricethezav/gitleaks/v8/version.Version=8.30.1" \
  github.com/zricethezav/gitleaks/v8@v8.30.1

# Trivy (needs Go; first build is slow). Same version-string caveat.
go install -ldflags "-X github.com/aquasecurity/trivy/pkg/version/app.ver=0.76.0" \
  github.com/aquasecurity/trivy/cmd/trivy@v0.76.0

# OSV-Scanner (optional)
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0
```

Prebuilt binaries, Homebrew packages and container images from each project's release channel also
work, but were **not** exercised here (GitHub release downloads were blocked in the authoring sandbox).
Whatever route you choose, verify checksums/signatures as the project documents, and make sure the
binaries are on `PATH`.

## 3. Verify the scanner versions

```bash
reposcan doctor          # enabled scanners only (gitleaks, semgrep, trivy by default)
reposcan doctor --all    # include optional scanners
reposcan doctor --json   # machine-readable
```

**Observed** (2026-10-16):

```text
reposcan 0.1.0
  gitleaks     ok                found=8.30.1    supported=>=8.19,<9  tested=8.30.1
  semgrep      ok                found=1.181.0   supported=>=1.70,<2  tested=1.181.0
  trivy        ok                found=0.76.0    supported=>=0.50,<1  tested=0.76.0
```

Statuses: `ok`, `not_found`, `version_mismatch`, `failed`. Any status other than `ok` makes
`doctor` exit with code `3`. If you have not installed Trivy, scan with
`--scanners gitleaks,semgrep` or disable it in a [config file](configuration.md).

## 4. Your first scan

```bash
reposcan scan sample-data/demo-repo --scanners gitleaks,semgrep --output-dir demo-output/first
echo "exit code: $?"
```

This scans the bundled, intentionally vulnerable demo repository, writes reports into
`demo-output/first/`, prints a summary and exits `1` because new high-severity findings exist.
`sample-data/clean-repo` exits `0`. The next step is the [walkthrough](walkthrough.md).

Prefer one command that shows all three outcomes (clean, findings, scanner failure)?

```bash
scripts/demo.sh
scripts/cleanup.sh      # remove everything the demo generated
```

## What touches the network?

| Action | Network? |
|---|---|
| `reposcan scan` with Gitleaks and/or Semgrep (bundled rules) | **No** |
| Trivy first run / DB refresh (`reposcan update-db`, or any non-`--offline` scan) | Yes: pulls the vulnerability DB from OCI registries (default `mirror.gcr.io`, then `ghcr.io`) |
| Trivy `--offline` | No, but fails (exit 3) if the DB cache is cold |
| OSV-Scanner `mode = "api"` | Yes: sends package names and versions to `api.osv.dev` |
| OSV-Scanner `mode = "local-db"` | Yes at first: downloads ecosystem archives from `osv-vulnerabilities.storage.googleapis.com`; queries are then local |
| Semgrep registry rules (`p/…`) | Refused unless `allow_remote_rules = true` |
| `--image` (container scan) | Yes: Trivy pulls the image from its registry |

Source code is **never** uploaded by reposcan. See [Security and limitations](security-and-limitations.md).

## Where to go next

- [Walkthrough](walkthrough.md): four progressive exercises with exact commands and observed output.
- [User guide](user-guide.md): commands, reports, baselines, policies, CI.
- [Configuration reference](configuration.md)
- [Troubleshooting](troubleshooting.md)
- [Examples](examples.md)
