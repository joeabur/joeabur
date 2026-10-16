# Workflows

GitHub Actions only executes workflows found in the **repository-root** `.github/workflows/`.
This project's pipeline is therefore [`../../../.github/workflows/fim-ci.yml`](../../../.github/workflows/fim-ci.yml)
(scoped by `paths:` and `defaults.run.working-directory` to `file-integrity-monitor/`). If you
extract this directory into its own repository, move that file to this location and delete the
`paths:` filters and the `working-directory` defaults.

Jobs: lint + type check, pytest on Python 3.11-3.13 (unit, integration, documentation), ShellCheck +
bats, lockfile/schema reproducibility, `pip-audit`, dependency review (PRs), gitleaks secret
scanning, and install smoke tests on Ubuntu and Rocky Linux 9.
