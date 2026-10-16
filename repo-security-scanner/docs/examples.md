# Examples

All snippets are ready to copy. Files referenced here exist in the repository; `tests/unit/test_docs.py`
checks that the `reposcan` commands parse, TOML blocks validate and linked paths exist.

## Local use

```bash
reposcan doctor
reposcan scan . --config policies/balanced.toml --baseline ci/reposcan-baseline.json --output-dir /tmp/rs
reposcan report show --input /tmp/rs/reposcan-report.json --status new
```

Report-only rollout, then tighten:

```bash
reposcan scan . --config policies/report-only.toml --output-dir /tmp/rs      # never fails on severity
reposcan scan . --config policies/balanced.toml    --output-dir /tmp/rs      # fail on new high+
```

## Config: tune one team's policy

```toml
# reposcan:config
[policy]
fail_on = "medium"
max_accept_days = 90

[scan]
timeout_seconds = 900
unknown_severity = "high"      # treat unrecognised severities cautiously

[scanners.trivy]
scanners = ["vuln", "misconfig", "secret"]
```

## Config: your own Semgrep rules and Gitleaks config

```toml
# reposcan:config
[scanners.semgrep]
rules = ["rules/team-rules.yml"]     # relative to this config file

[scanners.gitleaks]
config = "gitleaks-team.toml"
```

Start `gitleaks-team.toml` with `[extend]` / `useDefault = true` so you keep Gitleaks' default rules.
Never point `rules` at registry shortcuts (`p/…`) unless you accept the `semgrep.dev` traffic.

## Config: a reviewed suppression

```toml
# reposcan:config
[[suppressions]]
rule_id = "reposcan.python.weak-hash"
path = "app/cache/*.py"
owner = "platform-team"
reason = "MD5 is used only to derive non-security cache keys"
expires = 2027-03-31
```

## Accepting existing findings

```bash
reposcan baseline create . --owner team-appsec --reason "Legacy code, TICKET-123" \
  --expires 2027-01-31 --baseline-file ci/reposcan-baseline.json
reposcan baseline review ci/reposcan-baseline.json --strict
```

`--strict` is a good scheduled job: it exits 1 when any entry is expired, stale (pass `--report` from a
fresh scan to detect staleness) or has no expiry.

## GitHub Actions: scan a pull request

Condensed from `.github/workflows/security-scan.yml` (the full file is linted with `actionlint`, SHAs pinned):

```yaml
name: security-scan
on:
  pull_request:        # never pull_request_target for untrusted code
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
      - run: |
          pip install "reposcan==0.1.0" "semgrep==1.181.0"
          GOBIN="${RUNNER_TEMP}/bin" go install \
            -ldflags "-X github.com/zricethezav/gitleaks/v8/version.Version=8.30.1" \
            github.com/zricethezav/gitleaks/v8@v8.30.1
          echo "${RUNNER_TEMP}/bin" >> "${GITHUB_PATH}"
      - run: reposcan doctor
      - run: |
          reposcan scan . --config ci/reposcan.toml --fail-on high \
            --output-dir "${RUNNER_TEMP}/reposcan" --format json,sarif,md \
            --github-annotations --github-summary
      - if: ${{ always() && github.event.pull_request.head.repo.fork != true }}
        uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
        with:
          sarif_file: ${{ runner.temp }}/reposcan/reposcan.sarif
```

(`reposcan==0.1.0` assumes you publish the package to your index; otherwise install from a pinned
checkout: `pip install ./repo-security-scanner`.)

### Baseline from the base branch

A pull request must not be able to add its own exceptions. Read the baseline from the target branch:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Trusted baseline from the base branch
        env:
          BASE_REF: ${{ github.base_ref }}      # untrusted-looking values go through env, not into the script
        run: git show "origin/${BASE_REF}:ci/reposcan-baseline.json" > "${RUNNER_TEMP}/baseline.json"
      - run: reposcan scan . --config ci/reposcan.toml --baseline "${RUNNER_TEMP}/baseline.json" --output-dir "${RUNNER_TEMP}/reposcan"
```

Also protect `ci/` with CODEOWNERS and require the check in branch protection.

## GitLab CI

`examples/gitlab/.gitlab-ci.yml` (digest-pinned image, merge-request pipelines, Code Quality widget):

```yaml
reposcan:
  stage: security
  script:
    - pip install "reposcan==0.1.0" "semgrep==1.181.0"
    - reposcan scan . --config ci/reposcan.toml --baseline ci/reposcan-baseline.json
        --scanners gitleaks,semgrep --fail-on high --output-dir reposcan-output
        --format json,sarif,md,codequality
  artifacts:
    when: always
    expire_in: 14 days
    paths: [reposcan-output/reposcan-report.json, reposcan-output/reposcan.sarif]
    reports:
      codequality: reposcan-output/gl-code-quality-report.json
```

## Branching on exit codes in a script

```bash
reposcan scan . --config policies/balanced.toml --output-dir /tmp/rs
case $? in
  0)   echo "clean" ;;
  1)   echo "new findings: see /tmp/rs/reposcan-summary.md" ;;
  2)   echo "pipeline misconfigured" ; exit 2 ;;
  3)   echo "a scanner failed; do NOT treat this as a pass" ; exit 3 ;;
  130) echo "cancelled" ;;
  *)   echo "internal error" ; exit 4 ;;
esac
```

## Re-render a saved result

```bash
reposcan report render --input /tmp/rs/reposcan-report.json --format html,sarif --output-dir /tmp/rs2
python scripts/validate_sarif.py /tmp/rs2/reposcan.sarif
```

The JSON shape is documented by `docs/report-schema.json`.

## Scan a container image (Trivy)

```bash
reposcan scan . --scanners trivy --image alpine:3.20 --output-dir /tmp/rs-image
```

Trivy pulls the image from its registry and scans it **instead of** the filesystem. Findings carry an
`artifact` (not a file), and SARIF locations fall back to `.`. *Illustrative; not run during authoring.*

## Run the whole demo or walkthrough

```bash
scripts/demo.sh            # three outcomes: exit 0, 1, 3
scripts/walkthrough.sh     # every walkthrough command
scripts/cleanup.sh
```
