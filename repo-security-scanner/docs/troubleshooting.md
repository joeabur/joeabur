# Troubleshooting

First step, always: `reposcan doctor --all` and read the `status` column. Then re-run the failing command
with `-v` (debug logging; secrets are redacted) and open `reposcan-report.json` — every scanner's `status`,
`error`, `exit_code` and `command` are recorded there.

| Exit | Think |
|---|---|
| 1 | Not a malfunction: new findings at/above the threshold. Read the report. |
| 2 | You asked for something invalid (path, flag, config, baseline, format). |
| 3 | A scanner did not complete. Results are incomplete by definition. |
| 4 | reposcan crashed. Please report it. |
| 130 | You (or the CI runner) cancelled it. |

## Scanner problems (exit 3)

| Symptom (message in the report) | Cause and fix |
|---|---|
| `status not_found` — "`trivy` is not installed or not on PATH" | Install it, or exclude it: `--scanners gitleaks,semgrep` or `enabled = false`. reposcan only searches `PATH` and never runs a binary located *inside* the scanned directory. |
| `status version_mismatch` — "`X` is outside the supported range …" | Install a supported version (see `doctor`), or for experiments set `[scan] version_policy = "warn"`. |
| `could not determine the gitleaks version` / version `unknown` | A plain `go install` build prints "version is set by build process". Rebuild with the `-ldflags` shown in [Getting started](getting-started.md#2-install-the-scanners), or use a release binary. |
| `status timeout` — "exceeded the 600s timeout" | Raise `--timeout`/`timeout_seconds`; Trivy's first run downloads ≈1.6 GB. Excluding huge vendored directories from the scan target also helps. |
| `status failed` — "produced more than N bytes of output" / "report … is N bytes (limit …)" | Raise `max_output_bytes`, or scan a smaller tree. Truncation is never applied silently. |
| `status failed` — "did not produce a report file" | The scanner exited without writing JSON. Re-run with `-v`; check the stderr excerpt in the `error` field. |
| `status malformed_output` | Scanner output was not JSON or not the expected shape — usually a scanner version outside the tested range. Check `reposcan doctor`; capture the output for a bug report (redact first). |
| `trivy:ignore` error: "the scanned repository contains inline `trivy:ignore`/`tfsec:ignore` directives …" | Trivy honours these comments and they could hide misconfigurations. Review the listed files; if acceptable, pass `--allow-repo-ignore-files` (a warning naming the files is recorded). |
| `.gitleaksignore` error: "the scanned repository contains a .gitleaksignore file…" | Gitleaks always honours that file, so it could hide findings. Review it. If acceptable, pass `--allow-repo-ignore-files` (a warning is recorded in the report). |
| `semgrep rule source 'p/…' is a remote registry reference` | Use local rules, or consciously set `allow_remote_rules = true`. |
| Trivy fails with a DB / "unable to download" message | You are offline or the registry is blocked. Run `reposcan update-db` while online, or point `TRIVY_CACHE_DIR` (via `env_passthrough`) at a warm cache. Behind a proxy, ensure `HTTPS_PROXY` and CA variables are set; reposcan passes them through. |
| `--offline` Trivy scan exits 3 | Cold cache: expected and by design. Warm it first. |
| OSV-Scanner exit 127 / "Forbidden" / `api.osv.dev` errors | The API is unreachable. Allow the host, use `mode = "local-db"`, or disable OSV. |
| `semgrep` seems to hang on `--version` | It checks for updates online. reposcan disables that via `SEMGREP_ENABLE_VERSION_CHECK=0`; if you run Semgrep yourself offline, set the same variable. |
| `semgrep reported errors while scanning: …` | Rule or parse errors made the scan incomplete, so it is a failure. Fix the rules file (`semgrep --validate --config rules.yml`). |

## Configuration and usage errors (exit 2)

| Message | Fix |
|---|---|
| `scan path does not exist` / `refusing to scan the filesystem root` | Pass the repository directory. |
| `invalid configuration: scan.timeout_seconds: …` | Compare with the [reference](configuration.md); `reposcan config validate FILE` shows every problem. |
| `config file is not valid TOML` | TOML requires quoted strings and `key = value`. |
| `unknown scanner(s): …` / `unknown report format(s): …` | Names: `gitleaks, semgrep, trivy, osv-scanner`; formats: `json, html, sarif, md, codequality`. |
| `invalid container image reference` | Only `[A-Za-z0-9._/:@-]`, no leading `-`, no `..`. |
| `--history requires a git repository` | The target needs a `.git` directory. |
| `baseline file is invalid …` | The baseline is strict JSON validated against a schema; hand edits that break it are rejected. Re-create or fix the named field. |
| "`high` findings require an expiry date" | Add `--expires YYYY-MM-DD` (policy `require_expiry_at_or_above`). |
| `expiry is more than 365 days away` | Lower it or raise `max_accept_days`. |
| `refusing to write through a symbolic link` | A report path in the output directory is a symlink. Remove it or choose another directory. |
| `output directory is inside the scan target` (warning) | Write reports outside the repository so they are not rescanned or committed. |

## Unexpected results

| Question | Answer |
|---|---|
| "My finding disappeared after I moved the file." | Fingerprints include the file path. Moving a file creates a new identity (a baselined finding becomes `new`). Re-baseline deliberately. |
| "Why does a baselined finding count as new?" | Its entry expired (`suppression_expired: true`), or the code/evidence changed materially. |
| "`baseline review` says STALE." | The finding no longer appears — remove the entry. Only shown when you pass `--report`. |
| "Trivy and OSV-Scanner both report the same CVE." | They are independent scanners and each reports it. Disable one, or accept duplicates. |
| "Dependency counts differ from the docs." | Advisory databases change daily; the docs' dependency numbers are dated snapshots. |
| "No findings in files listed in `.gitignore`." | reposcan passes `--no-git-ignore`/`--no-ignore`, so ignored files **are** scanned. If you see none, check that the scanner actually supports the file type (see `scope.top_extensions` in the report). |
| "Evidence says `REDACTED` only." | Gitleaks rules whose whole match is the secret. Use the file and line to locate it. |
| "The HTML report looks unstyled." | Intentional: a strict Content-Security-Policy blocks everything except the one embedded stylesheet. Some viewers/extensions strip it. |

## CI

| Symptom | Fix |
|---|---|
| `reposcan: command not found` | Activate the venv or add `.venv/bin` to `PATH` (`echo "$PWD/.venv/bin" >> "$GITHUB_PATH"`). |
| SARIF upload fails with "Resource not accessible by integration" | Add `security-events: write` to that job; forks never get it. |
| Annotations missing on fork PRs | GitHub limits fork workflows; the exit code still gates the check. |
| `check_workflows.py` reports an unpinned action | Replace `@v4` with the full commit SHA and keep the tag in a trailing comment; Dependabot (`.github/dependabot.yml`) can update both. |
| Job passes locally but fails in CI with exit 3 | Different scanner versions. Pin them (`semgrep==…`, `go install …@vX`) and compare `reposcan doctor` output. |

## Still stuck?

Collect: `reposcan version`, `reposcan doctor --json`, the **JSON report** (it contains no secret values) and
the exact command. Do not paste raw scanner output from a real repository without checking it. For
suspected leaks of credential values, follow `SECURITY.md`.
