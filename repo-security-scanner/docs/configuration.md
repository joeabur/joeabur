# Configuration reference

reposcan works with no configuration (built-in defaults). To change behaviour pass a TOML file with
`--config FILE`. The file is validated strictly: unknown keys, wrong types and out-of-range values are
errors (exit 2), and `reposcan config validate FILE` checks a file without scanning.

> **Configuration is never discovered inside the scanned repository.** A `reposcan.toml`, `.gitleaks.toml`,
> `.semgrepignore`, `.trivyignore`, `trivy.yaml` or `osv-scanner.toml` found in the target is not used,
> because the scanned content is untrusted and must not be able to weaken its own scan. Keep the config
> and baseline in a reviewed location (for example `ci/` with CODEOWNERS) and pass them explicitly.

Relative paths inside a config file (`rules`, `config`) are resolved against **the directory of the config
file**. Ready-to-use presets are in `policies/`; annotated examples are in `examples/configs/`.

## Complete example

```toml
# reposcan:config
[scan]
timeout_seconds = 600
max_output_bytes = 67108864
offline = false
version_policy = "enforce"
history = false
unknown_severity = "medium"
env_passthrough = []

[policy]
fail_on = "high"
fail_on_baseline = false
require_expiry_at_or_above = "critical"
max_accept_days = 365

[scanners.gitleaks]
enabled = true

[scanners.semgrep]
enabled = true
allow_remote_rules = false

[scanners.trivy]
enabled = true
scanners = ["vuln", "misconfig"]

[scanners.osv]
enabled = false
mode = "api"
allow_network_resolution = false

[[suppressions]]
rule_id = "reposcan.python.weak-hash"
path = "app/cache/*.py"
owner = "platform-team"
reason = "MD5 is used only to derive non-security cache keys"
expires = 2027-03-31
```

## `[scan]`

| Key | Type / default | Meaning |
|---|---|---|
| `timeout_seconds` | int 1–7200, `600` | Wall-clock limit **per scanner**. The process group is killed on expiry (status `timeout`). Override with `--timeout`. |
| `max_output_bytes` | int 1 KiB–1 GiB, `67108864` (64 MiB) | Cap on each of stdout, stderr **and** the scanner's report file. Exceeding it is a failure (never truncation). |
| `offline` | bool, `false` | Disable scanner network access (see [offline use](user-guide.md#offline-use-and-database-updates)). Override with `--offline/--online`. |
| `version_policy` | `"enforce"` (default) \| `"warn"` | `enforce`: a version outside the adapter's supported range is a scanner failure (exit 3). `warn`: record a warning and continue. |
| `history` | bool, `false` | Gitleaks scans git history instead of the working tree. Same as `--history`. |
| `unknown_severity` | `critical`…`info`, `"medium"` | Severity assigned to findings whose scanner severity is missing or unrecognised. Choose conservatively. |
| `env_passthrough` | list of names, `[]` | Extra environment variable **names** copied to scanner processes. By default only `PATH`, `HOME`, locale/time-zone, CA-bundle and proxy variables, XDG cache dirs and `TRIVY_CACHE_DIR`/`SEMGREP_USER_HOME` are passed; CI tokens and cloud credentials never are. |

## `[policy]`

| Key | Type / default | Meaning |
|---|---|---|
| `fail_on` | `critical\|high\|medium\|low\|info\|none`, `"high"` | Lowest severity of a **new** finding that fails the build. `none` = report-only (scanner errors still exit 3). Override with `--fail-on`. |
| `fail_on_baseline` | bool, `false` | Also count baselined findings toward the threshold. |
| `require_expiry_at_or_above` | severity or `none`, `"critical"` | Accepting a finding at or above this severity (baseline create) requires `--expires`. |
| `max_accept_days` | int 1–3650, `365` | Furthest-allowed expiry date from today. |

## `[scanners.gitleaks]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run Gitleaks. |
| `config` | bundled `src/reposcan/data/gitleaks.toml` | Path to your Gitleaks TOML (relative to the config file). The bundled config extends Gitleaks' default ruleset and adds the synthetic `DEMO_TOKEN_*` rule used by the demo. Always passed explicitly. |

## `[scanners.semgrep]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run Semgrep. |
| `rules` | `[]` → bundled `semgrep-rules.yml` | Local rule files (relative to the config file). Files are copied into a private work directory before use. Registry references (`p/…`, `r/…`, `auto`, URLs) are **refused** (scanner failure) unless `allow_remote_rules` is true. |
| `allow_remote_rules` | `false` | Permit registry rules. Fetching them contacts `semgrep.dev`; use deliberately. Telemetry stays off (`--metrics off`). |

## `[scanners.trivy]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run Trivy. |
| `scanners` | `["vuln", "misconfig"]` | Any of `vuln` (dependencies), `misconfig` (IaC / Dockerfile), `secret` (overlaps with Gitleaks; enable if you want a second opinion). Image scans (`--image REF`, a command-line option) drop `misconfig`. |

## `[scanners.osv]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Run OSV-Scanner. |
| `mode` | `"api"` | `"api"` queries `api.osv.dev` (sends package names/versions); `"local-db"` downloads archives and matches locally. |
| `allow_network_resolution` | `false` | Allow transitive dependency resolution through package registries. |

## `[[suppressions]]`

| Key | Required | Meaning |
|---|---|---|
| `owner` | yes | Person or team accountable. |
| `reason` | yes (≥3 chars) | Why the finding is accepted. Shown in every report. |
| `expires` | no | TOML date (`2027-03-31`). Expired suppressions stop applying and the finding is `new` again. |
| `fingerprint` | one of these two | 32-hex fingerprint from a report. |
| `rule_id` | one of these two | Exact rule/advisory id. |
| `scanner`, `path` | no | Narrow a `rule_id` match: scanner name; `fnmatch`-style path glob relative to the scan root. |

## Environment variables read by reposcan

| Variable | Effect |
|---|---|
| `SOURCE_DATE_EPOCH` | Fixed timestamps for reproducible reports. |
| `GITHUB_STEP_SUMMARY` | Target file for `--github-summary`. |

Variables set **for the scanners** by reposcan: `NO_COLOR=1`, `GIT_TERMINAL_PROMPT=0`,
`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `TMPDIR=<private work dir>`, and for Semgrep
`SEMGREP_ENABLE_VERSION_CHECK=0`, `SEMGREP_SEND_METRICS=off`.

## Presets in `policies/`

| File | Intent |
|---|---|
| `balanced.toml` | Recommended start: fail on new high+; Gitleaks + Semgrep + Trivy. |
| `strict.toml` | Fail on medium+; expiry required for high+ and at most 90 days; Trivy with secrets; OSV-Scanner in `local-db` mode. |
| `report-only.toml` | Never fail on severity; `version_policy = "warn"`. For rollout. |
| `offline.toml` | `offline = true`; OSV off. Requires a warm Trivy cache. |
| `selfscan.toml` | Used by this project's own CI (path-allowlists synthetic fixtures for Gitleaks). Do not reuse. |
| `gitleaks-selfscan.toml` | The Gitleaks config referenced by `selfscan.toml`. |
