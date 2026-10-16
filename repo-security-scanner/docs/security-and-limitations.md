# Security and limitations

Read this before putting reposcan in a pipeline. The formal analysis is in the [threat model](threat-model.md).

## Security design

| Requirement | What reposcan does | Where it is tested |
|---|---|---|
| Repository content, file names and scanner output are **untrusted** | Scanner JSON is parsed with `json.loads` and validated field by field into Pydantic models; anything unexpected is `malformed_output`. File names are stripped of control characters; paths outside the scan root are dropped. | `test_adapters.py`, `test_paths.py` |
| **No full secrets** in logs or reports | Gitleaks runs with `--redact=100`; every string bound for a log, console line or report passes `redaction.sanitize` (known token formats, private keys, `key=value`, URL credentials, bearer tokens). Debug logging goes through a redacting filter that also sanitises exception text. Other scanners' evidence is withheld on lines a secret scanner flagged. Parameter ids in tests avoid credential-shaped strings. | `test_redaction.py`, `test_cli_e2e.py::test_no_report_or_console_output_contains_secret_values`, integration `test_reports_never_contain_secret_values` |
| **Do not execute repository code** | Scanners only read files. Semgrep runs static rules; Trivy `fs` and OSV-Scanner `--no-resolve` read manifests; no build, install, hook or project script is ever run, and the scan cwd is a private temp directory, not the repository. The one exception is documented: `--history` runs `git` against repository data (see below). | `test_adapters.py::test_gitleaks_command_*`, runner tests |
| **No transmission of source or findings** | reposcan has no network code. Default scanners (Gitleaks, Semgrep with bundled rules) are network-free (verified in a network-less namespace). Telemetry is disabled for Semgrep (`--metrics off`, env) and Trivy (`--disable-telemetry`). Registry rules are refused unless `allow_remote_rules`. OSV `api` mode sends package names/versions only and `local-db` sends nothing. | integration `test_default_path_needs_no_network_at_all` |
| **Command injection** | Single subprocess boundary (`runner.py`): argument lists, `shell=False`, NUL rejected, allow-listed environment, private cwd, process-group kill. Image refs and paths are validated; target paths are resolved to absolute paths so they can never be parsed as options. | `test_runner.py::test_no_shell_interpretation`, `test_paths.py` |
| **Path traversal / symlinks** | Targets resolved; report files opened with `O_NOFOLLOW`; reports written via temp file + atomic rename and refuse symlink destinations; snippet reads stay inside the scan root and refuse symlinks; the file walk never follows links. | `test_paths.py`, `test_reporting.py` |
| **HTML / Markdown / workflow injection** | HTML: every value goes through `html.escape(quote=True)`; no scripts or external resources; CSP `default-src 'none'` with a hash-pinned style. Markdown: escaping, `@mention` and autolink neutralisation. GitHub annotations: percent-encoding of `%`, CR, LF, `:` and `,`. SARIF/JSON: serialised, never templated. | `test_reporting.py` |
| **Unsafe deserialisation** | JSON and TOML only, validated by Pydantic with `extra="forbid"`. No pickle, no YAML loading, no `eval`. Size caps on every input file. | `test_baseline_policy.py`, `test_config.py` |
| **No automatic remediation** | reposcan only reads the scan target. It never edits code, deletes findings, rotates credentials or commits. Baselines are written only on explicit `baseline create`. | by construction (no write path into the target) |
| **No silent suppression** | Scanner-side suppression channels controlled by the repository are disabled or fail closed (below); accepted findings stay visible with owner and reason; expiry brings them back. | `test_real_scanners.py` hardening tests |

### Repository-controlled suppression is neutralised

A malicious pull request could try to hide its own findings. Verified against the real tools:

| Mechanism | Treatment |
|---|---|
| `# gitleaks:allow` inline comment | `--ignore-gitleaks-allow` |
| `.gitleaksignore` in the target | **Fail closed** (exit 3) unless `--allow-repo-ignore-files`; then a warning is recorded. (Gitleaks always reads it; there is no flag to turn that off.) |
| `.gitleaks.toml` in the target | Never read; the config is always passed explicitly. |
| `.semgrepignore`, `.gitignore`, Semgrep's built-in default excludes (`tests/`, `vendor/`, `node_modules/`) | `--x-ignore-semgrepignore-files --no-git-ignore`; verified that `tests/`, `node_modules/` and `vendor/` are scanned. |
| `# nosemgrep` trailing comments | `--disable-nosem` (verified: without it the finding is hidden, with it the finding is reported) |
| `.trivyignore`, `trivy.yaml` | `--ignorefile <empty>` and a private cwd. |
| Inline `#trivy:ignore:<id>` / `#tfsec:ignore:<id>` comments in IaC files (verified: a HIGH Terraform finding disappears; Trivy has no switch to disable this) | **Fail closed** (exit 3) when such a directive is found in `.tf/.tfvars/.hcl/.yaml/.yml/.json/.template/.tpl` files or Dockerfiles, unless `--allow-repo-ignore-files`; then a warning naming the files is recorded. Only checked when Trivy's `misconfig` scanner is active. |
| `osv-scanner.toml` | `--config <empty>` and `--no-ignore` (verified: ids listed in a repository `osv-scanner.toml` are still reported). |
| `reposcan.toml` / baseline in the repo | Never auto-discovered. You pass them explicitly, from a trusted location. |

### Isolation options

Scanners parse untrusted files, and parsers have bugs. For untrusted code (public pull requests, third-party
repositories) add OS-level isolation around the whole `reposcan` process. Options, from lightest to
heaviest:

1. **No-network namespace** (Linux). *Tested here* for the default path:
   ```bash
   unshare -rn reposcan scan path/to/repo --scanners gitleaks,semgrep --output-dir /tmp/out
   ```
   It proves the default scanners do not need or use the network and stops exfiltration by a compromised
   parser. Trivy/OSV-Scanner need their databases pre-warmed and `--offline`.
2. **Container** with no network, a read-only bind mount of the repository, a writable `/out`, non-root user,
   dropped capabilities. *Illustrative, not run here (no Docker daemon in the authoring sandbox):*
   ```bash
   docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
     --user 65534:65534 --tmpfs /tmp -v "$PWD":/src:ro -v "$PWD/out":/out your-image-with-reposcan \
     reposcan scan /src --scanners gitleaks,semgrep --output-dir /out
   ```
3. **Ephemeral CI runner / VM** per untrusted job, without secrets, with `contents: read` only.

reposcan itself does not build images or wrap containers: a half-tested sandbox would be worse than none.

## Baseline risks

- **A baseline is an allow-list.** Anyone who can edit it can hide a finding. Protect it with CODEOWNERS and
  branch protection, and in CI take it from the *base branch* ([example](examples.md#baseline-from-the-base-branch)).
- **Stale entries** accumulate and may later mask a *different* finding with the same fingerprint. Run
  `baseline review --report … --strict` on a schedule.
- **Over-broad suppressions** (`rule_id` without `path`) hide future instances too. Prefer fingerprints or
  path-scoped rules, and always set expiries.
- **Fingerprints exclude line numbers** so refactors do not resurrect findings; two textually identical
  matches in one file are distinguished only by order. If they swap places the pairing swaps, which is
  harmless because both carry the same rule and evidence.
- **Baselines record, they do not fix.** Secrets in a baseline are still leaked secrets: revoke first.
- Fingerprints for secrets derive from the rule, file and *redacted* match, never from the secret, so a
  baseline file reveals no credential material.

## Limitations

**Coverage**

- reposcan finds only what the scanners find. A clean report is evidence, not proof.
- The bundled Semgrep rule pack is **small and Python-only** (SQL concatenation, `shell=True`, `eval`,
  weak hashes, unsafe `yaml.load`). It exists so the tool and demo work offline. Bring your own rules
  (`[scanners.semgrep] rules`) for real coverage, or consciously enable registry rules.
- Gitleaks `dir` mode scans the working tree only; use `--history` for commits (and note it replaces the
  working-tree scan). Binary, very large (>64 MiB report) and archive contents follow each scanner's defaults.
- OSV-Scanner `--no-resolve` means transitive dependencies of manifests without lockfiles are not resolved.
- Trivy `fs` needs lockfiles/manifests it recognises; `--image` needs registry access.

**Redaction** is by pattern. An unusual credential shape embedded in free text could slip through a
*non-Gitleaks* field (for example a Semgrep evidence line). Mitigations: Gitleaks-flagged lines are
withheld from other scanners' evidence; evidence is one line, ≤240 characters. Treat reports as sensitive
anyway (mode `0600`, short artifact retention).

**Data freshness and availability**

- Vulnerability databases are only as fresh as the last update. Offline scans use cached data; the report
  does not currently record the DB age, so date your caches yourself.
- Scanner availability, versions and licences are the operator's responsibility; reposcan neither installs
  nor updates them.
- Findings and counts in this documentation are dated snapshots.

**Platform and process**

- POSIX only (Linux/macOS): uses process groups, `O_NOFOLLOW`, `/dev/null`. Windows is unsupported.
- Scanners run sequentially; a large Trivy first run can dominate pipeline time.
- `--history` executes `git` over repository data. Git can run external programs through repository
  configuration paths such as textconv drivers named in `.gitattributes`. reposcan neutralises global and
  system git config but cannot make an untrusted repository's own data safe. Use a sandbox.
- A scan target containing more than 200,000 files is summarised partially (`scope.truncated`); scanners
  themselves are not limited by that cap.
- A killed scanner may leave its own caches in a partial state; reposcan's work directory is removed in all
  cases.

**What was and was not verified** is listed in the [README](../README.md#outstanding-validation).
