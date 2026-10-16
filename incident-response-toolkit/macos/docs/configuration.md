# Configuration

Pass a YAML file with `--config FILE`. Values override built-in defaults ([`configs/default.yaml`](../configs/default.yaml)
lists every key). **Unknown keys and wrongly-typed values are rejected** (exit code 1).

| Key | Default | Meaning |
|---|---|---|
| `limits.command_timeout_seconds` | 15 | Per subprocess timeout |
| `limits.max_command_output_bytes` | 2000000 | Output cap per subprocess (child killed beyond it) |
| `limits.max_processes` | 5000 | Process records cap |
| `limits.max_hash_bytes` | 104857600 | Files larger than this are not hashed |
| `limits.max_log_lines` / `max_log_file_bytes` | 5000 / 5000000 | Parsed-line / imported-file bounds |
| `limits.max_records_per_artifact` | 20000 | Record cap |
| `limits.max_walk_entries` | 500 | Entries examined in staging-directory walk |
| `limits.max_process_hashes` | 400 | Distinct process executables hashed |
| `limits.max_codesign_checks` | 100 | `codesign -dv` calls on launch-item executables (`extended`) |
| `profiles.<name>.collectors` | see file | Subset of `inventory, processes, network, persistence, logs, files` |
| `profiles.<name>.deep` | basic false / extended true | Apple launch items, codesign checks |
| `logs.window_hours` | 24 | Log window (1–2160) |
| `logs.predicate` | sshd/sudo/su/login/screensharingd | NSPredicate for `log show` (single line, ≤ 500 chars) |
| `detection.max_findings_per_rule` | 200 | Finding cap per rule |
| `detection.max_regex_input_chars` | 2048 | Input truncation before regex/substring tests |
| `detection.max_records` | 200000 | Records evaluated per artifact |
| `ioc.match_subdomains` | false | Opt-in: `a.evil.test` matches `evil.test` |
| `ioc.case_insensitive_paths` | **true** | Lower-case path comparison (APFS default is case-insensitive) |
| `redaction.enabled` | true | Disable only for lab data |
| `redaction.extra_patterns` | [] | `{name, pattern, replacement}` regexes (≤ 500 chars each) |

Example ([`configs/detections.yaml`](../configs/detections.yaml)):

```yaml
profiles:
  persistence-review:
    collectors: [persistence, files]
    deep: true
logs:
  window_hours: 12
  predicate: 'process == "sshd" OR process == "sudo"'
```

```bash
python -m mac_ir --config configs/detections.yaml collect --profile persistence-review --dry-run --output ./evidence
```

## Rule files (`rules/*.yaml`)

```yaml
rules:
  - id: MIR-PERS-002            # MIR-CATEGORY-NNN, unique
    version: 1
    title: ...
    description: ...
    category: persistence
    severity: high              # info|low|medium|high|critical
    confidence: medium          # low|medium|high   (separate from severity)
    artifact: persistence       # artifacts/<name>.json to evaluate
    type: match                 # match (default) | threshold | baseline
    when:                       # all conditions must hold
      - {field: kind, op: eq, value: launchd_plist}
      - {field: exec_binary, op: startswith_any, value: ["/private/tmp/"]}
    why: "{label} ({path}) runs {exec_binary}."      # {field} placeholders only
    false_positives: [...]      # required, non-empty
    next_steps: [...]           # required, non-empty
    attack: [T1543.001]         # optional, only where justified
```

Operators: `eq ne in not_in startswith_any endswith_any contains_any regex exists gte lte truthy falsy`; list fields match
if any element does; dotted paths allowed. `threshold` rules add `group_by`, `threshold`, `window_seconds`. `baseline`
rules add `key_fields`, `mode: new|changed`, `compare_fields` and need `--baseline`. Regexes are length-limited and
nested quantifiers are rejected. Rule files use `yaml.safe_load` and are data only.

Useful macOS record fields: launchd — `label, program, program_arguments, exec_binary, exec_exists, exec_sha256, signed,
signing.team_id, standard_location, run_at_load, keep_alive, scope (system|user|apple), mode, owner`; processes —
`pid, ppid, uid, user, name, exe, cmdline, exe_sha256, start_time`; logs — `event_type, user, src_ip, ts`.

## IOC file schema

```json
{"schema_version": 1, "name": "...", "synthetic": true,
 "indicators": [{"type": "ip", "value": "203.0.113.50", "severity": "high", "description": "...", "source": "..."}]}
```

Types: `sha256`, `process_name` (bare name, exact, case-sensitive), `file_path` (absolute; compared case-insensitively by
default), `ip` (v4/v6 canonicalised), `domain` (lower-cased; matched against domains extracted from command lines,
launchd arguments, cron/startup commands and log messages). Duplicates are ignored with a warning; invalid entries make
the whole file fail validation. See [`examples/iocs.json`](../examples/iocs.json) (synthetic).

Environment: `IR_TOOLKIT_RULES` – rules directory.
