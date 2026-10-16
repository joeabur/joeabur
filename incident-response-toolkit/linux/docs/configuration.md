# Configuration

Pass a YAML file with `--config FILE`. Values override built-in defaults ([`configs/default.yaml`](../configs/default.yaml)
lists every key). **Unknown keys and wrongly-typed values are rejected** with exit code 1.

| Key | Default | Meaning |
|---|---|---|
| `limits.command_timeout_seconds` | 15 | Per subprocess timeout |
| `limits.max_command_output_bytes` | 2000000 | Output cap per subprocess (child killed beyond it) |
| `limits.max_processes` | 5000 | Process records cap |
| `limits.max_hash_bytes` | 104857600 | Files larger than this are not hashed |
| `limits.max_log_lines` / `max_log_file_bytes` | 5000 / 5000000 | Log bounds (tail of each file is read) |
| `limits.max_records_per_artifact` | 20000 | Persistence record cap |
| `limits.max_walk_entries` | 500 | Entries examined in staging-directory walk |
| `profiles.<name>.collectors` | see file | Subset of `inventory, processes, network, persistence, logs, files` |
| `profiles.<name>.deep` | basic false / extended true | Enables deeper sources |
| `logs.window_hours` | 24 | Log time window (1–2160) |
| `detection.max_findings_per_rule` | 200 | Finding cap per rule |
| `detection.max_regex_input_chars` | 2048 | Input truncation before regex/substring tests |
| `detection.max_records` | 200000 | Records evaluated per artifact |
| `ioc.match_subdomains` | false | Opt-in: `a.evil.test` matches `evil.test` |
| `ioc.case_insensitive_paths` | false | Lower-case path comparison |
| `redaction.enabled` | true | Disable only for lab data |
| `redaction.extra_patterns` | [] | List of `{name, pattern, replacement}` (regex ≤ 500 chars) |

Example custom profile and redaction (`configs/redaction.yaml` is a ready example):

```yaml
profiles:
  auth-only:
    collectors: [logs, persistence]
    deep: false
redaction:
  extra_patterns:
    - {name: ticket, pattern: 'CORP-[A-Z0-9]{12}', replacement: '[REDACTED-CORP-TOKEN]'}
```

```bash
python -m linux_ir --config configs/redaction.yaml collect --profile auth-only --dry-run --output ./evidence
```

## Rule files (`rules/*.yaml`)

```yaml
rules:
  - id: LIR-PROC-001            # PREFIX-CATEGORY-NNN, unique
    version: 1
    title: ...
    description: ...
    category: process
    severity: medium            # info|low|medium|high|critical
    confidence: low             # low|medium|high   (separate from severity)
    artifact: processes         # which artifacts/<name>.json to evaluate
    type: match                 # match (default) | threshold | baseline
    when:                       # all conditions must hold
      - {field: exe, op: startswith_any, value: ["/tmp/"]}
    why: "Process {name} (pid {pid}) runs from {exe}."   # {field} placeholders only
    false_positives: [...]      # required, non-empty
    next_steps: [...]           # required, non-empty
    attack: [T1059.004]         # optional, only where justified
```

- Operators: `eq ne in not_in startswith_any endswith_any contains_any regex exists gte lte truthy falsy`.
  List-valued fields match if any element matches. `field` supports dotted paths (`settings.permitemptypasswords`).
- `threshold` adds `group_by`, `threshold`, `window_seconds` (needs record `ts`).
- `baseline` adds `key_fields`, `mode: new|changed`, `compare_fields` (needs `--baseline`).
- Regexes are length-limited (256) and rejected if they contain nested quantifiers (ReDoS heuristic). Rule files are
  parsed with `yaml.safe_load` and are pure data: nothing in them is ever executed.

## IOC file schema

```json
{"schema_version": 1, "name": "...", "synthetic": true,
 "indicators": [{"type": "ip", "value": "203.0.113.50", "severity": "high", "description": "...", "source": "..."}]}
```

Types: `sha256`, `process_name` (bare name, exact, case-sensitive), `file_path` (absolute), `ip` (v4/v6, canonicalised),
`domain` (lower-cased, trailing dot removed; matched against domains extracted from command lines, cron commands,
startup files and log messages). Max 100 000 indicators / 10 MB. Duplicates are ignored with a warning. See
[`examples/iocs.json`](../examples/iocs.json) (synthetic).

## Environment

`IR_TOOLKIT_RULES` – directory containing rule files.
