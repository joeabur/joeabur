# Configuration

Defaults live in [`src/Configuration/default.json`](../src/Configuration/default.json) (`schemaVersion` 1). Pass your own JSON
file with `Invoke-IRCollection -ConfigPath` or `winir.ps1 -ConfigPath`; it is merged over the defaults and strictly validated:
**unknown keys, wrong types, non-positive limits, unknown collectors or invalid regexes are rejected.**

| Key | Default | Meaning |
|---|---|---|
| `limits.maxProcesses` | 5000 | Process record cap |
| `limits.maxHashBytes` | 104857600 | Files larger than this are not hashed |
| `limits.maxHashedExecutables` | 400 | Distinct executables hashed per run |
| `limits.maxSignatureChecks` | 200 | Authenticode checks per run |
| `limits.maxEvents` | 2000 | Events per channel (truncation is reported) |
| `limits.maxRecordsPerArtifact` | 20000 | Record cap |
| `limits.maxOwnerLookups` | 300 | Process owner (GetOwner) lookups |
| `limits.commandLineMaxChars` | 2000 | Command-line / script-block truncation |
| `events.windowHours` | 24 | Event window (1–2160) |
| `profiles.<name>.collectors` | see file | Subset of `inventory, processes, network, accounts, persistence, events` |
| `profiles.<name>.logs` | optional | Channels for the `events` collector |
| `profiles.<name>.description` | optional | Free text |
| `detection.maxFindingsPerRule` / `maxRegexInputChars` / `maxRecords` | 200 / 2048 / 200000 | Resource limits for rule evaluation |
| `ioc.matchSubdomains` | false | Opt-in: `a.evil.test` matches `evil.test` |
| `redaction.enabled` | true | Disable only for lab data |
| `redaction.patterns` | built-in | `{name, pattern, replacement}` (regex ≤ 500 chars; 250 ms match timeout) |
| `redaction.extraPatterns` | `[]` | Your additional patterns |

Example ([`examples/config.example.json`](../examples/config.example.json)):

```json
{
  "schemaVersion": 1,
  "events": { "windowHours": 6 },
  "profiles": {
    "RdpReview": { "description": "RDP-focused", "collectors": ["inventory", "accounts", "events"], "logs": ["Security"] }
  },
  "redaction": { "extraPatterns": [ { "name": "ticket", "pattern": "CORP-[A-Z0-9]{12}", "replacement": "[REDACTED-CORP-TOKEN]" } ] }
}
```

```powershell
.\scripts\winir.ps1 -Command Collect -Profile RdpReview -ConfigPath .\examples\config.example.json -OutputPath .\evidence -DryRun
```

## Rule files (`src/Configuration/rules/*.json`)

```json
{ "rules": [ {
    "id": "WIR-PERS-001", "version": 1, "title": "...", "description": "...", "category": "persistence",
    "severity": "high", "confidence": "medium", "artifact": "persistence",
    "when": [ { "field": "kind", "op": "eq", "value": "service" },
              { "field": "exec_expanded", "op": "contains_any", "value": ["\\appdata\\local\\temp\\"] } ],
    "why": "Service {name} runs {exec_binary}.",
    "false_positives": ["..."], "next_steps": ["..."], "attack": ["T1543.003"]
} ] }
```

- `type`: `match` (default), `threshold` (`group_by`, `threshold`, `window_seconds`; needs `ts`) or `baseline`
  (`key_fields`, `mode: new|changed`, `compare_fields`; needs `-BaselinePath`).
- Operators: `eq ne in not_in startswith_any endswith_any contains_any regex exists gte lte truthy falsy`. String comparisons are
  case-insensitive; list-valued fields match if any element matches; dotted field paths are allowed.
- `why` accepts `{field}` placeholders only (no code). Regexes are limited to 256 characters, nested quantifiers are rejected and
  matching has a timeout. Rule files are data: nothing in them is ever executed.
- `severity` (`info|low|medium|high|critical`) and `confidence` (`low|medium|high`) are independent; `false_positives` and
  `next_steps` are mandatory; ATT&CK ids must look like `T1059` or `T1059.001` and should be used only where justified.

Useful record fields: processes — `pid ppid name exe cmdline parent_name user start_time exe_sha256 signature_status visibility`;
network — `proto state local_addr local_port remote_addr remote_port pid process process_path`; persistence — `kind name exec_binary
exec_expanded exec_exists exec_sha256 signature_status command unquoted_path_with_spaces registry_key task_path`; events —
`event_type ts user src_ip logon_type group member image_path script_block_text`.

## IOC file schema

```json
{ "schema_version": 1, "name": "...", "synthetic": true,
  "indicators": [ { "type": "ip", "value": "203.0.113.50", "severity": "high", "description": "...", "source": "..." } ] }
```

Types: `sha256`, `process_name` (bare file name, case-insensitive), `file_path` (absolute Windows path, normalised to lower-case
backslashes), `ip` (v4/v6, canonicalised), `domain` (lower-cased; matched against domains extracted from command lines and
event text). Duplicates are ignored with a warning; any invalid entry fails the whole file (exit code 1). The file is never
downloaded, uploaded or executed. See [`examples/iocs.json`](../examples/iocs.json) (synthetic).
