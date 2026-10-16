# User guide

All commands: `python -m mac_ir [--config FILE] <command> ...` (also installed as `mac-ir`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error (invalid config/rules/IOC file, malformed evidence, refusing to overwrite) |
| 2 | Usage error (bad arguments, missing paths, unknown profile/collector, live collection on non-macOS) |
| 3 | Evidence verification failed (`verify-manifest`, or `scan`/`report` without `--allow-unverified`) |
| 10 | `scan --fail-on-findings` and at least one finding exists |

## Command reference

| Command | Purpose | Key options |
|---|---|---|
| `info [--json]` | Platform, version support, privileges | |
| `doctor` | Readiness: OS/version/arch, privileges, native tools | |
| `collect` | Read-only collection into a new unique directory | `--profile basic\|extended`, `--output DIR` (required), `--collectors a,b`, `--dry-run`, `--log-hours N`, `--import-log FILE.ndjson`, `--import-archive X.logarchive` (repeatable) |
| `scan` | Run detections and IOC matching | `--input DIR`, `--iocs FILE`, `--rules DIR`, `--baseline DIR`, `--allow-unverified`, `--json`, `--fail-on-findings` |
| `report` | Write JSON/CSV/Markdown reports | as scan plus `--output DIR` (files never overwritten) |
| `verify-manifest` | Recompute hashes and compare with `manifest.json` | `--input DIR`, `--json` |
| `seal` | Create a manifest for an existing `artifacts/` directory | `--input DIR` |

## Profiles

| Profile | Collectors | Privileges / reason |
|---|---|---|
| `basic` | inventory, processes, network, persistence, logs | None required. `lsof` shows only your sockets; `log show` may be limited to non-admin visibility; `/Library` and `~/Library` launch items are readable |
| `extended` | basic + files | Adds Apple's `/System/Library/Launch*` items, `codesign -dv` signing context for up to 100 launch-item executables, and a bounded walk of `/private/tmp`, `/private/var/tmp`, `/Users/Shared`. **None of this needs administrator rights**; an administrator run additionally improves `lsof`, `log show` and cron coverage |

`--dry-run` prints each collector's planned reads and commands and the privilege note, and writes nothing.
The tool never invokes `sudo`: if you decide a specific collector needs it, re-run that collector yourself:
`sudo python -m mac_ir collect --collectors network,logs --output ./evidence-admin`.

## Workflow

1. `doctor` → know what will be partial.
2. `collect --dry-run` → review exactly what will run.
3. `collect` → note `EVIDENCE_DIR=` and the manifest SHA-256 (store it **separately**).
4. `verify-manifest` → `scan` → `report`.
5. Optionally collect again after a change and use `--baseline` to diff.

## Interpreting results

Reports separate **confirmed observations** (facts read from the host), **heuristic findings** (rule matches; severity is
impact-if-true, confidence is how likely the match is meaningful), **IOC matches** (exact equality with a supplied indicator),
**collection errors**, and **areas not assessed**. Unsigned, unfamiliar or oddly located software is *context*, never
proof of maliciousness. Each finding's `evidence_ref` (e.g. `artifacts/persistence.json#records[4]`) points to the raw record.

## Unified log notes

The default predicate is in `configs/default.yaml` (`logs.predicate`); override in your own config. The predicate is passed
to `log show --predicate` as one argument (no shell). Output is capped at `limits.max_command_output_bytes`; when the cap
is hit the artifact records a `truncated` error. Events containing `<private>` are counted in `redacted_events`.
Archives created with `log collect` (requires administrator rights) and analyse it elsewhere via `--import-archive`.
