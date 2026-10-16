# User guide

All commands: `python -m linux_ir [--config FILE] <command> ...` (also installed as `linux-ir`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error (invalid config/rules/IOC file, malformed evidence, refusing to overwrite) |
| 2 | Usage error (bad arguments, missing paths, unknown profile/collector) |
| 3 | Evidence verification failed (`verify-manifest`, or `scan`/`report` without `--allow-unverified`) |
| 10 | `scan --fail-on-findings` and at least one finding exists |

## Command reference

| Command | Purpose | Key options |
|---|---|---|
| `info [--json]` | Platform, init system, privileges | |
| `doctor` | Readiness checks: OS, arch, init, privileges, tools, readable paths | |
| `collect` | Read-only collection into a new unique directory | `--profile basic\|extended`, `--output DIR` (required), `--collectors a,b`, `--dry-run`, `--log-hours N`, `--import-log FILE` (repeatable) |
| `scan` | Run detections and IOC matching | `--input DIR` (required), `--iocs FILE`, `--rules DIR`, `--baseline DIR`, `--allow-unverified`, `--json`, `--fail-on-findings` |
| `report` | Write JSON/CSV/Markdown reports | same as scan plus `--output DIR` (required; files are never overwritten) |
| `verify-manifest` | Recompute hashes and compare with `manifest.json` | `--input DIR`, `--json` |
| `seal` | Create a manifest for an existing `artifacts/` directory (imported/synthetic evidence) | `--input DIR` |

## Profiles

| Profile | Collectors | Notes |
|---|---|---|
| `basic` | inventory, processes, network, persistence, logs | Works without root; systemd units only from `/etc` and `/run`; rotated logs not read |
| `extended` | basic + `files` | Also `/usr/lib` & `/lib` systemd units, rotated/gz auth logs, firewall metadata (`nft`, `iptables`; root normally required), sensitive-file hashes and a bounded walk of `/tmp`, `/var/tmp`, `/dev/shm` |

`--dry-run` prints each collector's planned reads and commands, and writes nothing.

## Workflow

1. `doctor` → know what will be partial.
2. `collect --dry-run` → review exactly what will happen.
3. `collect` → note the printed `EVIDENCE_DIR=` and manifest SHA-256; store the SHA-256 **separately**.
4. `verify-manifest` → `scan` (optionally `--iocs`, `--baseline`) → `report`.
5. Re-run individual collectors with elevated privileges **only if you decide it is justified**, e.g.
   `sudo python -m linux_ir collect --collectors logs,network --output ./evidence-root` (the tool never invokes sudo).

## Interpreting results

- **Confirmed observations**: facts read from the host (counts, versions).
- **Heuristic findings**: rule matches. *Severity* = impact if true; *confidence* = how likely the match is meaningful.
- **IOC matches**: exact equality with a supplied indicator; **not** proof of compromise.
- **Collection errors / not assessed**: what could not be read. Missing data ≠ absence of activity.

Every finding lists `evidence_ref` such as `artifacts/persistence.json#records[1]` — open that file and index to see the raw
record.

## Baselines

Collect on a known-good host (or earlier time), then `--baseline <old-evidence-dir>` enables rules of type `baseline`
(new units, changed unit/sensitive-file hashes, new listeners). Without a baseline these rules are skipped and listed
under "notes".

## Importing logs

`collect --collectors logs --import-log /path/export.log` parses the file (plain or `.gz`) in addition to host logs and
stores a verbatim copy in `imported/` inside the evidence directory.
