# macOS Incident Response Toolkit (`macos-ir-toolkit`)

A read-only command-line toolkit for **authorised** macOS investigations: collect host evidence, inspect launchd and
other persistence, query the unified log with bounded predicates, match IOCs, run explainable detections, and produce
integrity-verifiable reports. Part of the [incident-response-toolkit](../README.md) (Linux · macOS · Windows).

> **Not an EDR and not forensic acquisition.** Live collection changes volatile state, cannot see through SIP/TCC
> protections (and never tries to), and the absence of findings is never proof that a Mac is clean.
> See [security and limitations](docs/security-and-limitations.md).

## Features

| Area | What it does |
|---|---|
| Inventory | `sw_vers` version/build, architecture (incl. Rosetta flag), uptime, sessions, volumes, SIP / Gatekeeper / FileVault / application-firewall **status** (read-only queries) |
| Processes | `ps`: pid/ppid/uid/user/state/start time, executable path, **redacted** command line, executable SHA-256 |
| Network | `lsof` sockets with owning process (fallback `netstat`), `ifconfig` interfaces, routing table |
| Persistence | LaunchDaemons/LaunchAgents (system, user; Apple's in `extended`), plist ownership/permissions/hash, program path existence & hash, `codesign` signing context, current user's crontab, StartupItems/emond/periodic, login-item artifact metadata, shell startup files |
| Unified log | `log show` with a configurable predicate and window, size-capped output, `.logarchive` and exported ndjson import, `<private>` redaction accounting |
| Files | selected config files (hash/metadata) and executables in `/private/tmp`, `/private/var/tmp`, `/Users/Shared` |
| IOCs | validated JSON/YAML; sha256, process name, path (case-insensitive by default on APFS), IP, domain; exact matching |
| Detections | 22 declarative YAML rules (match / threshold / baseline) with severity ≠ confidence, false positives, ATT&CK |
| Evidence | unique 0700 output dirs, SHA-256 manifest, `verify-manifest` detects modification/deletion/additions |
| Reports | executive summary + technical report (Markdown), JSON, CSV, manifest copy |

Never done: killing/suspending/injecting into processes, changing settings or logs, executing discovered content, reading
keychains/private keys/browser profiles, bypassing SIP/TCC/FileVault, uploading anything, calling `sudo`.

## Quick start

```bash
git clone <repository-url> && cd incident-response-toolkit/macos
./scripts/setup-dev.sh && source .venv/bin/activate
pytest -q
python -m mac_ir doctor
bash scripts/run-demo.sh          # fully synthetic end-to-end demo (works on any OS)
```

On a test Mac (read-only; no administrator rights, no Full Disk Access needed for `basic`):

```bash
python -m mac_ir collect --dry-run --profile basic --output ./evidence
python -m mac_ir collect --profile basic --output ./evidence
python -m mac_ir verify-manifest --input ./evidence/<printed-directory>
python -m mac_ir scan --input ./evidence/<printed-directory> --iocs ./examples/iocs.json
python -m mac_ir report --input ./evidence/<printed-directory> --output ./reports/case1
```

Full tutorial: [docs/walkthrough.md](docs/walkthrough.md).

## Supported platforms

| Platform | Status |
|---|---|
| macOS 12 Monterey – 15 Sequoia, Apple silicon (arm64) and Intel (x86_64) | **Targeted.** Live collection has **not yet been run on a real Mac by the author of this repository**; collectors are verified against synthetic command output and a fake filesystem. macOS-only integration tests exist (`tests/integration/test_macos_live.py`) and run on the macOS CI job. |
| Linux / Windows | Live collection is refused with an explanation (`--dry-run`, `scan`, `report`, `verify-manifest`, `seal` and all tests work). |

Python ≥ 3.11 (3.12 recommended) and `PyYAML`. Native tools used: `sw_vers`, `ps`, `lsof`, `netstat`, `ifconfig`, `log`,
`who`, `df`, `sysctl`, `csrutil`, `spctl`, `fdesetup`, `socketfilterfw`, `codesign` (`extended`), `crontab`. Missing tools
are reported by `doctor` and recorded as collection errors.

## Example output

Synthetic data (`python -m mac_ir scan --input examples/synthetic-evidence/case-001`):

```
16 finding(s) from 22 rules
[HIGH    /medium] MIR-PERS-002 Launch item executes from a world-writable or shared directory
    com.example.updater (/Library/LaunchDaemons/com.example.updater.plist) runs /private/tmp/.cache/kworker-upd.
    ref: artifacts/persistence.json#records[4]
```

## Architecture

```
collect ─► collectors/* ─► artifacts/*.json ─► manifest.json (SHA-256)
scan/report ─► verify ─► detections (rules/*.yaml) + IOC matcher ─► findings ─► reporting (json/csv/md)
```

Details: [docs/architecture.md](docs/architecture.md).

## Limitations (summary)

SIP/TCC-protected locations and the Background Task Management database are inaccessible without privileges and are
reported, never bypassed; unified logs can omit, expire or redact events; `lsof` without root only sees the current
user's sockets; code-signing status is context, not a verdict; a manifest stored beside evidence is not tamper-proof.

## Documentation

- [Getting started](docs/getting-started.md) · [Walkthrough](docs/walkthrough.md) · [User guide](docs/user-guide.md)
- [Configuration](docs/configuration.md) · [Troubleshooting](docs/troubleshooting.md)
- [Security and limitations](docs/security-and-limitations.md) · [Architecture](docs/architecture.md)
- [Evidence handling](docs/evidence-handling.md) · [Examples](docs/examples.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md)

## Project status

Version 0.1.0 (see [validation status](docs/security-and-limitations.md#validation-status-v010)).
