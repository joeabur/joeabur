# Linux Incident Response Toolkit (`linux-ir-toolkit`)

A read-only command-line toolkit for **authorised** Linux investigations. It collects host evidence, inspects
persistence mechanisms, matches indicators of compromise (IOCs), applies explainable detection rules, and writes
integrity-verifiable reports. Part of the [incident-response-toolkit](../README.md) (Linux · macOS · Windows).

> **Not an EDR and not forensic imaging.** Live collection changes volatile state, cannot see everything, and a
> missing finding is never proof that a host is clean. See [security and limitations](docs/security-and-limitations.md).

## Features

| Area | What it does |
|---|---|
| Inventory | OS/kernel/arch, init system, uptime, sessions, mounts, disk, selected kernel/LSM settings |
| Processes | `/proc` enumeration: PID/PPID, owner, exe, **redacted** cmdline, start time, state, exe SHA-256; handles vanished/denied processes |
| Network | `ss` (fallback `/proc/net`), interfaces, routes, optional firewall metadata |
| Persistence | systemd units/timers/drop-ins, cron, `at` metadata, shell startup, rc.local, init.d, sshd settings, `authorized_keys` fingerprints, kernel modules |
| Logs | journald + `auth.log`/`secure`, SSH/sudo/su events, bounded window, gzip, imported logs |
| Files | selected sensitive files (hash/metadata) and executables in `/tmp`, `/var/tmp`, `/dev/shm` |
| IOCs | validated JSON/YAML; sha256, process name, path, IP, domain; exact matching by default |
| Detections | 24 declarative YAML rules (match / threshold / baseline-diff), severity ≠ confidence, false positives, ATT&CK |
| Evidence | unique 0700 output dirs, SHA-256 manifest, `verify-manifest` detects modification/deletion/additions |
| Reports | executive summary + technical report (Markdown), JSON, CSV, manifest copy |

Never done: killing processes, changing services/users/firewall/logs, executing discovered content, reading private
keys or password hashes, uploading anything, calling `sudo`.

## Quick start

```bash
git clone <repository-url> && cd incident-response-toolkit/linux
./scripts/setup-dev.sh && source .venv/bin/activate
pytest -q
python -m linux_ir doctor
bash scripts/run-demo.sh          # fully synthetic end-to-end demo
```

Real host (read-only; no root required for `basic`):

```bash
python -m linux_ir collect --dry-run --profile basic --output ./evidence
python -m linux_ir collect --profile basic --output ./evidence
python -m linux_ir verify-manifest --input ./evidence/<printed-directory>
python -m linux_ir scan --input ./evidence/<printed-directory> --iocs ./examples/iocs.json
python -m linux_ir report --input ./evidence/<printed-directory> --output ./reports/case1
```

Full tutorial: [docs/walkthrough.md](docs/walkthrough.md).

## Supported platforms

| Platform | Status |
|---|---|
| Ubuntu 22.04/24.04, Debian 12, Fedora 40+ (systemd), x86-64 and ARM64 | Targeted. **Tested** in this repo: Ubuntu 24.04 x86-64 (container, non-systemd PID 1, run as root). GitHub Actions workflows for `ubuntu-latest` (x86-64) and `ubuntu-24.04-arm` are provided but have not been executed yet. Debian, Fedora, systemd-based hosts, ARM64 and unprivileged runs are expected to work but are **not tested** on real hosts (covered only by synthetic fake-root tests). |
| Non-systemd init (OpenRC, runit, SysV) | Supported with reduced scope: systemd collection is skipped and reported. |
| macOS / Windows | Use the sibling toolkits. The parsers and analysis engine (tests, `scan`, `report`) run on any OS; live collection requires Linux. |

Requires Python ≥ 3.11 (3.12 recommended) and `PyYAML`. Native tools are optional (`ss`, `ip`, `journalctl`, `systemctl`,
`who`, `findmnt`, `nft`, `iptables`); missing tools are reported by `doctor` and recorded as collection errors.

## Example output

Synthetic data (produced by `python -m linux_ir scan --input examples/synthetic-evidence/case-001`):

```
16 finding(s) from 24 rules
[HIGH    /medium] LIR-PERS-002 systemd unit executes from a world-writable staging directory
    Unit evil-updater.service (/etc/systemd/system/evil-updater.service) runs /tmp/.cache/kworker-upd from a staging directory.
    ref: artifacts/persistence.json#records[1]
```

## Architecture

```
collect ──► collectors/*  ──► artifacts/*.json ──► manifest.json (SHA-256)
                                   │
 scan/report ◄── verify ◄──────────┘
        ├─► detections (rules/*.yaml)  ─┐
        └─► ioc matcher (examples/iocs.json) ─► findings ─► reporting (json/csv/md)
```

Details: [docs/architecture.md](docs/architecture.md).

## Limitations (summary)

Live-response data is volatile and incomplete; unprivileged runs miss other users' sockets, auth logs and firewall
rules; rootkits can falsify what user space sees; syslog timestamps lack year/zone (UTC assumed); a manifest stored
beside evidence is not tamper-proof (store its SHA-256 elsewhere).

## Documentation

- [Getting started](docs/getting-started.md) · [Walkthrough](docs/walkthrough.md) · [User guide](docs/user-guide.md)
- [Configuration](docs/configuration.md) · [Troubleshooting](docs/troubleshooting.md)
- [Security and limitations](docs/security-and-limitations.md) · [Architecture](docs/architecture.md)
- [Evidence handling](docs/evidence-handling.md) · [Examples](docs/examples.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md)

## Project status

Version 0.1.0. See [docs/security-and-limitations.md](docs/security-and-limitations.md) for the validation matrix of what
was and was not tested.
