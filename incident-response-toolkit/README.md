# Incident Response Toolkit

Three **read-only**, open-source toolkits for authorised incident-response triage, one per operating system. Each collects
host evidence, inspects persistence, matches IOCs, applies explainable detection rules, verifies evidence integrity with a
SHA-256 manifest, and writes reports. They share one design so that evidence from any platform is analysed the same way.

| Toolkit | Language | Folder | Start here |
|---|---|---|---|
| **Linux** (`linux-ir-toolkit`) | Python ≥ 3.11 (stdlib-first; PyYAML only) | [`linux/`](linux) | [README](linux/README.md) · [walkthrough](linux/docs/walkthrough.md) |
| **macOS** (`macos-ir-toolkit`) | Python ≥ 3.11 | [`macos/`](macos) | [README](macos/README.md) · [walkthrough](macos/docs/walkthrough.md) |
| **Windows** (`WinIRToolkit`) | PowerShell 5.1 / 7 | [`windows/`](windows) | [README](windows/README.md) · [walkthrough](windows/docs/walkthrough.md) |

## Shared principles

- **Read-only.** No process killing, remediation, setting changes, privilege escalation, evidence upload, or execution of
  discovered files/commands/IOC content. The tools never call `sudo`/elevate themselves.
- **Honest coverage.** Every collector records what it could *not* read (permission, missing utility, protected location). Reports
  separate confirmed observations, heuristic findings, IOC matches, collection errors and areas not assessed. **No findings is
  never "clean".**
- **Integrity.** New owner-only output directories, exclusive file creation, SHA-256 manifest and `verify` command. A manifest
  stored beside evidence is not tamper-proof: store its hash elsewhere.
- **Explainable detections.** Declarative rules (data, not code) with stable IDs, separate severity and confidence, known false
  positives, next steps and ATT&CK mapping only where justified.
- **Synthetic demos.** Every toolkit ships invented evidence (RFC 5737 IPs, `*.example.test`, a harmless text file instead of
  malware) and a walkthrough that needs no elevated privileges, production data or network access.

## Validation status (what was and was not run)

| | Linux | macOS | Windows |
|---|---|---|---|
| Automated tests | pytest: run, passing (Linux, Python 3.13) | pytest: run, passing on Linux (macOS-only tests skipped) | 109 unit tests run through the bundled subset runner on PowerShell 7.4 / Linux; **real Pester 5 not run here** |
| Lint / type checks | Ruff, mypy: run, passing | Ruff, mypy: run, passing | **PSScriptAnalyzer not run here** |
| Live collection on the target OS | Run on an Ubuntu 24.04 container (root, non-systemd) | **Not run** (no Mac available) | **Not run** (no Windows host available) |
| Synthetic walkthrough commands | Run | Run (on Linux) | Run (on PowerShell 7 / Linux) |
| GitHub Actions | Written, not executed | Written, not executed | Written, not executed |

See each toolkit's `docs/security-and-limitations.md` for details and blind spots.

## Repository layout

```
incident-response-toolkit/
├── linux/    macos/    windows/        one self-contained project each (src, tests, docs, examples, scripts)
└── README.md                           this file
```

CI definitions live in the repository's root [`.github/workflows/`](../.github/workflows) (`*-tests.yml`, `*-security.yml` per toolkit).

## Use responsibly

Only use these tools on systems you are authorised to investigate. Collected data contains personal and organisational
information: handle it under your organisation's policies and never commit it to version control.
