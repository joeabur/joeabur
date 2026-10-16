# Security and limitations

## Intended use and threat model

For authorised responders examining a Windows host that may be compromised. An attacker may have altered files, registry,
logs and configuration, so everything collected is **untrusted input**: parsed as text, size-bounded, never executed, never used to
build commands. Safeguards:

- Read-only by design: only `Get-*` cmdlets, CIM queries and read-only registry access (plus `GetOwner`, which queries a process
  token). `tests/Unit/Module.Tests.ps1` fails the build if source files use state-changing or execution commands
  (`Stop-Process`, `Remove-Item`, `Set-ItemProperty`, `Start-Process`, `Invoke-Expression`, `Invoke-WebRequest` ...).
- Discovered commands (services, tasks, Run keys, WMI) are parsed to extract the executable path; the executable is hashed
  and signature-checked **by path** but never launched.
- No network access of any kind; nothing is uploaded; IOC files are local files that are never fetched.
- Output paths are validated (no `..`, no device paths, no existing file), directories are unique and owner-only (ACL on
  Windows), files are created with `CreateNew` and never overwritten; manifest entries are checked against traversal and reparse points.
- Rule files, IOC files and configuration are JSON data validated before use; regexes are length-limited, nested quantifiers
  rejected and matching has a timeout; templates only substitute `{field}` values.
- Secrets in command lines, WMI commands, service paths, event data and reports are redacted with configurable patterns
  (best effort: unusual formats may slip through). HTML output HTML-encodes every dynamic value, has no script and sets a restrictive
  Content-Security-Policy. CSV cells that could be read as formulas are neutralised.

## Privacy

Evidence and reports contain usernames, host names, IP addresses, command lines, scheduled-task and service definitions and event
excerpts. Treat them as sensitive personal and organisational data: store with restricted access, share only under your
organisation's rules, never commit them (`.gitignore` excludes `evidence/`, `reports/`, `*.evtx`, `*.dmp`). Not collected by design:
LSASS/credential stores, DPAPI/vault data, browser profiles, private keys, credential hashes, file contents of user directories.

## Privileges (what elevation adds)

| Source | Not elevated | Elevated adds |
|---|---|---|
| Processes | Names, PIDs; command lines/owners for your own and many others' | Protected-process details, all owners |
| Security event log | Denied unless in *Event Log Readers* | Authentication, account, log-clearing events |
| Scheduled tasks | Tasks visible to the current token | Other users' / protected tasks |
| WMI `root\subscription` | Often readable; may be denied | Reliable enumeration |
| Defender status | Basic fields | Tamper protection etc. |

The toolkit never elevates itself. Run specific collectors from an elevated session if you decide it is justified and authorised.

## Blind spots

- Live collection is not a forensic image: no memory, no disk slack/unallocated space, no deleted-file recovery; running the tool changes volatile state.
- Kernel-mode malware, tampered WMI/CIM providers or hooked APIs can falsify what is returned.
- Cleared or rolled-over logs cannot be recovered; absent auditing policy means absent events. Sysmon/PowerShell logging only exist if enabled.
- Persistence coverage is selective: services, scheduled tasks, Run/RunOnce, startup items/folders, Winlogon `Shell`/`Userinit`, WMI
  subscriptions. Not covered: COM hijacking, AppInit/AppCert DLLs, IFEO debuggers, LSA packages, drivers, BITS jobs, browser extensions, DLL search-order issues.
- Containers/VMs: the view is of the guest only. Domain accounts and group nesting are not expanded.
- Timestamps come from the host clock (normalised to UTC; original local time/offset retained in inventory); skew is not corrected.
- Authenticode "Valid" does not mean benign; "NotSigned" does not mean malicious (signing is context only).
- An IOC match is not a confirmed compromise. **No findings is not "clean", especially when `coverage` shows partial, failed or skipped artifacts.**

## Validation status (v0.1.0)

| Check | Status |
|---|---|
| Module import, all collectors against synthetic data sources, rule engine, IOC matching, manifest/verify, reports (JSON/CSV/HTML), schema check, CLI exit codes, demo | **Run** on PowerShell 7.4.6 under Linux (Ubuntu 24.04) using the bundled subset runner: 109 unit tests passed, 4 Windows-only integration tests skipped |
| Real **Pester 5** execution of `tests/Unit` | **Not run here** (PowerShell Gallery unreachable); configured in CI |
| **PSScriptAnalyzer** | **Not run here**; configured in CI (`PSScriptAnalyzerSettings.psd1`) |
| Windows PowerShell 5.1 | **Not run here**; code avoids 7-only syntax (`??`, ternary, `&&`, `-AsHashtable`) but is unverified on 5.1 |
| Live collection on Windows 10/11 / Server (CIM, `Get-WinEvent`, registry, Authenticode, WMI) | **Not run here** (no Windows host); `tests/Integration` runs on the `windows-latest` CI job |
| GitHub Actions workflows | Written, **not executed** here |
