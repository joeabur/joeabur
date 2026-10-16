# Walkthrough: from fresh clone to a finished investigation

Everything in this guide uses **synthetic data** (RFC 5737 IPs, `*.example.test` domains, a harmless text file standing in
for malware). It needs **no administrator rights, no production data and no network access** (except cloning and optionally
installing Pester). Sections marked *live* run read-only collection on the Windows machine you are logged in to; they are optional.

Output marked **(actual)** was produced by running the command during development, **on PowerShell 7.4 under Linux** because no
Windows host was available. Output marked **(illustrative)** shows the shape of results from a real Windows host: your values
will differ. Commands use forward slashes, which work on Windows PowerShell 5.1, PowerShell 7 and non-Windows PowerShell.

## 1. Prerequisites

- Windows 10/11 or Windows Server (live collection), Windows PowerShell 5.1 or PowerShell 7+. The synthetic workflow also runs on PowerShell 7 elsewhere.
- `git`. (Optional for the tests: Pester 5.5+ and PSScriptAnalyzer from the PowerShell Gallery.)

## 2. Clone and import the module

```powershell
git clone <repository-url>
cd incident-response-toolkit/windows
Import-Module ./src/Modules/WinIRToolkit/WinIRToolkit.psd1 -Force
Get-Command -Module WinIRToolkit | Measure-Object | Select-Object -ExpandProperty Count   # (actual) 20
```

No system setting is changed. If importing is blocked by your execution policy see
[troubleshooting](troubleshooting.md#execution-policy); do not weaken the machine-wide policy as a routine step.

## 3. Run the tests (optional but recommended)

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser     # once
Invoke-Pester -Path ./tests/Unit -Output Detailed
```

(actual) With the bundled subset runner `pwsh -File tests/Shim/PesterShim.ps1 -Path tests/Unit`: `Tests: 109 passed, 0 failed` (plus 4 Windows-only integration tests that are skipped on other platforms). The
real Pester run is performed by CI and was **not** available in the environment where this guide was written.

## 4. Check readiness (privileges, cmdlets)

```powershell
./scripts/winir.ps1 -Command Doctor
```

(illustrative, on Windows)

```
[OK  ] operating system: Microsoft Windows 11 Pro
[OK  ] PowerShell: 5.1.22621.2506 (Desktop); Windows PowerShell 5.1 and PowerShell 7+ are supported
[OK  ] privileges: not elevated: the Security log, other users' processes and some WMI data may be partial. ...
[OK  ] cmdlet:Get-CimInstance: available
...
```

(actual, on Linux) `[FAIL] operating system: Ubuntu 24.04.5 LTS: live collection is unsupported here (analysis, reporting and manifest verification still work)`, exit code 1.

## 5. Dry-run collection

```powershell
./scripts/winir.ps1 -Command Collect -Profile BasicTriage -OutputPath ./evidence -DryRun
```

(actual, abridged; works on any OS)

```
DRY RUN: profile=BasicTriage; nothing will be collected or written. Output would go under .../evidence\<host>-<UTC time>-<id>\

[inventory] OS, computer system, time zone, uptime (Win32_OperatingSystem/ComputerSystem)
  permissions: None (some Defender fields need elevation)
  - CIM: Win32_OperatingSystem, Win32_ComputerSystem, Win32_TimeZone
...
```

`./evidence` is not created.

## 6. Basic collection without administrator rights (*live*, Windows only)

```powershell
./scripts/winir.ps1 -Command Collect -Profile BasicTriage -OutputPath ./evidence
```

(illustrative)

```
Evidence collected: C:\...\evidence\LAPTOP-7F3A-20260310T120000Z-a1b2c3
Manifest SHA-256 (store a copy separately): 9f2c...
  inventory    ok          records=3      errors=0
  processes    ok          records=214    errors=0
  network      ok          records=96     errors=0
  accounts     ok          records=9      errors=0
  persistence  partial     records=187    errors=2
  events       partial     records=41     errors=1
Some data is missing (see manifest errors). Missing data is NOT evidence of absence of activity.
EVIDENCE_DIR=C:\...\evidence\LAPTOP-7F3A-20260310T120000Z-a1b2c3
```

**Permission errors look like this** in `manifest.json` / the report: `events / Security / permission_denied / Attempted to perform
an unauthorized operation.` The artifact becomes `partial`, the other collectors still complete, and the report lists the gap
under "Collection errors" and "Areas not assessed". Features that need elevation: the Security log (or *Event Log Readers*
membership), other users' command lines/owners, some WMI namespaces, other users' scheduled tasks.

**Incomplete is not clean:** a `partial`/`failed`/`skipped` artifact or a non-empty error list means you cannot conclude absence
of activity from the results, even when no findings are reported.

## 7. Inspect the manifest and verify hashes (synthetic)

```powershell
$case = './sample-data/case-001'
Get-Content "$case/manifest.json" -Raw | ConvertFrom-Json | Select-Object -ExpandProperty coverage
./scripts/winir.ps1 -Command Verify -InputPath $case; $LASTEXITCODE
```

(actual)

```
Manifest SHA-256: 2cfbf569e33041d4731080a24f36ebf135b4f54a00bcb9b6d1a13459f16c3719
Verified files : 6
RESULT: PASS: all hashes match
0
```

(The SHA-256 changes whenever the samples are regenerated; compare with `examples/expected-results/verify-manifest.txt`.)
The manifest records tool version, start/finish (UTC), `privileged`, per-artifact `status`/`errors`/`notes`, every file's size and
SHA-256, and limitations. Keep a copy of the manifest hash somewhere *outside* the evidence directory.

## 8. Analyse the synthetic process, authentication and persistence artifacts

```powershell
./scripts/winir.ps1 -Command Scan -InputPath ./sample-data/case-001
```

(actual, first lines of 25 findings)

```
25 finding(s) from 33 rules
[HIGH    /high  ] WIR-AUTH-003 Audit log cleared
    audit_log_cleared by analyst at 2026-03-10T11:58:00Z.
    ref: artifacts/events.json#records[15]
[HIGH    /medium] WIR-AUTH-007 Service installed from a user-writable location
    Service WinUpdateHelper installed with "C:\Users\analyst\AppData\Local\Temp\updater.exe" --service password=[REDACTED] at 2026-03-10T09:02:00Z.
    ref: artifacts/events.json#records[17]
[HIGH    /medium] WIR-PERS-001 Service runs from a user-writable location
...
note: WIR-NET-001: no baseline supplied for 'network'; rule not evaluated
A finding is a lead, not a verdict. Missing coverage is not a clean result.
```

Rules that cannot run (here: baseline rules without a baseline) are listed, not silently skipped.

## 9. Match synthetic IOCs (and a baseline)

```powershell
./scripts/winir.ps1 -Command Scan -InputPath ./sample-data/case-001 -IocPath ./examples/iocs.json -BaselinePath ./sample-data/baseline
```

(actual) `59 finding(s) from 33 rules`: 25 heuristic + 34 more once the IOC file and baseline are used (IOC matches plus
baseline-diff findings such as `WIR-PERS-011 New service compared with baseline`).

## 10. Generate and review reports

```powershell
./scripts/winir.ps1 -Command Report -InputPath ./sample-data/case-001 -IocPath ./examples/iocs.json `
  -BaselinePath ./sample-data/baseline -OutputPath ./reports/synthetic
```

(actual)

```
wrote .../reports/synthetic/report.json
wrote .../reports/synthetic/findings.csv
wrote .../reports/synthetic/report.html
wrote .../reports/synthetic/evidence-manifest.json
wrote .../reports/synthetic/evidence-manifest.sha256
```

Open `report.html` in a browser (it is self-contained: no scripts, no external resources, every value HTML-encoded). It shows
integrity status, counts by severity, coverage, **confirmed observations**, **heuristic findings**, **IOC matches**, **collection
errors**, **areas not assessed**, limitations and next steps. `report.json` is the machine-readable form (validated against
`src/Configuration/schemas/report.schema.json`); `findings.csv` opens in a spreadsheet (formula-like cells are prefixed with `'`).
Reports are redacted and contain usernames, command lines and IPs: protect them like the evidence. Re-running into the same
directory fails with "Refusing to overwrite".

## 11. Permissions, missing logs and false positives

- Every finding lists **known false positives** and **next steps**. For example `WIR-PERS-003` (unquoted service path) is very common;
  `WIR-AUTH-006` (RDP logon) is normal remote administration; `WIR-PROC-001` also fires on installers run from Downloads.
- Missing channel (for example Sysmon not installed) → `not_found` entry; empty channel → note that auditing may be off.
- `visibility: limited` on a process means no path/command line was available (protected process or no elevation).

## 12. The reproducible demo

```powershell
./scripts/Invoke-Demo.ps1
```

(actual) verifies the manifest, analyses with IOCs and baseline, writes reports to a temporary directory, validates them against the
schema and checks the finding count against `examples/expected-results/scan-findings.json`:

```
findings: 59 (28 IOC matches)
findings in report: 59; expected: 59
Demo OK
Demo output kept in: /tmp/winir-demo-xxxxxx (delete it when done: Remove-Item -Recurse -Force '/tmp/winir-demo-xxxxxx')
```

## 13. Clean up

```powershell
Remove-Item -Recurse -Force ./reports/synthetic          # synthetic reports
Remove-Item -Recurse -Force (Join-Path ([IO.Path]::GetTempPath()) 'winir-*')   # demo and exercise output
Remove-Item -Recurse -Force ./evidence                    # ONLY if it holds just test collections
Remove-Module WinIRToolkit
```

---

## Exercise 1 — Basic host inventory and report generation

```powershell
Import-Module ./src/Modules/WinIRToolkit/WinIRToolkit.psd1 -Force
$case = './sample-data/case-001'
$inv = Get-Content "$case/artifacts/inventory.json" -Raw | ConvertFrom-Json
$inv.records | Where-Object kind -eq 'host' | Select-Object hostname, os_caption, os_build, boot_time, uptime_seconds, utc_offset_minutes, elevated | Format-List
Get-ChildItem "$case/artifacts" | Select-Object Name, Length | Format-Table -AutoSize
$analysis = Invoke-IRAnalysis -Path $case
$out = Join-Path ([IO.Path]::GetTempPath()) 'winir-ex1'
$analysis | Export-IRReport -OutputPath $out -EvidencePath $case
(Get-Content "$out/report.json" -Raw | ConvertFrom-Json).confirmed_observations
```

**Expected (actual):**

```
hostname           : SYNTH-WS01
os_caption         : Microsoft Windows 11 Pro (synthetic)
os_build           : 22631
boot_time          : 03/09/2026 08:00:00        # PowerShell 7 parses ISO strings to DateTime; the file holds 2026-03-09T08:00:00Z
uptime_seconds     : 100800
utc_offset_minutes : 120                        # original local offset is retained next to the UTC times
elevated           : False

accounts.json, events.json, inventory.json, network.json, persistence.json, processes.json   (six artifacts)
... report.json, findings.csv, report.html, evidence-manifest.json, evidence-manifest.sha256 written ...
Host SYNTH-WS01 runs Microsoft Windows 11 Pro (synthetic) (version 10.0.22631, build 22631, 64-bit); ... elevated=False; uptime 100800s.
9 processes were recorded; 2 had limited visibility.
5 sockets recorded, 3 listening.
Persistence items: run_key=3, scheduled_task=2, service=3, startup_command=1, startup_folder_item=1, winlogon_value=2, wmi_subscription=2.
Events in window: audit_log_cleared=1, group_member_added=1, logon_failure=12, ...
```

**Explanation:** each artifact is one collector's output (`inventory` = host facts, `processes`, `network`, `accounts`, `persistence`,
`events`). The report's *confirmed observations* are facts read from the host; they are separated from heuristic findings and IOC matches.

**Verify:** `Test-IREvidenceManifest -Path $case` returns `Ok : True`; `Test-IRReportSchema` on the parsed report returns `Valid : True`.

**Live variant (Windows only, illustrative):** `(Get-IRHostInventory).Records | Where-Object kind -eq 'host' | Format-List` shows your own
host; compare `elevated` with `Test-IRElevated`.

**Common mistakes:** analysing the parent folder instead of the evidence directory; expecting `elevated : True` data without an elevated session;
forgetting that reports are never overwritten (use a new `-OutputPath`).

**Cleanup:** `Remove-Item -Recurse -Force $out`

## Exercise 2 — Focused investigation of suspicious process and authentication events

```powershell
$analysis = Invoke-IRAnalysis -Path $case
$proc = Get-Content "$case/artifacts/processes.json" -Raw | ConvertFrom-Json
$proc.records | Where-Object { $_.pid -in 4100, 4200, 4300, 4400 } | Select-Object pid, ppid, name, parent_name, signature_status | Format-Table -AutoSize
$analysis.Findings | Where-Object { $_.rule_id -in 'WIR-PROC-003', 'WIR-PROC-004', 'WIR-AUTH-001' } | Select-Object rule_id, severity, confidence, observation | Format-List
($analysis.Findings | Where-Object rule_id -eq 'WIR-AUTH-001').evidence.event_refs | Select-Object -First 3
```

**Expected (actual):**

```
 pid ppid name           parent_name  signature_status
 --- ---- ----           -----------  ----------------
4100 2100 WINWORD.EXE    explorer.exe Valid
4200 4100 cmd.exe        WINWORD.EXE  Valid
4300 4200 powershell.exe cmd.exe      Valid
4400 2100 updater.exe    explorer.exe NotSigned

rule_id     : WIR-PROC-003      severity : high     confidence : medium
observation : WINWORD.EXE (pid 4100) spawned cmd.exe (pid 4200): cmd.exe /c powershell.exe -nop -w hidden -enc SQBFAFgA...
rule_id     : WIR-AUTH-001      severity : medium   confidence : medium
observation : 10 failed logons from 203.0.113.50 within the window.
rule_id     : WIR-PROC-004      severity : medium   confidence : low
observation : powershell.exe (pid 4300) was started with an encoded command.

artifacts/events.json#records[0]
artifacts/events.json#records[1]
artifacts/events.json#records[2]
```

(Findings are shown in the order the shell prints them; layout abbreviated.)

**Explanation:** `WIR-PROC-003` matches an Office parent (`parent_name`) with a script-interpreter child; its rule file is
[`src/Configuration/rules/process.json`](../src/Configuration/rules/process.json) — read `when`, `false_positives` and `next_steps`.
`WIR-AUTH-001` is a *threshold* rule: ≥10 failed logons (event 4625) from one IP within 600 s; `event_refs` lead to the individual events.
Neither claims compromise: the cmdline is a lead to decode **offline**, and the failures need a check for a later success from the same address.

**Verify:** open the referenced record: `(Get-Content "$case/artifacts/events.json" -Raw | ConvertFrom-Json).records[0] | Format-List`.

**Common mistakes:** treating `signature_status = Valid` for `cmd.exe` as proof the activity is benign (it is the *parent chain* that matters);
running the encoded command to "see what it does" — never do this on an analysis machine.

**Cleanup:** nothing was written.

## Exercise 3 — IOC matching, manifest verification and HTML/JSON export

```powershell
$a2 = Invoke-IRAnalysis -Path $case -IocPath ./examples/iocs.json
$a2.Findings | Where-Object classification -eq 'ioc_match' | Group-Object rule_id | Select-Object Name, Count | Format-Table -AutoSize
$m = $a2.Findings | Where-Object rule_id -eq 'IOC-MATCH-SHA256' | Select-Object -First 1
$m.evidence_ref; $m.observation

# integrity: change a COPY, verify, and compare the reports
$tmp = Join-Path ([IO.Path]::GetTempPath()) 'winir-ex3'; New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item -Recurse $case "$tmp/case"
Add-Content "$tmp/case/artifacts/network.json" ' '
Test-IREvidenceManifest -Path "$tmp/case" | Select-Object Ok, Verified, Modified | Format-List
try { Invoke-IRAnalysis -Path "$tmp/case" } catch { $_.Exception.Message }
$bad = Invoke-IRAnalysis -Path "$tmp/case" -AllowUnverified
$bad | Export-IRReport -OutputPath "$tmp/reports" | Out-Null
(Get-Content "$tmp/reports/report.json" -Raw | ConvertFrom-Json).integrity.Ok
Select-String -Path "$tmp/reports/report.html" -Pattern 'FAILED or not performed' -SimpleMatch | Select-Object -First 1 | ForEach-Object { 'HTML warns about failed integrity' }
```

**Expected (actual, abridged):**

```
Name                   Count
IOC-MATCH-DOMAIN           3
IOC-MATCH-FILE_PATH        5
IOC-MATCH-IP              14
IOC-MATCH-PROCESS_NAME     3
IOC-MATCH-SHA256           3
artifacts/persistence.json#records[2]
Field 'exec_sha256' = 'ac42db2b...0a4cce' exactly matches indicator sha256='ac42db2b...0a4cce' (indicator source: synthetic).
Ok       : False
Verified : 5
Modified : {@{path=artifacts/network.json; expected=...; actual=...}}
Evidence integrity verification FAILED (modified=1, missing=0, unexpected=0, unsafe=0). Re-run with -AllowUnverified to analyse anyway.
False
HTML warns about failed integrity
```

**Explanation:** IOC matching is *exact* after normalisation (lower-case, canonical IP, Windows path form). Every match carries
`evidence_ref`; the three SHA-256 matches point at the service, the Run-key target and the process executable that share the synthetic
stand-in file's hash (see `examples/iocs.json`). A one-byte change to `network.json` makes verification fail, analysis refuses to run
by default, and with `-AllowUnverified` the report records `integrity.Ok = False` and the HTML report shows a prominent warning.
The manifest cannot detect a rewritten `manifest.json`: keep its SHA-256 elsewhere.

**Verify:** `./scripts/winir.ps1 -Command Verify -InputPath "$tmp/case"` exits with code 3; try deleting `accounts.json` (MISSING) or adding a file (UNEXPECTED).

**Common mistakes:** editing the committed sample instead of the copy (restore with `git checkout -- sample-data`); expecting `example.test`
to match `evil.example.test` without `ioc.matchSubdomains`; invalid IOC files fail as a whole (exit code 1).

**Cleanup:** `Remove-Item -Recurse -Force $tmp`

---

## Optional: elevated collection on a test machine (separate from the synthetic workflow)

Not required by anything above. An elevated session sees the Security log and other users' process details, which also means the
evidence contains more sensitive data. You open the elevated PowerShell yourself; the toolkit never elevates.

```powershell
./scripts/winir.ps1 -Command Collect -Profile AuthenticationInvestigation -OutputPath ./evidence-admin
```

Compare `coverage`/`errors` with your unprivileged run to see what elevation added. Elevated live collection still cannot defeat
kernel-level tampering or recover cleared logs.
