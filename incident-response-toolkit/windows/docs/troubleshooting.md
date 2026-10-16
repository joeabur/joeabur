# Troubleshooting

## Execution policy

Windows client editions default to the `Restricted` policy, which blocks all script files, including the module. Options, from least
to most invasive. **None of them is a routine installation step, and none changes the machine-wide policy.**

1. Check the effective policy: `Get-ExecutionPolicy -List`. Many managed machines already use `RemoteSigned` or `AllSigned`.
2. With `RemoteSigned`, files obtained by `git clone` run without prompts. Files from a ZIP download carry a "downloaded from the
   Internet" mark and are blocked: prefer `git clone`. Only after reviewing the code yourself may you remove the mark for this
   folder with `Get-ChildItem -Recurse .\windows | Unblock-File`.
3. If policy is `Restricted` or `AllSigned` and you are authorised to run this tool, ask your administrator to approve it (for example
   by signing the scripts with your organisation's certificate), or start a *process-scoped* session for one run:
   `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\scripts\winir.ps1 -Command Doctor`. This changes nothing stored on
   the machine, cannot override a Group Policy setting, and is **not** a security boundary — use it only on a machine you control.

| Symptom | Cause / fix |
|---|---|
| `File ... cannot be loaded because running scripts is disabled` | See *Execution policy* above. |
| `Import-Module : The specified module ... was not loaded` / parse errors | Make sure you import the `.psd1` from `src/Modules/WinIRToolkit/`, from a complete checkout; run `Import-Module ... -Force -Verbose`. |
| `Unknown profile 'X'` (exit 2) | Valid names: `BasicTriage`, `AuthenticationInvestigation`, `PersistenceReview`, `FocusedIncident`, plus profiles from `-ConfigPath`. |
| `Live collection is only supported on Windows` (exit 2) | You are on Linux/macOS; use `-DryRun` or analyse existing evidence. |
| `permission_denied` for `Security` | Not elevated and not in *Event Log Readers*. Decide whether to re-run that collector elevated. |
| `not_found` for `Microsoft-Windows-Sysmon/Operational` | Sysmon is not installed: expected. PowerShell operational logging (4104) also needs to be enabled by policy to produce events. |
| `unavailable` for `SecurityCenter2` | Windows Server / restricted systems; installed AV products are not enumerated (a note is recorded). |
| `unavailable` for `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `Get-NetTCPConnection` ... | The Defender / NetSecurity / NetTCPIP modules are missing (Server Core, stripped images, third-party AV). Data is partial. |
| `Get-WinEvent` returns nothing | Audit policy disabled, log rolled over, or the window is too short. An empty channel is reported as a note, never as "clean". |
| Command line / owner missing for many processes | Protected processes or no elevation → `visibility: limited`. |
| `Evidence integrity verification FAILED` (exit 3) | A file changed after collection (modified / missing / unexpected). Investigate. Use `-AllowUnverified` only for deliberate exercises. |
| `Refusing to overwrite existing file` | Reports and manifests are created exclusively; choose a new `-OutputPath`. |
| `Unknown configuration key: ...` | The configuration is validated strictly; compare with `src/Configuration/default.json`. |
| `IOC file: indicators[N]: invalid ...` (exit 1) | One malformed indicator fails the entire file by design. |
| Rule error `... regex too long or has nested quantifiers` | ReDoS guard; simplify the pattern (≤ 256 chars, no `(a+)+`). |
| Pester: `Should -Be` syntax errors / old Pester | Windows ships Pester 3.4; install 5.x: `Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force -SkipPublisherCheck`. |
| PSScriptAnalyzer not found | `Install-Module PSScriptAnalyzer -Scope CurrentUser`. |
| Dates print as `03/09/2026 08:00:00` | PowerShell 7 converts ISO strings from JSON into `DateTime` for display; the files and reports hold ISO 8601 UTC strings. |
| Unicode/encoding oddities | Files are written as UTF-8 without BOM; read with `-Encoding UTF8` on Windows PowerShell 5.1. |
