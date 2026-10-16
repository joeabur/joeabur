# Getting started

## Prerequisites

- Windows 10/11 or a supported Windows Server for live collection (Windows PowerShell 5.1 or PowerShell 7+).
  The synthetic walkthrough, analysis, reporting and manifest verification also run on PowerShell 7 on Linux/macOS.
- `git`. No administrator rights and no network access are needed for the synthetic workflow.
- Pester 5 and PSScriptAnalyzer are only needed for running the tests/linters (see below).

## Get the code

```powershell
git clone <repository-url>
cd incident-response-toolkit\windows
```

Cloning with git (instead of downloading a ZIP) avoids the "downloaded from the Internet" mark on files, which matters
for some execution policies (see [troubleshooting](troubleshooting.md#execution-policy)). Nothing in this repository asks you to
change the system-wide execution policy.

## Import the module

```powershell
Import-Module .\src\Modules\WinIRToolkit\WinIRToolkit.psd1 -Force
Get-Command -Module WinIRToolkit
```

## First successful run (synthetic data, no privileges)

```powershell
.\scripts\winir.ps1 -Command Doctor
.\scripts\Invoke-Demo.ps1
```

On PowerShell 7 launched from another shell use `pwsh -NoProfile -File .\scripts\Invoke-Demo.ps1`; on Windows
PowerShell 5.1 use `powershell.exe -NoProfile -File .\scripts\Invoke-Demo.ps1`.

## Run the tests and linters

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-Pester -Path .\tests\Unit -Output Detailed
Invoke-ScriptAnalyzer -Path .\src, .\scripts -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

Offline alternative (subset runner, development use only; CI uses real Pester):

```powershell
pwsh -NoProfile -File .\tests\Shim\PesterShim.ps1 -Path .\tests\Unit
```

`tests/Integration` contains read-only tests that need a real Windows host; they are skipped elsewhere.

Next: the [walkthrough](walkthrough.md) or the [user guide](user-guide.md).
