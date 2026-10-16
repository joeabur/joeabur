# Contributing

This toolkit is read-only by design: contributions must not add remediation, process killing, registry/service changes,
evidence upload, or execution of discovered content (`tests/Unit/Module.Tests.ps1` scans the source for forbidden commands).

## Development setup

```powershell
git clone <repository-url>
cd incident-response-toolkit/windows
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser    # needs PSGallery access
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

## Checks (run before opening a pull request)

```powershell
Invoke-ScriptAnalyzer -Path .\src, .\scripts -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester -Path .\tests\Unit
pwsh -File .\scripts\Invoke-Demo.ps1
```

Offline machines without Pester can run the same test files with the bundled subset runner
`pwsh -File tests/Shim/PesterShim.ps1 -Path tests/Unit` (see `docs/getting-started.md`); CI always runs real Pester.

## Guidelines

- Every collector reads data only through the `Get-IRRaw*` functions in `src/Private/RawSources.ps1`, so tests can replace them.
  Never swallow errors silently: record a collection error with `Add-IRCaughtError`.
- Test files share state through `$script:` variables and define helpers with `function script:Name` (Pester 5 scoping).
- New detection rules are JSON under `src/Configuration/rules/` and must include `false_positives`, `next_steps`, separate
  severity and confidence, and an ATT&CK id only where justified.
- Use approved verbs, comment-based help (with `.EXAMPLE`), and keep Windows PowerShell 5.1 compatibility (no `??`, ternary, `&&`).
- Synthetic data only: RFC 5737 IP ranges, `*.example.test` names. Regenerate samples with `scripts/New-SyntheticEvidence.ps1` and
  refresh `examples/expected-results/`.
