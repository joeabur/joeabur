<#
.SYNOPSIS
    Reproducible, fully synthetic end-to-end demo. No real system data, no administrator rights, no network.
.DESCRIPTION
    Verifies sample-data/case-001, analyses it with IOCs and a baseline, writes JSON/CSV/HTML reports to a temporary
    directory, validates the report against the documented schema and compares the finding count with
    examples/expected-results/scan-findings.json. Exits 0 on success. Works on Windows PowerShell 5.1 and PowerShell 7.
.EXAMPLE
    pwsh -File scripts/Invoke-Demo.ps1
#>
[CmdletBinding()]
param([string]$OutputRoot = [IO.Path]::GetTempPath())
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
Import-Module (Join-Path $root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
$case = Join-Path $root 'sample-data\case-001'
$out = Join-Path $OutputRoot ("winir-demo-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))

Write-Output '== 1. Verify the synthetic evidence manifest'
$v = Test-IREvidenceManifest -Path $case
Write-Output ("verified files: {0}; ok: {1}" -f $v.Verified, $v.Ok)
if (-not $v.Ok) { throw 'Synthetic evidence failed verification.' }

Write-Output '== 2. Analyse (rules + IOCs + baseline)'
$a = Invoke-IRAnalysis -Path $case -IocPath (Join-Path $root 'examples\iocs.json') -BaselinePath (Join-Path $root 'sample-data\baseline')
Write-Output ("findings: {0} ({1} IOC matches)" -f @($a.Findings).Count, @($a.Findings | Where-Object classification -eq 'ioc_match').Count)

Write-Output '== 3. Write reports'
$files = @($a | Export-IRReport -OutputPath $out -EvidencePath $case)
$files | ForEach-Object { Write-Output "wrote $_" }

Write-Output '== 4. Validate report schema and compare with expected results'
$report = Get-Content -LiteralPath (Join-Path $out 'report.json') -Raw | ConvertFrom-Json
$schema = Test-IRReportSchema -Report $report
if (-not $schema.Valid) { throw "Report schema problems: $($schema.Problems -join '; ')" }
$expected = Get-Content -LiteralPath (Join-Path $root 'examples\expected-results\scan-findings.json') -Raw | ConvertFrom-Json
$got = @($report.heuristic_findings).Count + @($report.ioc_matches).Count
Write-Output "findings in report: $got; expected: $(@($expected).Count)"
if ($got -ne @($expected).Count) { throw 'Finding count differs from expected results.' }
Write-Output 'Demo OK'
Write-Output "Demo output kept in: $out (delete it when done: Remove-Item -Recurse -Force '$out')"
