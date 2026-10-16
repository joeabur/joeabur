<#
.SYNOPSIS
    Regenerates sample-data/ from the synthetic Windows data sources (developer tool; output is already committed).
.DESCRIPTION
    Runs the real collector code against tests/Fixtures/FakeWindows.ps1 (no access to the real system), writes the
    artifacts with a fixed reference time, then seals them with a manifest. Works on Windows PowerShell 5.1 and PowerShell 7.
.EXAMPLE
    pwsh -File scripts/New-SyntheticEvidence.ps1
#>
[CmdletBinding()]
param([string]$Destination = (Join-Path $PSScriptRoot '..\sample-data'))
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Import-Module (Join-Path $root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
. (Join-Path $root 'tests\Fixtures\FakeWindows.ps1')
$module = Get-Module WinIRToolkit
$null = New-Item -ItemType Directory -Force -Path $Destination

foreach ($variant in @(@{ Name = 'case-001'; Baseline = $false }, @{ Name = 'baseline'; Baseline = $true })) {
    Install-IRFakeSource -Module $module -Baseline:$variant.Baseline
    $out = Join-Path $Destination $variant.Name
    if (Test-Path $out) { Remove-Item -Recurse -Force $out }
    $null = New-Item -ItemType Directory -Path $out
    $now = Get-FakeNow
    $cfg = Get-IRConfiguration
    $results = @(
        (Get-IRHostInventory -Config $cfg -Now $now),
        (Get-IRProcessInfo -Config $cfg),
        (Get-IRNetworkInfo -Config $cfg),
        (Get-IRAccountInfo -Config $cfg),
        (Get-IRPersistenceInfo -Config $cfg),
        (Get-IREventLog -Config $cfg -Log @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational') -Hours 24 -Now $now)
    )
    & $module {
        param($dir, $results)
        foreach ($r in $results) { $null = Write-IRArtifact -EvidenceDir $dir -Document (New-IRArtifactDocument -Result $r -CollectedAt '2026-03-10T12:00:00Z') }
        $meta = [ordered]@{ platform = 'Windows'; profile = 'FocusedIncident'; collectors_requested = @('inventory', 'processes', 'network', 'accounts', 'persistence', 'events'); started_at = '2026-03-10T12:00:00Z'; finished_at = '2026-03-10T12:00:05Z'
            host = [ordered]@{ hostname = 'SYNTH-WS01'; synthetic = $true }; privileged = $false; event_window_hours = 24 }
        $m = New-IREvidenceManifest -EvidenceDir $dir -Metadata $meta
        $null = Write-IREvidenceManifest -EvidenceDir $dir -Manifest $m
    } $out $results
    Write-Output "wrote $out"
}

# Expected results used by scripts/Invoke-Demo.ps1 and tests/Unit/Documentation.Tests.ps1
$resolved = (Resolve-Path $Destination).ProviderPath
$a = Invoke-IRAnalysis -Path (Join-Path $resolved 'case-001') -IocPath (Join-Path $root 'examples\iocs.json') -BaselinePath (Join-Path $resolved 'baseline')
$expected = @($a.Findings | Sort-Object rule_id, evidence_ref | ForEach-Object { [ordered]@{ rule_id = $_.rule_id; severity = $_.severity; confidence = $_.confidence; classification = $_.classification; evidence_ref = $_.evidence_ref } })
$expDir = Join-Path $root 'examples\expected-results'
$null = New-Item -ItemType Directory -Force -Path $expDir
[IO.File]::WriteAllText((Join-Path $expDir 'scan-findings.json'), ((ConvertTo-Json -InputObject $expected -Depth 4) + "`n"), (New-Object Text.UTF8Encoding($false)))
$v = Test-IREvidenceManifest -Path (Join-Path $resolved 'case-001')
[IO.File]::WriteAllText((Join-Path $expDir 'verify-manifest.txt'), ("Manifest SHA-256: {0}`nVerified files : {1}`nRESULT: PASS: all hashes match`n" -f $v.ManifestSha256, $v.Verified), (New-Object Text.UTF8Encoding($false)))
Write-Output "wrote expected results ($($expected.Count) findings)"
