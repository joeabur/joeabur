<#
.SYNOPSIS
    Command-line entry point for the Windows IR toolkit with consistent exit codes.
.DESCRIPTION
    Wraps the WinIRToolkit module. Exit codes: 0 success, 1 runtime error, 2 usage error,
    3 evidence verification failed, 10 findings present (only with -FailOnFindings).
    The script never elevates itself and never changes system settings.
.PARAMETER Command
    Doctor | Info | Collect | Scan | Report | Verify | Seal
.EXAMPLE
    pwsh -File scripts/winir.ps1 -Command Doctor
.EXAMPLE
    pwsh -File scripts/winir.ps1 -Command Collect -Profile BasicTriage -OutputPath .\evidence -DryRun
.EXAMPLE
    pwsh -File scripts/winir.ps1 -Command Scan -InputPath .\sample-data\case-001 -IocPath .\examples\iocs.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][ValidateSet('Doctor', 'Info', 'Collect', 'Scan', 'Report', 'Verify', 'Seal')][string]$Command,
    [string]$Profile = 'BasicTriage', [string]$OutputPath, [string]$InputPath, [string]$IocPath, [string]$BaselinePath,
    [string]$RulesPath, [string]$ConfigPath, [string[]]$Collector, [int]$EventHours = 0,
    [switch]$DryRun, [switch]$AllowUnverified, [switch]$FailOnFindings, [switch]$SkipSignature, [switch]$AllowNonWindows, [switch]$Json
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force

function Stop-WithCode([int]$Code, [string]$Message) { if ($Message) { [Console]::Error.WriteLine("error: $Message") }; exit $Code }
function Require-Param([string]$Name, [string]$Value) { if ([string]::IsNullOrWhiteSpace($Value)) { Stop-WithCode 2 "-$Name is required for -Command $Command" } }

try {
    switch ($Command) {
        'Info' { $i = Get-IRPlatformInfo; if ($Json) { $i | ConvertTo-Json -Depth 5 } else { $i | Format-List }; exit 0 }
        'Doctor' {
            $checks = Test-IRPrerequisite
            foreach ($c in $checks) { Write-Output ('[{0,-4}] {1}: {2}' -f $c.Status, $c.Check, $c.Detail) }
            Write-Output "`nNote: this tool never elevates itself. You decide whether to re-run specific collectors as administrator."
            if (@($checks | Where-Object Status -eq 'FAIL').Count -gt 0) { exit 1 }
            exit 0
        }
        'Collect' {
            Require-Param 'OutputPath' $OutputPath
            $r = Invoke-IRCollection -Profile $Profile -OutputPath $OutputPath -Collector $Collector -EventHours $EventHours -ConfigPath $ConfigPath -DryRun:$DryRun -SkipSignature:$SkipSignature -AllowNonWindows:$AllowNonWindows
            if ($r.DryRun) {
                Write-Output "DRY RUN: profile=$($r.Profile); nothing will be collected or written. Output would go under $($r.OutputPath)\<host>-<UTC time>-<id>\"
                foreach ($s in $r.Plan) { Write-Output "`n[$($s.Collector)] $($s.Description)`n  permissions: $($s.Permissions)"; foreach ($o in $s.Operations) { Write-Output "  - $o" } }
                exit 0
            }
            Write-Output "Evidence collected: $($r.EvidenceDir)"
            Write-Output "Manifest SHA-256 (store a copy separately): $($r.ManifestSha256)"
            foreach ($a in $r.Manifest.artifacts) { Write-Output ('  {0,-12} {1,-11} records={2,-6} errors={3}' -f $a.name, $a.status, $a.record_count, @($a.errors).Count) }
            if (@($r.Manifest.artifacts | Where-Object { $_.status -in 'partial', 'failed' }).Count -gt 0) { Write-Output 'Some data is missing (see manifest errors). Missing data is NOT evidence of absence of activity.' }
            Write-Output "EVIDENCE_DIR=$($r.EvidenceDir)"
            exit 0
        }
        'Verify' {
            Require-Param 'InputPath' $InputPath
            $v = Test-IREvidenceManifest -Path $InputPath
            if ($Json) { $v | ConvertTo-Json -Depth 6 }
            elseif ($v.Error) { Write-Output "ERROR: $($v.Error)" }
            else {
                Write-Output "Manifest SHA-256: $($v.ManifestSha256)"; Write-Output "Verified files : $($v.Verified)"
                foreach ($k in 'Modified', 'Missing', 'Unexpected', 'Unsafe') { foreach ($i in @($v.$k)) { Write-Output ("{0,-10}: {1}" -f $k.ToUpperInvariant(), ($i | ConvertTo-Json -Compress -Depth 3)) } }
                Write-Output ('RESULT: ' + $(if ($v.Ok) { 'PASS: all hashes match' } else { 'FAIL: evidence differs from manifest' }))
            }
            exit $(if ($v.Ok) { 0 } else { 3 })
        }
        'Seal' { Require-Param 'InputPath' $InputPath; $s = Protect-IREvidenceDirectory -Path $InputPath; Write-Output "sealed $InputPath; manifest SHA-256 $($s.Sha256)"; exit 0 }
        { $_ -in 'Scan', 'Report' } {
            Require-Param 'InputPath' $InputPath
            $cfg = Get-IRConfiguration -Path $ConfigPath
            $a = Invoke-IRAnalysis -Path $InputPath -IocPath $IocPath -BaselinePath $BaselinePath -RulesPath $RulesPath -Config $cfg -AllowUnverified:$AllowUnverified
            if ($Command -eq 'Scan') {
                if ($Json) { $a.Findings | ConvertTo-Json -Depth 8 }
                else {
                    if ($a.Verification -and -not $a.Verification.Ok) { Write-Output 'WARNING: analysing evidence that FAILED integrity verification' }
                    Write-Output "$(@($a.Findings).Count) finding(s) from $($a.RuleCount) rules"
                    foreach ($f in $a.Findings) { Write-Output ('[{0,-8}/{1,-6}] {2} {3}' -f $f.severity.ToUpperInvariant(), $f.confidence, $f.rule_id, $f.title); Write-Output "    $($f.observation)"; Write-Output "    ref: $($f.evidence_ref)" }
                    foreach ($n in $a.Notes) { Write-Output "note: $n" }
                    Write-Output 'A finding is a lead, not a verdict. Missing coverage is not a clean result.'
                }
                if ($FailOnFindings -and @($a.Findings).Count -gt 0) { exit 10 }
                exit 0
            }
            Require-Param 'OutputPath' $OutputPath
            foreach ($p in @($a | Export-IRReport -OutputPath $OutputPath -EvidencePath $InputPath -Config $cfg)) { Write-Output "wrote $p" }
            exit 0
        }
    }
}
catch {
    $id = "$($_.FullyQualifiedErrorId)"
    $code = if ($id -like 'IRUsage*') { 2 } elseif ($id -like 'IRVerificationFailed*') { 3 } else { 1 }
    Stop-WithCode $code $_.Exception.Message
}
