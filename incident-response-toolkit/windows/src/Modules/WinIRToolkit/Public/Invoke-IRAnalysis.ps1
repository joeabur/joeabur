function Invoke-IRAnalysis {
    <#
    .SYNOPSIS
        Verifies evidence, evaluates detection rules and matches IOCs. Read-only.
    .DESCRIPTION
        Loads artifacts from an evidence directory, verifies manifest.json (unless the directory has none, which is
        noted), evaluates JSON rules, applies baseline-diff rules when a baseline evidence directory is given, and
        matches an optional IOC file. Verification failure stops the analysis unless -AllowUnverified is used.
    .PARAMETER Path
        Evidence directory.
    .PARAMETER IocPath
        Optional IOC JSON file.
    .PARAMETER BaselinePath
        Optional earlier evidence directory for baseline-diff rules.
    .PARAMETER RulesPath
        Rules directory (default: shipped rules).
    .PARAMETER Config
        Configuration hashtable.
    .PARAMETER AllowUnverified
        Analyse even if manifest verification fails (the failure is recorded in the report).
    .OUTPUTS
        PSCustomObject: Artifacts, Manifest, Verification, Findings, Notes, IocMeta, RuleCount.
    .NOTES
        Permissions: none. Throws categorised errors (IRUsage, IRVerificationFailed, IRRuntime).
    .EXAMPLE
        Invoke-IRAnalysis -Path .\sample-data\case-001 -IocPath .\examples\iocs.json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Path, [string]$IocPath, [string]$BaselinePath, [string]$RulesPath,
        [System.Collections.IDictionary]$Config, [switch]$AllowUnverified
    )
    if (-not $Config) { $Config = Get-IRConfiguration }
    foreach ($p in @(@('evidence', $Path), @('IOC file', $IocPath), @('baseline', $BaselinePath), @('rules', $RulesPath))) {
        if ($p[1] -and -not (Test-Path -LiteralPath $p[1])) { New-IRTerminatingError -Id IRUsage -Message "$($p[0]) path not found: $($p[1])" }
    }
    try { $ev = Read-IREvidence -Path $Path } catch { New-IRTerminatingError -Id IRRuntime -Message $_.Exception.Message }
    $verification = $null
    $notes = New-Object 'System.Collections.Generic.List[string]'
    if ($ev.Manifest) {
        $verification = Test-IREvidenceManifest -Path $Path
        if (-not $verification.Ok -and -not $AllowUnverified) {
            New-IRTerminatingError -Id IRVerificationFailed -Message ("Evidence integrity verification FAILED (modified={0}, missing={1}, unexpected={2}, unsafe={3}). Re-run with -AllowUnverified to analyse anyway." -f @($verification.Modified).Count, @($verification.Missing).Count, @($verification.Unexpected).Count, @($verification.Unsafe).Count)
        }
    }
    else { $notes.Add('no manifest.json present: integrity could not be verified') }
    $baseline = $null
    if ($BaselinePath) { try { $baseline = (Read-IREvidence -Path $BaselinePath).Artifacts } catch { New-IRTerminatingError -Id IRRuntime -Message "baseline: $($_.Exception.Message)" } }
    try { $rules = Import-IRRule -Path $RulesPath } catch { New-IRTerminatingError -Id IRRuntime -Message $_.Exception.Message }
    $d = $Config.detection
    $r = Invoke-IRRuleEvaluation -Rules $rules -Artifacts $ev.Artifacts -Baseline $baseline -MaxPerRule ([int]$d.maxFindingsPerRule) -MaxChars ([int]$d.maxRegexInputChars) -MaxRecords ([int]$d.maxRecords)
    $findings = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($f in $r.Findings) { $findings.Add($f) }
    foreach ($n in $r.Notes) { $notes.Add($n) }
    $iocMeta = $null
    if ($IocPath) {
        try { $ioc = Import-IRIoc -Path $IocPath } catch { New-IRTerminatingError -Id IRRuntime -Message "IOC file: $($_.Exception.Message)" }
        $iocMeta = [pscustomobject]@{ name = $ioc.Name; description = $ioc.Description; synthetic = $ioc.Synthetic; indicator_count = @($ioc.Indicators).Count }
        foreach ($w in $ioc.Warnings) { $notes.Add($w) }
        foreach ($f in @(Find-IRIocMatch -Artifacts $ev.Artifacts -Indicators $ioc.Indicators -MatchSubdomains:([bool]$Config.ioc.matchSubdomains))) { $findings.Add($f) }
    }
    $order = @{ critical = 0; high = 1; medium = 2; low = 3; info = 4 }
    $sorted = @($findings | Sort-Object @{ Expression = { $order[$_.severity] } }, rule_id, evidence_ref)
    [pscustomobject]@{ Artifacts = $ev.Artifacts; Manifest = $ev.Manifest; Verification = $verification; Findings = $sorted; Notes = @($notes); IocMeta = $iocMeta; RuleCount = @($rules).Count }
}
