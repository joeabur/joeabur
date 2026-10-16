function Invoke-IRCollection {
    <#
    .SYNOPSIS
        Read-only evidence collection into a new, uniquely named directory with a SHA-256 manifest.
    .DESCRIPTION
        Runs the collectors of the chosen profile (a failing collector never stops the others), writes one JSON
        artifact per collector, then writes manifest.json (file sizes and SHA-256, coverage, errors, limitations).
        Output directories are created with owner-only permissions and are never reused or overwritten.
        Nothing is killed, changed, deleted or transmitted. Use -DryRun to preview.
    .PARAMETER Profile
        BasicTriage | AuthenticationInvestigation | PersistenceReview | FocusedIncident (or a custom profile from -ConfigPath).
    .PARAMETER OutputPath
        Parent directory; a unique sub-directory is created inside it.
    .PARAMETER Collector
        Optional subset of collectors (inventory, processes, network, accounts, persistence, events).
    .PARAMETER EventHours
        Event window in hours (1-2160).
    .PARAMETER ConfigPath
        Optional JSON configuration file (strictly validated).
    .PARAMETER DryRun
        Return the plan only; collect and write nothing.
    .PARAMETER SkipSignature
        Skip Authenticode checks.
    .PARAMETER AllowNonWindows
        Allow running on a non-Windows host (for demos/tests; collectors will report unavailable sources).
    .OUTPUTS
        PSCustomObject: EvidenceDir, ManifestSha256, Manifest (or the plan when -DryRun).
    .NOTES
        Permissions: none required; elevation adds coverage (Security log, other users' data). Never self-elevates.
    .EXAMPLE
        Invoke-IRCollection -Profile BasicTriage -OutputPath .\evidence -DryRun
    .EXAMPLE
        $r = Invoke-IRCollection -Profile BasicTriage -OutputPath .\evidence; $r.EvidenceDir
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Profile = 'BasicTriage', [Parameter(Mandatory)][string]$OutputPath, [string[]]$Collector, [int]$EventHours = 0,
        [string]$ConfigPath, [switch]$DryRun, [switch]$SkipSignature, [switch]$AllowNonWindows
    )
    try { $cfg = Get-IRConfiguration -Path $ConfigPath } catch { New-IRTerminatingError -Id IRUsage -Message $_.Exception.Message }
    if ($EventHours -ne 0 -and ($EventHours -lt 1 -or $EventHours -gt 2160)) { New-IRTerminatingError -Id IRUsage -Message 'EventHours must be between 1 and 2160.' }
    if ($EventHours -gt 0) { $cfg.events.windowHours = $EventHours }
    $plan = @(Get-IRCollectionPlan -Profile $Profile -Config $cfg -Collector $Collector)
    try { $parent = Resolve-IROutputPath -Path $OutputPath } catch { New-IRTerminatingError -Id IRUsage -Message $_.Exception.Message }
    if ($DryRun) { return [pscustomobject]@{ DryRun = $true; Profile = $Profile; OutputPath = $parent; Plan = $plan } }
    if (-not (Test-IRWindowsHost) -and -not $AllowNonWindows) {
        New-IRTerminatingError -Id IRUsage -Message 'Live collection is only supported on Windows. Use -DryRun to preview, or analyse existing evidence (Invoke-IRAnalysis). Use -AllowNonWindows only for demos/tests.'
    }
    $started = Get-IRUtcNowIso
    $hostName = ($env:COMPUTERNAME, [Environment]::MachineName | Where-Object { $_ } | Select-Object -First 1)
    $safeHost = ($hostName -replace '[^A-Za-z0-9_-]', '_')
    $evdir = New-IRUniqueDirectory -Parent $parent -Prefix ("{0}-{1}" -f $safeHost, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
    $profileCfg = $cfg.profiles[$Profile]
    $logs = @(if ($profileCfg.Contains('logs')) { $profileCfg.logs })
    foreach ($step in $plan) {
        $name = $step.Collector
        try {
            $res = switch ($name) {
                'inventory' { Get-IRHostInventory -Config $cfg }
                'processes' { Get-IRProcessInfo -Config $cfg -SkipSignature:$SkipSignature }
                'network' { Get-IRNetworkInfo -Config $cfg }
                'accounts' { Get-IRAccountInfo -Config $cfg }
                'persistence' { Get-IRPersistenceInfo -Config $cfg -SkipSignature:$SkipSignature }
                'events' { if ($logs.Count) { Get-IREventLog -Config $cfg -Log $logs } else { Get-IREventLog -Config $cfg } }
            }
        }
        catch {
            $res = New-IRCollectorResult -Name $name
            Add-IRCollectionError $res $name 'other' ("collector crashed: " + ($_.Exception.Message -replace '\s+', ' '))
            $res.Status = 'failed'
        }
        $null = Write-IRArtifact -EvidenceDir $evdir -Document (New-IRArtifactDocument -Result $res -CollectedAt (Get-IRUtcNowIso))
    }
    $notRun = @{}
    foreach ($n in $script:CollectorNames) { if ($n -notin @($plan.Collector)) { $notRun[$n] = 'not selected by the chosen profile/collectors' } }
    $meta = [ordered]@{
        platform = 'Windows'; profile = $Profile; collectors_requested = @($plan.Collector); started_at = $started; finished_at = Get-IRUtcNowIso
        host = [ordered]@{ hostname = $hostName; powershell_version = "$($PSVersionTable.PSVersion)"; powershell_edition = "$($PSVersionTable.PSEdition)"; os = [Runtime.InteropServices.RuntimeInformation]::OSDescription }
        privileged = Test-IRElevated; event_window_hours = [int]$cfg.events.windowHours
    }
    $manifest = New-IREvidenceManifest -EvidenceDir $evdir -Metadata $meta -NotRun $notRun
    $w = Write-IREvidenceManifest -EvidenceDir $evdir -Manifest $manifest
    [pscustomobject]@{ DryRun = $false; EvidenceDir = $evdir; ManifestSha256 = $w.Sha256; Manifest = $manifest }
}
