function Get-IREventLog {
    <#
    .SYNOPSIS
        Bounded, read-only collection of selected Windows events (Security, System, PowerShell, Sysmon) in a time window.
    .DESCRIPTION
        Uses Get-WinEvent with FilterHashtable (never reads whole logs). Missing channels (for example Sysmon not
        installed) and access-denied errors (Security log without elevation) are recorded per channel; the other channels
        still run. Script-block and command-line text is redacted and truncated. "No events" is reported as an empty
        channel, not as proof that nothing happened.
    .PARAMETER Config
        Configuration hashtable. Defaults to the built-in configuration.
    .PARAMETER Log
        Channels to read. Default: Security, System, Microsoft-Windows-PowerShell/Operational.
    .PARAMETER Hours
        Time window in hours (default from configuration).
    .PARAMETER Now
        Reference time (UTC).
    .OUTPUTS
        PSCustomObject collector result.
    .NOTES
        Permissions: the Security log requires elevation or membership of Event Log Readers.
    .EXAMPLE
        Get-IREventLog -Log Security -Hours 6
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([System.Collections.IDictionary]$Config, [string[]]$Log, [int]$Hours = 0, [datetime]$Now = [DateTime]::UtcNow)
    if (-not $Config) { $Config = Get-IRConfiguration }
    if ($Hours -le 0) { $Hours = [int]$Config.events.windowHours }
    if ($Hours -gt 2160) { throw 'Hours must be between 1 and 2160.' }
    if (-not $Log -or $Log.Count -eq 0) { $Log = @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational') }
    $redactor = New-IRRedactor -Patterns (@($Config.redaction.patterns) + @($Config.redaction.extraPatterns)) -Enabled $Config.redaction.enabled
    $res = New-IRCollectorResult -Name 'events'
    $since = $Now.ToUniversalTime().AddHours(-$Hours)
    $maxPer = [int]$Config.limits.maxEvents
    $catalog = Get-IREventCatalog
    $stats = [ordered]@{}
    foreach ($channel in $Log) {
        $ids = @($catalog.Keys | Where-Object { $catalog[$_].Log -eq $channel } | ForEach-Object { [int]$_ })
        if ($ids.Count -eq 0 -and $channel -notin @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational')) {
            Add-IRCollectionError $res $channel 'other' 'channel is not in the supported list (Security, System, Microsoft-Windows-PowerShell/Operational, Microsoft-Windows-Sysmon/Operational)'
            continue
        }
        try {
            $count = 0
            foreach ($e in @(Get-IRRawWinEvent -LogName $channel -Id $ids -Since $since -MaxEvents $maxPer)) {
                if ($e.TimeCreatedUtc -lt $since) { continue }   # defensive: the source already filters by StartTime
                $rec = ConvertTo-IREventRecord -Event $e -Catalog $catalog -Redactor $redactor -CommandLineMaxChars ([int]$Config.limits.commandLineMaxChars)
                if ($rec) { $res.Records.Add($rec); $count++ }
            }
            $stats[$channel] = $count
            $res.Sources.Add($channel)
            if ($count -ge $maxPer) { Add-IRCollectionError $res $channel 'truncated' "stopped at maxEvents=$maxPer; the window is incomplete" }
            if ($count -eq 0) { $res.Notes.Add("${channel}: no matching events in the window (this is not evidence that nothing happened; auditing may be off).") }
        }
        catch {
            $kind = Get-IRErrorKind $_
            if ($kind -eq 'other' -and $_.Exception.Message -match '(?i)no channel|specified channel|could not be found|not exist|log.*not found') { $kind = 'not_found' }
            Add-IRCollectionError $res $channel $kind ("$($_.Exception.Message)" -replace '\s+', ' ')
        }
    }
    $res.Records.Add([pscustomobject][ordered]@{ kind = 'event_stats'; window_start = ConvertTo-IRUtcIso $since; window_end = ConvertTo-IRUtcIso $Now; per_channel = $stats })
    if ($res.Sources.Count -eq 0) { $res.Notes.Add('No event channel could be read: authentication/system telemetry is NOT available from this run.') }
    $res.Notes.Add('Event coverage depends on audit policy and log retention; cleared or rolled-over logs cannot be recovered by this tool.')
    return (Complete-IRCollectorResult $res)
}
