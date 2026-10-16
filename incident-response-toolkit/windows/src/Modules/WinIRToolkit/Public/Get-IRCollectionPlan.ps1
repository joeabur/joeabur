function Get-IRCollectionPlan {
    <#
    .SYNOPSIS
        Returns the planned (read-only) operations for a profile without collecting anything (dry run).
    .PARAMETER Profile
        BasicTriage, AuthenticationInvestigation, PersistenceReview or FocusedIncident.
    .PARAMETER Config
        Configuration hashtable.
    .PARAMETER Collector
        Optional override of the profile's collector list.
    .OUTPUTS
        PSCustomObject[] with Collector, Description, Permissions and Operations.
    .EXAMPLE
        Get-IRCollectionPlan -Profile BasicTriage | Format-List
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$Profile, [System.Collections.IDictionary]$Config, [string[]]$Collector)
    if (-not $Config) { $Config = Get-IRConfiguration }
    if (-not $Config.profiles.Contains($Profile)) { New-IRTerminatingError -Id IRUsage -Message "Unknown profile '$Profile'. Available: $($Config.profiles.Keys -join ', ')" }
    $names = @(if ($Collector) { $Collector } else { $Config.profiles[$Profile].collectors })
    $bad = @($names | Where-Object { $_ -notin $script:CollectorNames })
    if ($bad.Count -gt 0) { New-IRTerminatingError -Id IRUsage -Message "Unknown collector(s): $($bad -join ', '). Available: $($script:CollectorNames -join ', ')" }
    $logs = @(if ($Config.profiles[$Profile].Contains('logs')) { $Config.profiles[$Profile].logs } else { 'Security'; 'System'; 'Microsoft-Windows-PowerShell/Operational' })
    $catalog = @{
        inventory   = @('OS, computer system, time zone, uptime (Win32_OperatingSystem/ComputerSystem)', 'None (some Defender fields need elevation)', @('CIM: Win32_OperatingSystem, Win32_ComputerSystem, Win32_TimeZone', 'CIM: root/SecurityCenter2 AntiVirusProduct (client SKUs)', 'Get-MpComputerStatus, Get-NetFirewallProfile, registry: EnableLUA'))
        processes   = @('Processes with parent/child links, redacted command lines, owner, signer and SHA-256', 'None; elevation adds other users'' command lines and owners', @('CIM: Win32_Process (+ GetOwner, read-only)', 'Get-AuthenticodeSignature and SHA-256 of executables (read, never executed)'))
        network     = @('Listening ports and connections with owning process', 'None; elevation improves process attribution', @('Get-NetTCPConnection, Get-NetUDPEndpoint', 'CIM: Win32_Process (names only)'))
        accounts    = @('Local users, Administrators / Remote Desktop Users membership, logon sessions', 'None for local data', @('Get-LocalUser, Get-LocalGroupMember', 'CIM: Win32_LogonSession, Win32_LoggedOnUser'))
        persistence = @('Services, scheduled tasks, Run/RunOnce, startup items, Winlogon values, WMI event subscriptions', 'Tasks of other users and root\subscription may need elevation', @('CIM: Win32_Service, Win32_StartupCommand', 'Get-ScheduledTask / Get-ScheduledTaskInfo', 'registry: Run, RunOnce, Winlogon (read)', 'CIM: root\subscription (__EventFilter, consumers, bindings)', 'NEVER executes discovered commands'))
        events      = @(("Bounded event window ($($Config.events.windowHours)h): " + ($logs -join ', ')), 'Security log needs elevation or Event Log Readers; Sysmon/PowerShell channels may not exist', @(($logs | ForEach-Object { "Get-WinEvent -FilterHashtable (LogName=$_, selected Ids, StartTime, MaxEvents=$($Config.limits.maxEvents))" })))
    }
    foreach ($n in $names) {
        [pscustomobject]@{ Collector = $n; Description = $catalog[$n][0]; Permissions = $catalog[$n][1]; Operations = @($catalog[$n][2]) }
    }
}
