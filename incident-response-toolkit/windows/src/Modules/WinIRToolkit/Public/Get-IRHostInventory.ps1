function Get-IRHostInventory {
    <#
    .SYNOPSIS
        Read-only host inventory: OS version/build, uptime, time zone, installed security products and key settings.
    .DESCRIPTION
        Queries CIM/registry/Defender/firewall status only. Each failing source becomes a collection error; the other
        sources still run. Timestamps are UTC ISO 8601; the host's local time and UTC offset are retained.
    .PARAMETER Config
        Configuration hashtable (see Get-IRConfiguration). Defaults to the built-in configuration.
    .PARAMETER Now
        Reference time (UTC). Used for uptime; defaults to the current time.
    .OUTPUTS
        PSCustomObject collector result: Name, Status, Records, Errors, Sources, Notes.
    .NOTES
        Permissions: none required. Some Defender fields need elevation (reported, not escalated).
    .EXAMPLE
        Get-IRHostInventory | Select-Object -ExpandProperty Records
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([System.Collections.IDictionary]$Config, [datetime]$Now = [DateTime]::UtcNow)
    $res = New-IRCollectorResult -Name 'inventory'
    try {
        $os = Get-IRRawOperatingSystem
        $res.Sources.Add('Win32_OperatingSystem')
    }
    catch { Add-IRCaughtError $res 'Win32_OperatingSystem' $_; $os = $null }
    try { $cs = Get-IRRawComputerSystem; $res.Sources.Add('Win32_ComputerSystem') }
    catch { Add-IRCaughtError $res 'Win32_ComputerSystem' $_; $cs = $null }

    $bootIso = if ($os) { ConvertTo-IRUtcIso $os.LastBootUpTime } else { $null }
    $uptime = $null
    if ($bootIso) { $uptime = [int][Math]::Max(0, ($Now.ToUniversalTime() - [DateTime]::Parse($bootIso, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)).TotalSeconds) }
    $offset = if ($os) { Get-IRProp $os 'TimeZoneOffsetMinutes' } else { $null }
    $rec = [ordered]@{
        kind                = 'host'
        hostname            = if ($cs) { $cs.Name } else { $env:COMPUTERNAME }
        domain              = if ($cs) { $cs.Domain } else { $null }
        part_of_domain      = if ($cs) { [bool]$cs.PartOfDomain } else { $null }
        os_caption          = if ($os) { $os.Caption } else { $null }
        os_version          = if ($os) { $os.Version } else { $null }
        os_build            = if ($os) { $os.BuildNumber } else { $null }
        architecture        = if ($os) { $os.Architecture } else { $null }
        is_server           = if ($os) { ([int](Get-IRProp $os 'ProductType')) -gt 1 } else { $null }
        boot_time           = $bootIso
        uptime_seconds      = $uptime
        collected_at        = ConvertTo-IRUtcIso $Now
        local_time_original = if ($os) { "$($os.LocalDateTime)" } else { $null }
        time_zone           = if ($os) { Get-IRProp $os 'TimeZone' } else { $null }
        utc_offset_minutes  = $offset
        powershell_version  = "$($PSVersionTable.PSVersion)"
        powershell_edition  = "$($PSVersionTable.PSEdition)"
        elevated            = Test-IRElevated
    }
    $settings = [ordered]@{}
    try {
        $lua = Get-IRRawRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
        $settings['uac_enabled'] = ([int]$lua -eq 1)
        $res.Sources.Add('registry:EnableLUA')
    }
    catch { Add-IRCaughtError $res 'registry:EnableLUA' $_ }
    try {
        $fw = @(Get-IRRawFirewallProfile)
        $settings['firewall'] = [ordered]@{}
        foreach ($p in $fw) { $settings['firewall'][$p.Name] = [bool]$p.Enabled }
        $res.Sources.Add('Get-NetFirewallProfile')
    }
    catch { Add-IRCaughtError $res 'Get-NetFirewallProfile' $_ }
    try {
        $d = Get-IRRawDefender
        $settings['defender'] = [ordered]@{
            service_enabled = [bool]$d.AMServiceEnabled; antivirus_enabled = [bool]$d.AntivirusEnabled
            realtime_protection = [bool]$d.RealTimeProtectionEnabled; tamper_protected = [bool](Get-IRProp $d 'IsTamperProtected')
            signatures_updated = ConvertTo-IRUtcIso $d.AntivirusSignatureLastUpdated
        }
        $res.Sources.Add('Get-MpComputerStatus')
    }
    catch { Add-IRCaughtError $res 'Get-MpComputerStatus' $_ }
    $rec['settings'] = $settings
    $res.Records.Add([pscustomobject]$rec)

    try {
        foreach ($p in @(Get-IRRawSecurityProduct)) {
            $state = [int]$p.ProductState
            $res.Records.Add([pscustomobject][ordered]@{
                    kind = 'security_product'; name = $p.Name; product_state = $state
                    enabled = (($state -band 0x1000) -ne 0); signatures_up_to_date = (($state -band 0x10) -eq 0)
                })
        }
        $res.Sources.Add('SecurityCenter2.AntiVirusProduct')
    }
    catch {
        $kind = Get-IRErrorKind $_
        if ($kind -eq 'unavailable') { $res.Notes.Add('SecurityCenter2 is not available (Windows Server or restricted system): installed AV products were not enumerated.') }
        else { Add-IRCaughtError $res 'SecurityCenter2.AntiVirusProduct' $_ }
    }
    if (-not $rec.elevated) { $res.Notes.Add('Not elevated: some sources (Security log, Defender details, other users'' processes) may be partial.') }
    return (Complete-IRCollectorResult $res)
}
