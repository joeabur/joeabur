function Get-IRPlatformInfo {
    <#
    .SYNOPSIS
        Describes the current platform and whether live collection is supported here.
    .DESCRIPTION
        Reports OS, PowerShell edition/version, elevation, and availability of the cmdlets the collectors rely on.
        Missing cmdlets degrade the corresponding collector; they are never installed automatically.
    .OUTPUTS
        PSCustomObject
    .NOTES
        Permissions: none.
    .EXAMPLE
        Get-IRPlatformInfo | Format-List
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    $windows = Test-IRWindowsHost
    $cmds = [ordered]@{}
    foreach ($c in @('Get-CimInstance', 'Get-WinEvent', 'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-ScheduledTask', 'Get-LocalUser', 'Get-LocalGroupMember', 'Get-AuthenticodeSignature', 'Get-MpComputerStatus', 'Get-NetFirewallProfile')) {
        $cmds[$c] = [bool](Get-Command -Name $c -ErrorAction SilentlyContinue)
    }
    $osName = if ($windows) { try { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { 'Windows (version query failed)' } } else { [Runtime.InteropServices.RuntimeInformation]::OSDescription }
    [pscustomobject][ordered]@{
        tool_version = $script:ToolVersion; is_windows = $windows; os = $osName
        powershell_version = "$($PSVersionTable.PSVersion)"; powershell_edition = "$($PSVersionTable.PSEdition)"
        elevated = Test-IRElevated; live_collection_supported = $windows
        execution_policy = if ($windows) { try { "$(Get-ExecutionPolicy)" } catch { 'unknown' } } else { 'n/a' }
        cmdlets = [pscustomobject]$cmds; timestamp_utc = Get-IRUtcNowIso
    }
}
