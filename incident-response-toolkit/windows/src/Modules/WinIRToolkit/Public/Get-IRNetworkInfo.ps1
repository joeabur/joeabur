function Get-IRNetworkInfo {
    <#
    .SYNOPSIS
        Read-only listening ports and active connections with their owning processes.
    .DESCRIPTION
        Uses Get-NetTCPConnection / Get-NetUDPEndpoint and joins process name/path by owning PID. Remote endpoints are
        recorded as observed: an unfamiliar address is not labelled malicious.
    .PARAMETER Config
        Configuration hashtable. Defaults to the built-in configuration.
    .OUTPUTS
        PSCustomObject collector result.
    .NOTES
        Permissions: owning-process names for other users' sockets may be unavailable without elevation.
    .EXAMPLE
        (Get-IRNetworkInfo).Records | Where-Object state -eq 'Listen'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([System.Collections.IDictionary]$Config)
    $res = New-IRCollectorResult -Name 'network'
    $procMap = @{}
    try { foreach ($p in @(Get-IRRawProcess)) { $procMap[[int]$p.ProcessId] = $p } }
    catch { Add-IRCollectionError $res 'Win32_Process' (Get-IRErrorKind $_) 'process names unavailable for socket owners' }
    $add = {
        param($proto, $state, $la, $lp, $ra, $rp, $owner)
        $p = $null; if ($procMap.ContainsKey([int]$owner)) { $p = $procMap[[int]$owner] }
        $res.Records.Add([pscustomobject][ordered]@{
                kind = 'socket'; proto = $proto; state = $state; local_addr = $la; local_port = $lp; remote_addr = $ra; remote_port = $rp
                pid = [int]$owner; process = if ($p) { $p.Name } else { $null }; process_path = if ($p) { $p.ExecutablePath } else { $null }
            })
    }
    try {
        foreach ($c in @(Get-IRRawTcpConnection)) { & $add 'tcp' $c.State $c.LocalAddress $c.LocalPort $c.RemoteAddress $c.RemotePort $c.OwningProcess }
        $res.Sources.Add('Get-NetTCPConnection')
    }
    catch { Add-IRCaughtError $res 'Get-NetTCPConnection' $_ }
    try {
        foreach ($u in @(Get-IRRawUdpEndpoint)) { & $add 'udp' 'Listen' $u.LocalAddress $u.LocalPort '' 0 $u.OwningProcess }
        $res.Sources.Add('Get-NetUDPEndpoint')
    }
    catch { Add-IRCaughtError $res 'Get-NetUDPEndpoint' $_ }
    if ($res.Records.Count -gt 0 -and @($res.Records | Where-Object { $null -ne $_.process }).Count -eq 0) {
        $res.Notes.Add('No socket owner could be resolved to a process name; run elevated if this matters to the investigation.')
    }
    return (Complete-IRCollectorResult $res)
}
