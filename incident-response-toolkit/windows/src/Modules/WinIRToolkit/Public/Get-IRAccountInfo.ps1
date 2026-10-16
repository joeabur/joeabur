function Get-IRAccountInfo {
    <#
    .SYNOPSIS
        Read-only review of local users, local Administrators membership and accessible logon sessions.
    .DESCRIPTION
        Collects account metadata only (no password material). Authentication events are collected by Get-IREventLog.
    .PARAMETER Config
        Configuration hashtable. Defaults to the built-in configuration.
    .OUTPUTS
        PSCustomObject collector result.
    .NOTES
        Permissions: local user and group enumeration normally works unprivileged; domain accounts are not expanded.
    .EXAMPLE
        (Get-IRAccountInfo).Records | Where-Object { $_.kind -eq 'local_user' -and $_.enabled }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([System.Collections.IDictionary]$Config)
    $res = New-IRCollectorResult -Name 'accounts'
    try {
        foreach ($u in @(Get-IRRawLocalUser)) {
            $res.Records.Add([pscustomobject][ordered]@{
                    kind = 'local_user'; name = $u.Name; enabled = [bool]$u.Enabled; sid = $u.SID
                    last_logon = ConvertTo-IRUtcIso $u.LastLogon; password_last_set = ConvertTo-IRUtcIso $u.PasswordLastSet
                    password_required = [bool]$u.PasswordRequired
                })
        }
        $res.Sources.Add('Get-LocalUser')
    }
    catch { Add-IRCaughtError $res 'Get-LocalUser' $_ }
    foreach ($group in @('Administrators', 'Remote Desktop Users')) {
        try {
            foreach ($m in @(Get-IRRawLocalGroupMember -Group $group)) {
                $res.Records.Add([pscustomobject][ordered]@{ kind = 'group_member'; group = $group; member = $m.Name; object_class = $m.ObjectClass; sid = $m.SID })
            }
            $res.Sources.Add("Get-LocalGroupMember:$group")
        }
        catch { Add-IRCaughtError $res "Get-LocalGroupMember:$group" $_ }
    }
    try {
        foreach ($s in @(Get-IRRawLogonSession)) {
            $res.Records.Add([pscustomobject][ordered]@{
                    kind = 'logon_session'; logon_id = $s.LogonId; logon_type = [int]$s.LogonType; start_time = ConvertTo-IRUtcIso $s.StartTime
                    authentication_package = $s.AuthenticationPackage; user = $s.User; domain = $s.Domain
                })
        }
        $res.Sources.Add('Win32_LogonSession')
    }
    catch { Add-IRCaughtError $res 'Win32_LogonSession' $_ }
    $res.Notes.Add('Only local accounts and sessions visible to the current token are listed; domain group nesting is not expanded.')
    return (Complete-IRCollectorResult $res)
}
