# Event catalogue and normalisation.

function Get-IREventCatalog {
    [CmdletBinding()]
    param()
    return @{
        4624 = @{ Log = 'Security'; Type = 'logon_success' }
        4625 = @{ Log = 'Security'; Type = 'logon_failure' }
        4648 = @{ Log = 'Security'; Type = 'explicit_credentials' }
        4672 = @{ Log = 'Security'; Type = 'special_privileges' }
        4688 = @{ Log = 'Security'; Type = 'process_create' }
        4720 = @{ Log = 'Security'; Type = 'user_created' }
        4728 = @{ Log = 'Security'; Type = 'group_member_added' }
        4732 = @{ Log = 'Security'; Type = 'group_member_added' }
        4756 = @{ Log = 'Security'; Type = 'group_member_added' }
        1102 = @{ Log = 'Security'; Type = 'audit_log_cleared' }
        104  = @{ Log = 'System'; Type = 'log_cleared' }
        7045 = @{ Log = 'System'; Type = 'service_installed' }
        4104 = @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Type = 'scriptblock' }
        1    = @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Type = 'sysmon_process_create' }
        3    = @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Type = 'sysmon_network_connection' }
    }
}

function ConvertTo-IREventRecord {
    <#
    .SYNOPSIS
        Normalises a raw event into a flat, redacted record. Returns $null for unsupported ids.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Event, [Parameter(Mandatory)] $Catalog, [Parameter(Mandatory)] $Redactor, [int]$CommandLineMaxChars = 2000)
    $id = [int]$Event.Id
    if (-not $Catalog.ContainsKey($id) -or $Catalog[$id].Log -ne $Event.LogName) { return $null }
    $d = $Event.Data
    $get = { param($n) if ($d -is [System.Collections.IDictionary] -and $d.Contains($n)) { $v = "$($d[$n])"; if ($v -eq '' -or $v -eq '-') { $null } else { $v } } else { $null } }
    $trunc = { param($s) if ($null -eq $s) { $null } else { $r = Protect-IRText -Text $s -Redactor $Redactor; if ($r.Length -gt $CommandLineMaxChars) { $r.Substring(0, $CommandLineMaxChars) } else { $r } } }
    $rec = [ordered]@{
        kind = 'event'; event_type = $Catalog[$id].Type; event_id = $id; log = $Event.LogName; provider = $Event.ProviderName
        ts = ConvertTo-IRUtcIso $Event.TimeCreatedUtc; computer = $Event.MachineName; record_id = $Event.RecordId; level = $Event.Level
    }
    switch ($Catalog[$id].Type) {
        'logon_success' { $rec['user'] = & $get 'TargetUserName'; $rec['domain'] = & $get 'TargetDomainName'; $rec['logon_type'] = & $get 'LogonType'; $rec['src_ip'] = & $get 'IpAddress'; $rec['workstation'] = & $get 'WorkstationName'; $rec['process'] = & $get 'ProcessName' }
        'logon_failure' { $rec['user'] = & $get 'TargetUserName'; $rec['domain'] = & $get 'TargetDomainName'; $rec['logon_type'] = & $get 'LogonType'; $rec['src_ip'] = & $get 'IpAddress'; $rec['workstation'] = & $get 'WorkstationName'; $rec['status'] = & $get 'Status'; $rec['sub_status'] = & $get 'SubStatus' }
        'explicit_credentials' { $rec['user'] = & $get 'SubjectUserName'; $rec['target_user'] = & $get 'TargetUserName'; $rec['target_server'] = & $get 'TargetServerName'; $rec['process'] = & $get 'ProcessName' }
        'special_privileges' { $rec['user'] = & $get 'SubjectUserName'; $rec['domain'] = & $get 'SubjectDomainName' }
        'process_create' { $rec['user'] = & $get 'SubjectUserName'; $rec['process'] = & $get 'NewProcessName'; $rec['parent_process'] = & $get 'ParentProcessName'; $rec['command_line'] = & $trunc (& $get 'CommandLine') }
        'user_created' { $rec['user'] = & $get 'TargetUserName'; $rec['actor'] = & $get 'SubjectUserName' }
        'group_member_added' { $rec['group'] = & $get 'TargetUserName'; $rec['member'] = & $get 'MemberName'; $rec['member_sid'] = & $get 'MemberSid'; $rec['actor'] = & $get 'SubjectUserName' }
        'audit_log_cleared' { $rec['actor'] = & $get 'SubjectUserName' }
        'log_cleared' { $rec['actor'] = & $get 'SubjectUserName' }
        'service_installed' { $rec['service_name'] = & $get 'ServiceName'; $rec['image_path'] = & $trunc (& $get 'ImagePath'); $rec['service_type'] = & $get 'ServiceType'; $rec['start_type'] = & $get 'StartType'; $rec['account'] = & $get 'AccountName' }
        'scriptblock' { $rec['script_path'] = & $get 'Path'; $rec['script_block_text'] = & $trunc (& $get 'ScriptBlockText') }
        'sysmon_process_create' { $rec['process'] = & $get 'Image'; $rec['command_line'] = & $trunc (& $get 'CommandLine'); $rec['parent_process'] = & $get 'ParentImage'; $rec['user'] = & $get 'User'; $rec['sha256'] = if ((& $get 'Hashes') -match 'SHA256=([0-9A-Fa-f]{64})') { $Matches[1].ToLowerInvariant() } else { $null } }
        'sysmon_network_connection' { $rec['process'] = & $get 'Image'; $rec['user'] = & $get 'User'; $rec['remote_addr'] = & $get 'DestinationIp'; $rec['remote_port'] = & $get 'DestinationPort'; $rec['src_ip'] = & $get 'SourceIp' }
    }
    return [pscustomobject]$rec
}
