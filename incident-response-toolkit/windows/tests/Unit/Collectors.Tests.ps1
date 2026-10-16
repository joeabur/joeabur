BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    . (Join-Path $script:Root 'tests\Fixtures\FakeWindows.ps1')
    $script:Module = Get-Module WinIRToolkit
    Install-IRFakeSource -Module $script:Module
    $script:Now = Get-FakeNow
    function script:Kind($result, $kind) { @($result.Records | Where-Object { $_.kind -eq $kind }) }
}

Describe 'Get-IRHostInventory' {
    It 'records OS, build, UTC boot time, uptime and the original local time' {
        $r = Get-IRHostInventory -Now $script:Now
        $h = (script:Kind $r 'host')[0]
        $h.hostname | Should -Be 'SYNTH-WS01'
        $h.os_build | Should -Be '22631'
        $h.boot_time | Should -Be '2026-03-09T08:00:00Z'
        $h.uptime_seconds | Should -Be 100800
        $h.local_time_original | Should -Match '14:00:00'
        $h.utc_offset_minutes | Should -Be 120
        $h.settings.uac_enabled | Should -BeTrue
        $h.settings.defender.realtime_protection | Should -BeTrue
    }
    It 'lists installed security products' {
        $r = Get-IRHostInventory -Now $script:Now
        (script:Kind $r 'security_product')[0].name | Should -Match 'Defender'
    }
    It 'degrades gracefully when sources fail and says so' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawOperatingSystem' -Body { throw 'Access is denied.' }
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawSecurityProduct' -Body { throw 'Invalid namespace' }
        $r = Get-IRHostInventory -Now $script:Now
        $r.Status | Should -Be 'partial'
        @($r.Errors | Where-Object { $_.kind -eq 'permission_denied' }).Count | Should -BeGreaterThan 0
        ($r.Notes -join ' ') | Should -Match 'SecurityCenter2'
        Install-IRFakeSource -Module $script:Module
    }
}

Describe 'Get-IRProcessInfo' {
    It 'builds parent/child relationships and redacts secrets' {
        $r = Get-IRProcessInfo
        $ps = @($r.Records | Where-Object { $_.pid -eq 4300 })[0]
        $ps.ppid | Should -Be 4200
        $ps.parent_name | Should -Be 'cmd.exe'
        $up = @($r.Records | Where-Object { $_.pid -eq 4400 })[0]
        $up.cmdline | Should -Not -Match 'hunter2'
        $up.cmdline | Should -Match '\[REDACTED\]'
        $up.exe_sha256 | Should -Be (Get-FakeStandInSha256)
        $up.signature_status | Should -Be 'NotSigned'
        $up.user | Should -Be 'SYNTH-WS01\analyst'
    }
    It 'marks processes without path or command line as limited visibility' {
        $r = Get-IRProcessInfo
        @($r.Records | Where-Object { $_.pid -eq 4600 })[0].visibility | Should -Be 'limited'
        ($r.Notes -join ' ') | Should -Match 'limited visibility'
    }
    It 'survives a failing owner lookup and continues' {
        $r = Get-IRProcessInfo
        @($r.Records | Where-Object { $_.pid -eq 4600 })[0].user | Should -BeNullOrEmpty
        $r.Status | Should -Be 'ok'
    }
    It 'reports a failed collector instead of throwing when the process source is denied' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawProcess' -Body { throw 'Access is denied.' }
        $r = Get-IRProcessInfo
        $r.Status | Should -Be 'failed'
        $r.Errors[0].kind | Should -Be 'permission_denied'
        Install-IRFakeSource -Module $script:Module
    }
    It 'records a hash error for an inaccessible executable' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawFileHash' -Body { throw 'Access to the path is denied.' }
        $r = Get-IRProcessInfo
        @($r.Records | Where-Object { $_.pid -eq 4400 })[0].exe_hash_error | Should -Match 'denied'
        Install-IRFakeSource -Module $script:Module
    }
    It 'handles an empty process list' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawProcess' -Body { }
        $r = Get-IRProcessInfo
        $r.Records.Count | Should -Be 0
        Install-IRFakeSource -Module $script:Module
    }
    It 'honours the process limit and reports truncation' {
        $cfg = Get-IRConfiguration
        $cfg.limits.maxProcesses = 3
        $r = Get-IRProcessInfo -Config $cfg
        $r.Records.Count | Should -Be 3
        @($r.Errors | Where-Object { $_.kind -eq 'truncated' }).Count | Should -Be 1
    }
}

Describe 'Get-IRNetworkInfo' {
    It 'joins sockets to owning processes' {
        $r = Get-IRNetworkInfo
        $l = @($r.Records | Where-Object { $_.local_port -eq 4444 })[0]
        $l.process | Should -Be 'updater.exe'
        $l.state | Should -Be 'Listen'
        @($r.Records | Where-Object { $_.remote_addr -eq '203.0.113.50' }).Count | Should -Be 1
    }
    It 'reports partial results when UDP enumeration is unavailable' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawUdpEndpoint' -Body { throw 'The term ''Get-NetUDPEndpoint'' is not recognized' }
        $r = Get-IRNetworkInfo
        $r.Status | Should -Be 'partial'
        $r.Errors[0].kind | Should -Be 'unavailable'
        Install-IRFakeSource -Module $script:Module
    }
}

Describe 'Get-IRAccountInfo' {
    It 'lists users, Administrators members and logon sessions' {
        $r = Get-IRAccountInfo
        @($r.Records | Where-Object { $_.kind -eq 'local_user' }).Count | Should -Be 3
        @($r.Records | Where-Object { $_.kind -eq 'group_member' -and $_.group -eq 'Administrators' }).Count | Should -Be 3
        @($r.Records | Where-Object { $_.kind -eq 'logon_session' }).Count | Should -Be 2
    }
    It 'converts "never" timestamps to null' {
        $r = Get-IRAccountInfo
        @($r.Records | Where-Object { $_.name -eq 'svc_backup' })[0].last_logon | Should -BeNullOrEmpty
    }
}

Describe 'Get-IRPersistenceInfo' {
    It 'extracts executables, checks existence and flags quoting facts' {
        $r = Get-IRPersistenceInfo
        $svc = @($r.Records | Where-Object { $_.kind -eq 'service' -and $_.name -eq 'AcmeBackup' })[0]
        $svc.exec_exists | Should -BeFalse
        $svc.unquoted_path_with_spaces | Should -BeTrue
        $bad = @($r.Records | Where-Object { $_.kind -eq 'service' -and $_.name -eq 'WinUpdateHelper' })[0]
        $bad.exec_binary | Should -Match 'updater.exe$'
        $bad.exec_sha256 | Should -Be (Get-FakeStandInSha256)
    }
    It 'redacts secrets in WMI consumer commands and never executes anything' {
        $r = Get-IRPersistenceInfo
        $w = @($r.Records | Where-Object { $_.kind -eq 'wmi_subscription' -and $_.subscription_part -eq 'Consumer' })[0]
        $w.command | Should -Not -Match 'abc123synthetic'
        $w.command | Should -Match 'REDACTED'
    }
    It 'collects scheduled task actions, Run keys, Winlogon values and startup items' {
        $r = Get-IRPersistenceInfo
        foreach ($k in 'scheduled_task', 'run_key', 'winlogon_value', 'startup_command', 'startup_folder_item') { @($r.Records | Where-Object { $_.kind -eq $k }).Count | Should -BeGreaterThan 0 }
    }
    It 'records permission errors per source and keeps the rest' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawScheduledTask' -Body { throw 'Access is denied.' }
        $r = Get-IRPersistenceInfo
        $r.Status | Should -Be 'partial'
        @($r.Errors | Where-Object { $_.source -eq 'Get-ScheduledTask' -and $_.kind -eq 'permission_denied' }).Count | Should -Be 1
        @($r.Records | Where-Object { $_.kind -eq 'service' }).Count | Should -BeGreaterThan 0
        Install-IRFakeSource -Module $script:Module
    }
    It 'is empty but successful when nothing is configured' {
        foreach ($n in 'Get-IRRawService', 'Get-IRRawScheduledTask', 'Get-IRRawStartupCommand', 'Get-IRRawStartupFolderItem', 'Get-IRRawRegistryRunValue', 'Get-IRRawWmiSubscription') { Set-IRFakeOverride -Module $script:Module -Name $n -Body { } }
        $r = Get-IRPersistenceInfo
        @($r.Records | Where-Object { $_.kind -ne 'winlogon_value' }).Count | Should -Be 0
        Install-IRFakeSource -Module $script:Module
    }
}

Describe 'Get-IREventLog' {
    It 'normalises authentication events to UTC and filters by window' {
        $r = Get-IREventLog -Log @('Security') -Hours 24 -Now $script:Now
        $fails = @($r.Records | Where-Object { $_.event_type -eq 'logon_failure' })
        $fails.Count | Should -Be 12
        $fails[0].src_ip | Should -Be '203.0.113.50'
        $fails[0].ts | Should -Match '^2026-03-10T11:'
        @($r.Records | Where-Object { $_.event_type -eq 'logon_success' })[0].logon_type | Should -Be '10'
    }
    It 'redacts secrets in service image paths' {
        $r = Get-IREventLog -Log @('System') -Hours 24 -Now $script:Now
        (@($r.Records | Where-Object { $_.event_type -eq 'service_installed' })[0]).image_path | Should -Not -Match 'hunter2'
    }
    It 'reports a missing channel (Sysmon not installed) without failing the others' {
        $r = Get-IREventLog -Log @('Security', 'Microsoft-Windows-Sysmon/Operational') -Hours 24 -Now $script:Now
        $r.Status | Should -Be 'partial'
        @($r.Errors | Where-Object { $_.kind -eq 'not_found' }).Count | Should -Be 1
        $r.Sources | Should -Contain 'Security'
    }
    It 'reports access denied for the Security log' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawWinEvent' -Body { throw 'Attempted to perform an unauthorized operation.' }
        $r = Get-IREventLog -Log @('Security') -Hours 24 -Now $script:Now
        $r.Errors[0].kind | Should -Be 'permission_denied'
        ($r.Notes -join ' ') | Should -Match 'NOT available'
        Install-IRFakeSource -Module $script:Module
    }
    It 'notes that an empty channel is not proof of no activity' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawWinEvent' -Body { }
        $r = Get-IREventLog -Log @('Security') -Hours 24 -Now $script:Now
        ($r.Notes -join ' ') | Should -Match 'not evidence'
        Install-IRFakeSource -Module $script:Module
    }
    It 'rejects an out-of-range window and unsupported channels' {
        { Get-IREventLog -Hours 99999 } | Should -Throw
        $r = Get-IREventLog -Log @('Application') -Hours 1 -Now $script:Now
        $r.Errors[0].message | Should -Match 'not in the supported list'
    }
    It 'handles malformed event data without crashing' {
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawWinEvent' -Body {
            [pscustomobject]@{ TimeCreatedUtc = [DateTime]::UtcNow; Id = 4625; ProviderName = 'x'; LogName = 'Security'; MachineName = 'm'; RecordId = 1; Level = 'Information'; Data = $null }
        }
        $r = Get-IREventLog -Log @('Security') -Hours 1 -Now ([DateTime]::UtcNow)
        @($r.Records | Where-Object { $_.event_type -eq 'logon_failure' }).Count | Should -Be 1
        Install-IRFakeSource -Module $script:Module
    }
}
