# Read-only integration tests against a REAL Windows host. They are skipped on every other platform and are NOT run in
# the portable CI jobs; they run on the windows-latest job. They never change anything and never elevate.
BeforeAll {
    $script:IsWin = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
}

Describe 'Live Windows collection (read-only)' {
    It 'collects host inventory with OS build and UTC times' -Skip:(-not (($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows)) {
        $r = Get-IRHostInventory
        $h = @($r.Records | Where-Object kind -eq 'host')[0]
        $h.os_build | Should -Not -BeNullOrEmpty
        $h.collected_at | Should -Match 'Z$'
    }
    It 'collects the process list including the current process' -Skip:(-not (($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows)) {
        $r = Get-IRProcessInfo -SkipSignature
        @($r.Records | Where-Object { $_.pid -eq $PID }).Count | Should -Be 1
    }
    It 'collects network and persistence data or reports precise errors' -Skip:(-not (($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows)) {
        $n = Get-IRNetworkInfo; $p = Get-IRPersistenceInfo -SkipSignature
        $n.Status | Should -Not -Be 'failed'
        @($p.Records | Where-Object kind -eq 'service').Count | Should -BeGreaterThan 0
    }
    It 'reports the Security log as partial when not elevated instead of failing' -Skip:(-not (($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows)) {
        $e = Get-IREventLog -Log @('Security', 'System') -Hours 1
        $e.Status | Should -BeIn @('ok', 'partial')
    }
}
