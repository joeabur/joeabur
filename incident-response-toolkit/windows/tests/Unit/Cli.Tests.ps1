BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    $script:Script = Join-Path $script:Root 'scripts\winir.ps1'
    $script:Shell = (Get-Process -Id $PID).Path
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("wir-cli-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $null = New-Item -ItemType Directory $script:Tmp
    $script:Case = Join-Path $script:Root 'sample-data\case-001'
    function script:Run-Cli([string[]]$CliArgs) {
        $out = & $script:Shell -NoProfile -NonInteractive -File $script:Script @CliArgs 2>&1
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($out | Out-String) }
    }
}

Describe 'winir.ps1 exit codes' {
    It 'Verify passes on good evidence (0) and fails on tampered evidence (3)' {
        (script:Run-Cli @('-Command', 'Verify', '-InputPath', $script:Case)).ExitCode | Should -Be 0
        $copy = Join-Path $script:Tmp 'tamper'; Copy-Item -Recurse $script:Case $copy
        Add-Content (Join-Path $copy 'artifacts\network.json') ' '
        $r = script:Run-Cli @('-Command', 'Verify', '-InputPath', $copy)
        $r.ExitCode | Should -Be 3
        $r.Output | Should -Match 'MODIFIED'
        $r.Output | Should -Match 'FAIL'
    }
    It 'Scan refuses tampered evidence (3) unless -AllowUnverified (0)' {
        $copy = Join-Path $script:Tmp 'tamper'
        (script:Run-Cli @('-Command', 'Scan', '-InputPath', $copy)).ExitCode | Should -Be 3
        (script:Run-Cli @('-Command', 'Scan', '-InputPath', $copy, '-AllowUnverified')).ExitCode | Should -Be 0
    }
    It 'Scan returns 10 with -FailOnFindings when findings exist' {
        $r = script:Run-Cli @('-Command', 'Scan', '-InputPath', $script:Case, '-FailOnFindings')
        $r.ExitCode | Should -Be 10
        $r.Output | Should -Match 'WIR-AUTH-003'
    }
    It 'returns 2 for usage errors' {
        (script:Run-Cli @('-Command', 'Verify')).ExitCode | Should -Be 2
        (script:Run-Cli @('-Command', 'Scan', '-InputPath', (Join-Path $script:Tmp 'nope'))).ExitCode | Should -Be 2
        (script:Run-Cli @('-Command', 'Collect', '-Profile', 'Nope', '-OutputPath', (Join-Path $script:Tmp 'o'))).ExitCode | Should -Be 2
        (script:Run-Cli @('-Command', 'Bogus')).ExitCode | Should -Not -Be 0
    }
    It 'returns 1 for invalid IOC files and configuration' {
        $bad = Join-Path $script:Tmp 'bad-ioc.json'; Set-Content $bad '{ "schema_version": 1, "indicators": [ { "type": "ip", "value": "nope" } ] }'
        $r = script:Run-Cli @('-Command', 'Scan', '-InputPath', $script:Case, '-IocPath', $bad)
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'invalid IP'
    }
    It 'Collect -DryRun lists operations and writes nothing' {
        $out = Join-Path $script:Tmp 'dry'
        $r = script:Run-Cli @('-Command', 'Collect', '-Profile', 'BasicTriage', '-OutputPath', $out, '-DryRun')
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'DRY RUN'
        $r.Output | Should -Match '\[persistence\]'
        $out | Should -Not -Exist
    }
    It 'Collect refuses live collection on non-Windows hosts (2)' {
        if (-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) { (script:Run-Cli @('-Command', 'Collect', '-OutputPath', (Join-Path $script:Tmp 'live'))).ExitCode | Should -Be 2 }
    }
    It 'Report writes the reports and never overwrites (1)' {
        $out = Join-Path $script:Tmp 'rep'
        (script:Run-Cli @('-Command', 'Report', '-InputPath', $script:Case, '-OutputPath', $out)).ExitCode | Should -Be 0
        (Join-Path $out 'report.json') | Should -Exist
        (script:Run-Cli @('-Command', 'Report', '-InputPath', $script:Case, '-OutputPath', $out)).ExitCode | Should -Be 1
    }
    It 'Doctor runs and mentions that the tool never elevates itself' {
        $r = script:Run-Cli @('-Command', 'Doctor')
        $r.Output | Should -Match 'never elevates itself'
    }
}

AfterAll { Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue }
