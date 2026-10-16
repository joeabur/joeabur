BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    $script:Module = Get-Module WinIRToolkit
    function script:InModule([scriptblock]$Block, [object[]]$ArgumentList) { & $script:Module $Block @ArgumentList }
}

Describe 'Get-IRCommandLineExecutable' {
    It 'handles quoted, unquoted and argument-bearing command lines' {
        script:InModule { Get-IRCommandLineExecutable '"C:\Program Files\App\app.exe" --x' } | Should -Be 'C:\Program Files\App\app.exe'
        script:InModule { Get-IRCommandLineExecutable 'C:\Windows\System32\svchost.exe -k netsvcs' } | Should -Be 'C:\Windows\System32\svchost.exe'
        script:InModule { Get-IRCommandLineExecutable 'C:\Program Files\App\app.exe -service' } | Should -Be 'C:\Program Files\App\app.exe'
        script:InModule { Get-IRCommandLineExecutable 'powershell.exe -nop' } | Should -Be 'powershell.exe'
    }
    It 'returns null for empty input' {
        script:InModule { Get-IRCommandLineExecutable '' } | Should -BeNullOrEmpty
        script:InModule { Get-IRCommandLineExecutable $null } | Should -BeNullOrEmpty
    }
}

Describe 'Test-IRUnquotedServicePath' {
    It 'flags only unquoted paths whose executable path contains a space' {
        script:InModule { Test-IRUnquotedServicePath 'C:\Program Files\Foo\bar.exe -x' } | Should -BeTrue
        script:InModule { Test-IRUnquotedServicePath '"C:\Program Files\Foo\bar.exe" -x' } | Should -BeFalse
        script:InModule { Test-IRUnquotedServicePath 'C:\Windows\System32\svchost.exe -k netsvcs' } | Should -BeFalse
        script:InModule { Test-IRUnquotedServicePath '' } | Should -BeFalse
    }
}

Describe 'ConvertTo-IRUtcIso' {
    It 'normalises DateTime, DateTimeOffset and strings to UTC ISO 8601' {
        script:InModule { ConvertTo-IRUtcIso ([DateTime]::SpecifyKind([DateTime]'2026-03-10T10:00:00', 'Utc')) } | Should -Be '2026-03-10T10:00:00Z'
        script:InModule { ConvertTo-IRUtcIso ([DateTimeOffset]::Parse('2026-03-10T12:00:00+02:00')) } | Should -Be '2026-03-10T10:00:00Z'
        script:InModule { ConvertTo-IRUtcIso '2026-03-10T12:00:00+02:00' } | Should -Be '2026-03-10T10:00:00Z'
    }
    It 'returns null for empty, invalid and sentinel values' {
        script:InModule { ConvertTo-IRUtcIso $null } | Should -BeNullOrEmpty
        script:InModule { ConvertTo-IRUtcIso 'not a date' } | Should -BeNullOrEmpty
        script:InModule { ConvertTo-IRUtcIso ([DateTime]'1601-01-01') } | Should -BeNullOrEmpty
    }
}

Describe 'Get-IRErrorKind' {
    It 'classifies common failures' {
        script:InModule { Get-IRErrorKind ([UnauthorizedAccessException]::new('x')) } | Should -Be 'permission_denied'
        script:InModule { Get-IRErrorKind ([Exception]::new('Attempted to perform an unauthorized operation.')) } | Should -Be 'permission_denied'
        script:InModule { Get-IRErrorKind ([Exception]::new('The term ''Get-X'' is not recognized')) } | Should -Be 'unavailable'
        script:InModule { Get-IRErrorKind ([IO.FileNotFoundException]::new('gone')) } | Should -Be 'not_found'
        script:InModule { Get-IRErrorKind ([Exception]::new('weird')) } | Should -Be 'other'
    }
}

Describe 'Configuration' {
    It 'loads defaults and validates profiles' {
        $c = Get-IRConfiguration
        $c.profiles.Keys | Should -Contain 'BasicTriage'
        @($c.profiles.FocusedIncident.collectors).Count | Should -BeGreaterThan 3
    }
    It 'merges a valid override and rejects invalid ones' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("wir-cfg-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
        $null = New-Item -ItemType Directory $dir
        try {
            $good = Join-Path $dir 'good.json'; Set-Content $good '{ "events": { "windowHours": 6 } }'
            (Get-IRConfiguration -Path $good).events.windowHours | Should -Be 6
            $cases = @('{ "nonsense": 1 }', '{ "limits": { "nope": 1 } }', '{ "limits": { "maxProcesses": -5 } }', '{ "limits": { "maxProcesses": true } }',
                '{ "events": { "windowHours": 99999 } }', '{ "profiles": { "x": { "collectors": ["bogus"] } } }', '{ "profiles": { "x": { "collectors": [] } } }',
                '{ "redaction": { "extraPatterns": [ { "pattern": "[" } ] } }', '[1,2]', '{ bad json', '{ "schemaVersion": 99 }')
            $i = 0
            foreach ($text in $cases) {
                $f = Join-Path $dir ("bad$i.json"); Set-Content $f $text; $i++
                { Get-IRConfiguration -Path $f } | Should -Throw
            }
            { Get-IRConfiguration -Path (Join-Path $dir 'missing.json') } | Should -Throw
        }
        finally { Remove-Item -Recurse -Force $dir }
    }
}

Describe 'Redaction' {
    It 'redacts keyword assignments, CLI flags, URL credentials, bearer tokens and AWS keys' {
        $cfg = Get-IRConfiguration
        $r = script:InModule { param($p) New-IRRedactor -Patterns $p } @(, $cfg.redaction.patterns)
        $texts = @{
            'tool.exe --password=hunter2' = 'hunter2'; 'curl https://u:s3cret@host/x' = 's3cret'; 'Authorization: Bearer abcdefghijklmnop' = 'abcdefghijklmnop'
            'key AKIAABCDEFGHIJKLMNOP' = 'AKIAABCDEFGHIJKLMNOP'; 'token=abc123' = 'abc123'; 'net use \\srv\share P@ssw0rd /user:bob' = 'P@ssw0rd'
        }
        foreach ($t in $texts.Keys) {
            $out = script:InModule { param($t, $r) Protect-IRText -Text $t -Redactor $r } @($t, $r)
            $out | Should -Not -Match ([regex]::Escape($texts[$t]))
        }
    }
    It 'can be disabled and leaves benign text intact' {
        $r = script:InModule { New-IRRedactor -Patterns @() -Enabled $false }
        script:InModule { param($r) Protect-IRText -Text 'password=x' -Redactor $r } @($r) | Should -Be 'password=x'
    }
}
