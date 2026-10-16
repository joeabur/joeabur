BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    $script:Module = Get-Module WinIRToolkit
    $script:Dir = Join-Path ([IO.Path]::GetTempPath()) ("wir-ioc-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $null = New-Item -ItemType Directory $script:Dir
    function script:Write-Ioc($name, $obj) { $p = Join-Path $script:Dir $name; Set-Content -LiteralPath $p -Value ($obj | ConvertTo-Json -Depth 6); $p }
    function script:Doc($indicators) { [ordered]@{ schema_version = 1; indicators = @($indicators) } }
    function script:Arts($records) { $a = [ordered]@{}; foreach ($k in $records.Keys) { $a[$k] = [pscustomobject]@{ records = @($records[$k]) } }; $a }
    function script:Ind($t, $v) { [pscustomobject]@{ Type = $t; Value = $v; Severity = 'high'; Description = ''; Source = 'test' } }
}

Describe 'Import-IRIoc' {
    It 'loads the shipped synthetic IOC file and marks it synthetic' {
        $ioc = Import-IRIoc -Path (Join-Path $script:Root 'examples\iocs.json')
        $ioc.Synthetic | Should -BeTrue
        @($ioc.Indicators).Count | Should -Be 5
    }
    It 'normalises values and ignores duplicates with a warning' {
        $h = 'A' * 64
        $p = script:Write-Ioc 'ok.json' (script:Doc @(
                @{ type = 'sha256'; value = $h }, @{ type = 'sha256'; value = $h.ToLower() }, @{ type = 'domain'; value = 'EVIL.Example.Test.' },
                @{ type = 'ip'; value = '2001:DB8:0:0:0:0:0:1' }, @{ type = 'file_path'; value = 'C:/Users//Bob/x.EXE' }, @{ type = 'process_name'; value = 'Evil.EXE' }))
        $ioc = Import-IRIoc -Path $p
        @($ioc.Indicators).Count | Should -Be 5
        ($ioc.Indicators | Where-Object Type -eq 'domain').Value | Should -Be 'evil.example.test'
        ($ioc.Indicators | Where-Object Type -eq 'ip').Value | Should -Be '2001:db8::1'
        ($ioc.Indicators | Where-Object Type -eq 'file_path').Value | Should -Be 'c:\users\bob\x.exe'
        ($ioc.Indicators | Where-Object Type -eq 'process_name').Value | Should -Be 'evil.exe'
        ($ioc.Warnings -join ' ') | Should -Match 'duplicate'
    }
    It 'rejects malformed indicators and documents' {
        $bad = @(
            @{ type = 'sha256'; value = 'abc' }, @{ type = 'ip'; value = '999.1.1.1' }, @{ type = 'domain'; value = 'nodots' }, @{ type = 'file_path'; value = 'relative\path' },
            @{ type = 'file_path'; value = 'C:\a\..\b' }, @{ type = 'process_name'; value = 'C:\x\y.exe' }, @{ type = 'url'; value = 'x' }, @{ type = 'ip' },
            @{ type = 'ip'; value = '1.1.1.1'; severity = 'urgent' }, @{ type = 'ip'; value = '1.1.1.1'; extra = 1 })
        $i = 0
        foreach ($ind in $bad) { $p = script:Write-Ioc "bad$i.json" (script:Doc @(, $ind)); $i++; { Import-IRIoc -Path $p } | Should -Throw }
        { Import-IRIoc -Path (script:Write-Ioc 'v2.json' ([ordered]@{ schema_version = 2; indicators = @() })) } | Should -Throw
        { Import-IRIoc -Path (script:Write-Ioc 'noind.json' ([ordered]@{ schema_version = 1 })) } | Should -Throw
        { Import-IRIoc -Path (script:Write-Ioc 'extra.json' ([ordered]@{ schema_version = 1; indicators = @(); other = 1 })) } | Should -Throw
        Set-Content (Join-Path $script:Dir 'broken.json') '{ not json'
        { Import-IRIoc -Path (Join-Path $script:Dir 'broken.json') } | Should -Throw
        { Import-IRIoc -Path (Join-Path $script:Dir 'missing.json') } | Should -Throw
    }
}

Describe 'Find-IRIocMatch' {
    It 'matches every indicator type exactly and keeps evidence references' {
        $arts = script:Arts @{
            processes = @([pscustomobject]@{ pid = 1; name = 'Evil.exe'; exe = 'C:\Temp\Evil.exe'; exe_sha256 = ('a' * 64); cmdline = 'evil.exe http://c2.example.test/x 198.51.100.9' })
            network   = @([pscustomobject]@{ kind = 'socket'; remote_addr = '203.0.113.5'; local_addr = '10.0.0.1'; process = 'evil.exe' })
        }
        $ind = @((script:Ind 'sha256' ('a' * 64)), (script:Ind 'process_name' 'evil.exe'), (script:Ind 'file_path' 'c:\temp\evil.exe'), (script:Ind 'ip' '203.0.113.5'), (script:Ind 'ip' '198.51.100.9'), (script:Ind 'domain' 'c2.example.test'))
        $f = @(Find-IRIocMatch -Artifacts $arts -Indicators $ind)
        ($f.rule_id | Sort-Object -Unique) -join ',' | Should -Be 'IOC-MATCH-DOMAIN,IOC-MATCH-FILE_PATH,IOC-MATCH-IP,IOC-MATCH-PROCESS_NAME,IOC-MATCH-SHA256'
        foreach ($x in $f) { $x.classification | Should -Be 'ioc_match'; $x.evidence_ref | Should -Match '^artifacts/.+\.json#records\[\d+\]$'; ($x.recommended_next_steps -join ' ') | Should -Match 'not confirmation' }
    }
    It 'never matches on substrings by default' {
        $arts = script:Arts @{ processes = @([pscustomobject]@{ name = 'evilest.exe'; exe = 'C:\Temp\x\evil.exe'; cmdline = 'a.b.evil.example.test 203.0.113.50' }) }
        @(Find-IRIocMatch -Artifacts $arts -Indicators @((script:Ind 'process_name' 'evil.exe'), (script:Ind 'file_path' 'c:\temp'), (script:Ind 'domain' 'evil.example.test'), (script:Ind 'ip' '203.0.113.5'))).Count | Should -Be 0
    }
    It 'matches subdomains only when explicitly requested' {
        $arts = script:Arts @{ processes = @([pscustomobject]@{ cmdline = 'curl http://a.b.evil.example.test/x' }) }
        @(Find-IRIocMatch -Artifacts $arts -Indicators @(, (script:Ind 'domain' 'evil.example.test'))).Count | Should -Be 0
        @(Find-IRIocMatch -Artifacts $arts -Indicators @(, (script:Ind 'domain' 'evil.example.test')) -MatchSubdomains).Count | Should -Be 1
    }
    It 'handles empty evidence and unknown artifacts' {
        @(Find-IRIocMatch -Artifacts (script:Arts @{ processes = @() }) -Indicators @(, (script:Ind 'ip' '1.1.1.1'))).Count | Should -Be 0
        @(Find-IRIocMatch -Artifacts (script:Arts @{ weird = @([pscustomobject]@{ x = 1 }) }) -Indicators @(, (script:Ind 'ip' '1.1.1.1'))).Count | Should -Be 0
    }
}

AfterAll { Remove-Item -Recurse -Force $script:Dir -ErrorAction SilentlyContinue }
