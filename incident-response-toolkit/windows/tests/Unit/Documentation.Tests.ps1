BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    $script:Docs = @(Get-Item (Join-Path $script:Root 'README.md'), (Join-Path $script:Root 'CONTRIBUTING.md')) + @(Get-ChildItem (Join-Path $script:Root 'docs') -Filter '*.md')
}

Describe 'Documentation' {
    It 'ships every required guide and links it from the README' {
        $readme = Get-Content (Join-Path $script:Root 'README.md') -Raw
        foreach ($d in 'getting-started', 'walkthrough', 'user-guide', 'configuration', 'troubleshooting', 'security-and-limitations', 'examples') {
            (Join-Path $script:Root "docs/$d.md") | Should -Exist
            $readme | Should -Match ([regex]::Escape("docs/$d.md"))
        }
    }
    It 'has resolvable relative links' {
        foreach ($doc in $script:Docs) {
            $text = Get-Content $doc.FullName -Raw
            foreach ($m in [regex]::Matches($text, '\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)')) {
                $target = $m.Groups[1].Value
                if ($target -match '^(https?:|mailto:)' -or $target.StartsWith('<')) { continue }
                $full = Join-Path $doc.DirectoryName $target
                (Test-Path -LiteralPath $full) | Should -BeTrue -Because "$($doc.Name) links to $target"
            }
        }
    }
    It 'references only repository paths that exist' {
        foreach ($doc in $script:Docs) {
            $text = Get-Content $doc.FullName -Raw
            foreach ($m in [regex]::Matches($text, '(?<![\w/.-])\.?/?((?:examples|sample-data|scripts|src|tests|docs)/[\w./-]+\.\w+)')) {
                $p = $m.Groups[1].Value
                if ($p -match '[<>*]' -or $p -match 'my-imported|winir-|case-001/|baseline/') { continue }
                (Test-Path -LiteralPath (Join-Path $script:Root $p)) | Should -BeTrue -Because "$($doc.Name) references $p"
            }
        }
    }
    It 'documents only commands that exist' {
        $exported = (Get-Command -Module WinIRToolkit).Name
        foreach ($doc in $script:Docs) {
            $text = Get-Content $doc.FullName -Raw
            foreach ($m in [regex]::Matches($text, '\b((?:Get|Invoke|Import|Export|Test|Find|Protect)-IR[A-Za-z]+)\b')) {
                $name = $m.Groups[1].Value
                if ($name -like '*Raw*' -or $name -in 'Get-IRProp') { continue }
                $exported | Should -Contain $name -Because "$($doc.Name) mentions $name"
            }
        }
    }
    It 'documents only configuration keys that exist' {
        $cfg = Get-IRConfiguration
        $text = Get-Content (Join-Path $script:Root 'docs/configuration.md') -Raw
        foreach ($m in [regex]::Matches($text, '`((?:limits|events|detection|ioc|redaction)\.[A-Za-z]+)`')) {
            $section, $key = $m.Groups[1].Value.Split('.')
            $cfg[$section].Contains($key) | Should -BeTrue -Because $m.Groups[1].Value
        }
    }
    It 'ships a valid example configuration' {
        { Get-IRConfiguration -Path (Join-Path $script:Root 'examples/config.example.json') } | Should -Not -Throw
    }
    It 'never tells users to weaken the machine-wide execution policy' {
        foreach ($doc in $script:Docs) {
            (Get-Content $doc.FullName -Raw) | Should -Not -Match 'Set-ExecutionPolicy\s+(-Scope\s+LocalMachine\s+)?(Unrestricted|Bypass)'
        }
    }
}

Describe 'Sample data and expected results' {
    It 'matches the expected findings and the documented schema' {
        $case = Join-Path $script:Root 'sample-data/case-001'
        (Test-IREvidenceManifest -Path $case).Ok | Should -BeTrue
        $a = Invoke-IRAnalysis -Path $case -IocPath (Join-Path $script:Root 'examples/iocs.json') -BaselinePath (Join-Path $script:Root 'sample-data/baseline')
        $expected = Get-Content (Join-Path $script:Root 'examples/expected-results/scan-findings.json') -Raw | ConvertFrom-Json
        @($a.Findings).Count | Should -Be @($expected).Count
        $got = @($a.Findings | Sort-Object rule_id, evidence_ref | ForEach-Object { "$($_.rule_id)|$($_.severity)|$($_.confidence)|$($_.evidence_ref)" })
        $exp = @($expected | ForEach-Object { "$($_.rule_id)|$($_.severity)|$($_.confidence)|$($_.evidence_ref)" })
        ($got -join "`n") | Should -Be ($exp -join "`n")
    }
    It 'contains only synthetic indicators' {
        $ioc = Get-Content (Join-Path $script:Root 'examples/iocs.json') -Raw | ConvertFrom-Json
        $ioc.synthetic | Should -BeTrue
        foreach ($i in $ioc.indicators) {
            if ($i.type -eq 'ip') { $i.value | Should -Match '^(203\.0\.113|198\.51\.100|192\.0\.2)\.' }
            if ($i.type -eq 'domain') { $i.value | Should -Match '\.example\.test$' }
        }
    }
    It 'runs the demo script successfully' {
        $shell = (Get-Process -Id $PID).Path
        $out = & $shell -NoProfile -NonInteractive -File (Join-Path $script:Root 'scripts/Invoke-Demo.ps1') -OutputRoot ([IO.Path]::GetTempPath()) 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $out | Should -Match 'Demo OK'
        Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter 'winir-demo-*' | Remove-Item -Recurse -Force
    }
}
