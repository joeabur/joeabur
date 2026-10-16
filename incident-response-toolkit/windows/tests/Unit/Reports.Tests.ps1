BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    $script:Module = Get-Module WinIRToolkit
    $script:Case = Join-Path $script:Root 'sample-data\case-001'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("wir-rep-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $null = New-Item -ItemType Directory $script:Tmp
    $script:Analysis = Invoke-IRAnalysis -Path $script:Case -IocPath (Join-Path $script:Root 'examples\iocs.json') -BaselinePath (Join-Path $script:Root 'sample-data\baseline')
    $script:Out = Join-Path $script:Tmp 'r1'
    $script:Files = @($script:Analysis | Export-IRReport -OutputPath $script:Out -EvidencePath $script:Case)
    $script:Json = Get-Content (Join-Path $script:Out 'report.json') -Raw
    $script:Report = $script:Json | ConvertFrom-Json
    function script:Fake-Finding($over) {
        $f = [ordered]@{ rule_id = 'WIR-X-001'; rule_version = 1; title = '=SUM(A1)'; observation = '<script>alert(1)</script> password=hunter2'; rationale = 'r'; category = 'c'; severity = 'high'; confidence = 'low'
            classification = 'heuristic'; artifact = 'processes'; evidence_ref = 'artifacts/p.json#records[0]'; evidence = [pscustomobject]@{ cmd = '<b>x</b>' }; false_positives = @('fp "quoted"'); recommended_next_steps = @('ns'); attack = @('T1059') }
        foreach ($k in $over.Keys) { $f[$k] = $over[$k] }
        [pscustomobject]$f
    }
}

Describe 'Export-IRReport' {
    It 'writes JSON, CSV, HTML and a manifest copy with its SHA-256' {
        @($script:Files | ForEach-Object { Split-Path -Leaf $_ } | Sort-Object) -join ',' | Should -Be 'evidence-manifest.json,evidence-manifest.sha256,findings.csv,report.html,report.json'
        $expected = (Get-Content (Join-Path $script:Out 'evidence-manifest.sha256') -Raw).Split(' ')[0]
        $expected | Should -Be (Test-IREvidenceManifest -Path $script:Case).ManifestSha256
    }
    It 'matches the documented schema and separates observations, heuristics, IOC matches and errors' {
        $v = Test-IRReportSchema -Report $script:Report
        $v.Valid | Should -BeTrue -Because ($v.Problems -join '; ')
        @($script:Report.heuristic_findings | Where-Object classification -ne 'heuristic').Count | Should -Be 0
        @($script:Report.ioc_matches | Where-Object classification -ne 'ioc_match').Count | Should -Be 0
        @($script:Report.confirmed_observations).Count | Should -BeGreaterThan 3
        $script:Report.integrity.Ok | Should -BeTrue
        @($script:Report.collection_errors | Where-Object kind -eq 'not_found').Count | Should -BeGreaterThan 0
        (($script:Report.collection_errors | ForEach-Object source) -join ' ') | Should -Match 'Sysmon'
        ($script:Report.limitations -join ' ') | Should -Match 'tamper-proof'
    }
    It 'redacts secrets everywhere' {
        $script:Json | Should -Not -Match 'hunter2'
        $script:Json | Should -Not -Match 'abc123synthetic'
        (Get-Content (Join-Path $script:Out 'report.html') -Raw) | Should -Not -Match 'hunter2'
        (Get-Content (Join-Path $script:Out 'findings.csv') -Raw) | Should -Not -Match 'hunter2'
    }
    It 'never overwrites existing reports' {
        { $script:Analysis | Export-IRReport -OutputPath $script:Out } | Should -Throw 'overwrite'
    }
    It 'rejects unsafe output paths' {
        { $script:Analysis | Export-IRReport -OutputPath 'a\..\b' } | Should -Throw
        { $script:Analysis | Export-IRReport -OutputPath '' } | Should -Throw
    }
    It 'warns prominently when integrity verification failed' {
        $copy = Join-Path $script:Tmp 'tampered'; Copy-Item -Recurse $script:Case $copy
        Add-Content (Join-Path $copy 'artifacts\network.json') ' '
        $a = Invoke-IRAnalysis -Path $copy -AllowUnverified
        $null = $a | Export-IRReport -OutputPath (Join-Path $script:Tmp 'r2') -Format Html
        (Get-Content (Join-Path $script:Tmp 'r2\report.html') -Raw) | Should -Match 'FAILED or not performed'
    }
}

Describe 'HTML report safety' {
    It 'HTML-encodes all dynamic values and contains no script or external resources' {
        $model = & $script:Module { param($a) $cfg = Get-IRConfiguration; $r = New-IRRedactor -Patterns $cfg.redaction.patterns -Enabled $false; New-IRReportModel -Analysis $a -Redactor $r } ([pscustomobject]@{
                Artifacts = [ordered]@{}; Manifest = $null; Verification = $null; IocMeta = $null; Notes = @('<img src=x onerror=alert(1)>')
                Findings = @((script:Fake-Finding @{}), (script:Fake-Finding @{ rule_id = 'IOC-MATCH-IP'; classification = 'ioc_match' })) })
        $html = & $script:Module { param($m) ConvertTo-IRHtmlText -Report $m } $model
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '<img src=x'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Match '&lt;img src=x onerror'
        $html | Should -Match 'Content-Security-Policy'
        $html | Should -Not -Match '(src|href)\s*=\s*"?https?:'
    }
    It 'escapes hostile host names in the title' {
        $model = [pscustomobject]@{ generated_at = 'x'; tool = [pscustomobject]@{ name = 'n'; version = '1' }; host = [pscustomobject]@{ hostname = '</title><script>x</script>' }; integrity = $null
            detection_counts_by_severity = [pscustomobject]@{ info = 0; low = 0; medium = 0; high = 0; critical = 0 }; ioc_counts_by_severity = [pscustomobject]@{ info = 0; low = 0; medium = 0; high = 0; critical = 0 }
            coverage = [pscustomobject]@{}; confirmed_observations = @(); heuristic_findings = @(); ioc_matches = @(); collection_errors = @(); not_assessed = @(); limitations = @(); recommended_next_steps = @() }
        $html = & $script:Module { param($m) ConvertTo-IRHtmlText -Report $m } $model
        $html | Should -Not -Match '<script>x</script>'
        $html | Should -Match '&lt;/title&gt;'
    }
}

Describe 'CSV export' {
    It 'neutralises spreadsheet formulas and escapes quotes' {
        $report = [pscustomobject]@{ heuristic_findings = @((script:Fake-Finding @{})); ioc_matches = @() }
        $csv = & $script:Module { param($r) ConvertTo-IRCsvText -Report $r } $report
        $csv | Should -Match '"''=SUM\(A1\)"'
        $csv | Should -Match 'fp ""quoted""'
        ($csv -split "`r`n")[0] | Should -Match '"rule_id","rule_version"'
    }
    It 'contains one row per finding' {
        $lines = @((Get-Content (Join-Path $script:Out 'findings.csv')) | Where-Object { $_ })
        $lines.Count | Should -Be (1 + @($script:Report.heuristic_findings).Count + @($script:Report.ioc_matches).Count)
    }
}

Describe 'Report schema validation' {
    It 'reports missing keys and invalid severities' {
        $v = Test-IRReportSchema -Report ([pscustomobject]@{ schema_version = 1 })
        $v.Valid | Should -BeFalse
        @($v.Problems).Count | Should -BeGreaterThan 5
    }
}

AfterAll { Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue }
