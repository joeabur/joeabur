BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    $script:Module = Get-Module WinIRToolkit
    $script:Case = Join-Path $script:Root 'sample-data\case-001'
    $script:Base = Join-Path $script:Root 'sample-data\baseline'
    $script:Analysis = Invoke-IRAnalysis -Path $script:Case -BaselinePath $script:Base
    function script:Rule($over) {
        $r = [ordered]@{ id = 'WIR-TEST-001'; version = 1; title = 't'; description = 'd'; category = 'c'; severity = 'low'; confidence = 'low'; artifact = 'processes'; why = 'pid {pid}'
            false_positives = @('fp'); next_steps = @('n'); when = @(@{ field = 'name'; op = 'eq'; value = 'x' }) }
        foreach ($k in $over.Keys) { $r[$k] = $over[$k] }
        ($r | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
    }
    function script:Validate($rule) { & $script:Module { param($r) Test-IRRule -Rule $r -Source 'test' } $rule }
    function script:Eval($rule, $records, $status = 'ok', $baseline = $null, $max = 200) {
        & $script:Module { param($r, $recs, $st, $b, $m) $v = Test-IRRule -Rule $r -Source 'test'; $a = [ordered]@{}; $a[$r.artifact] = [pscustomobject]@{ status = $st; records = $recs }
            Invoke-IRRuleEvaluation -Rules @($v) -Artifacts $a -Baseline $b -MaxPerRule $m } $rule $records $status $baseline $max
    }
}

Describe 'Shipped rules' {
    It 'all validate and carry false positives, next steps, severity and confidence' {
        $rules = Import-IRRule
        @($rules).Count | Should -BeGreaterThan 25
        foreach ($r in $rules) { @($r.Raw.false_positives).Count | Should -BeGreaterThan 0; @($r.Raw.next_steps).Count | Should -BeGreaterThan 0; $r.Raw.severity | Should -Not -BeNullOrEmpty; $r.Raw.confidence | Should -Not -BeNullOrEmpty }
        @($rules | ForEach-Object Id | Sort-Object -Unique).Count | Should -Be @($rules).Count
    }
}

Describe 'Detections on the synthetic case' {
    It 'fires the expected rules with separate severity and confidence' {
        $ids = @($script:Analysis.Findings | ForEach-Object rule_id | Sort-Object -Unique)
        foreach ($expected in 'WIR-PROC-001', 'WIR-PROC-002', 'WIR-PROC-003', 'WIR-PROC-004', 'WIR-PERS-001', 'WIR-PERS-002', 'WIR-PERS-003', 'WIR-PERS-005', 'WIR-PERS-006', 'WIR-PERS-008', 'WIR-PERS-011', 'WIR-AUTH-001', 'WIR-AUTH-003', 'WIR-AUTH-005', 'WIR-AUTH-007', 'WIR-NET-001', 'WIR-NET-002', 'WIR-ACCT-002') {
            $ids | Should -Contain $expected
        }
        $f = $script:Analysis.Findings | Where-Object rule_id -eq 'WIR-AUTH-001' | Select-Object -First 1
        $f.severity | Should -Be 'medium'
        $f.confidence | Should -Be 'medium'
        $f.evidence.count | Should -BeGreaterThan 9
        $f.attack | Should -Contain 'T1110'
    }
    It 'gives every finding id, observation, evidence, severity, confidence, rationale and next steps' {
        foreach ($f in $script:Analysis.Findings) {
            foreach ($k in 'rule_id', 'observation', 'evidence', 'severity', 'confidence', 'rationale', 'recommended_next_steps', 'evidence_ref') { $f.PSObject.Properties.Name | Should -Contain $k }
            @($f.recommended_next_steps).Count | Should -BeGreaterThan 0
        }
    }
    It 'does not flag benign evidence (unfamiliar is not malicious)' {
        $rules = & $script:Module { Import-IRRule }
        $arts = [ordered]@{ processes = [pscustomobject]@{ status = 'ok'; records = @([pscustomobject]@{ pid = 9; ppid = 1; name = 'weird.exe'; exe = 'C:\Program Files\Strange\weird.exe'; cmdline = 'weird.exe --run'; parent_name = 'explorer.exe'; signature_status = 'NotSigned' }) } }
        $r = & $script:Module { param($rules, $arts) Invoke-IRRuleEvaluation -Rules $rules -Artifacts $arts -Baseline $null } $rules $arts
        @($r.Findings).Count | Should -Be 0
    }
    It 'skips baseline rules without a baseline and says so' {
        $a = Invoke-IRAnalysis -Path $script:Case
        ($a.Notes -join "`n") | Should -Match 'WIR-PERS-011: no baseline supplied'
    }
}

Describe 'Rule engine' {
    It 'matches case-insensitively and across list values' {
        $r = script:Rule @{ when = @(@{ field = 'cmdline'; op = 'contains_any'; value = @('DownloadString(') }) }
        @((script:Eval $r @([pscustomobject]@{ pid = 1; cmdline = 'x downloadstring(y' })).Findings).Count | Should -Be 1
        @((script:Eval $r @([pscustomobject]@{ pid = 1 })).Findings).Count | Should -Be 0
    }
    It 'applies thresholds inside the time window only' {
        $r = script:Rule @{ artifact = 'events'; type = 'threshold'; group_by = 'src_ip'; threshold = 3; window_seconds = 60; why = '{count} from {group}'; when = @(@{ field = 'event_type'; op = 'eq'; value = 'bad' }) }
        $close = 0, 10, 20 | ForEach-Object { [pscustomobject]@{ event_type = 'bad'; src_ip = '1.1.1.1'; ts = ('2026-03-10T11:00:{0:00}Z' -f $_) } }
        @((script:Eval $r $close).Findings).Count | Should -Be 1
        $far = '11:00:00', '11:05:00', '11:10:00' | ForEach-Object { [pscustomobject]@{ event_type = 'bad'; src_ip = '1.1.1.1'; ts = "2026-03-10T$_`Z" } }
        @((script:Eval $r $far).Findings).Count | Should -Be 0
        @((script:Eval $r @(1..5 | ForEach-Object { [pscustomobject]@{ event_type = 'bad'; src_ip = '1.1.1.1' } })).Findings).Count | Should -Be 0
    }
    It 'detects new and changed items against a baseline' {
        $r = script:Rule @{ artifact = 'persistence'; type = 'baseline'; mode = 'changed'; key_fields = @('name'); compare_fields = @('exec_sha256'); when = @(@{ field = 'kind'; op = 'eq'; value = 'service' }); why = '{name} changed' }
        $cur = [pscustomobject]@{ kind = 'service'; name = 'S'; exec_sha256 = 'b' }
        $old = [ordered]@{ persistence = [pscustomobject]@{ status = 'ok'; records = @([pscustomobject]@{ kind = 'service'; name = 'S'; exec_sha256 = 'a' }) } }
        $f = (script:Eval $r @($cur) 'ok' $old).Findings
        @($f).Count | Should -Be 1
        $f[0].evidence.changed_fields | Should -Contain 'exec_sha256'
        @((script:Eval $r @([pscustomobject]@{ kind = 'service'; name = 'S'; exec_sha256 = 'a' }) 'ok' $old).Findings).Count | Should -Be 0
    }
    It 'does not evaluate rules for failed or missing artifacts' {
        $res = script:Eval (script:Rule @{}) @([pscustomobject]@{ name = 'x'; pid = 1 }) 'failed'
        @($res.Findings).Count | Should -Be 0
        ($res.Notes -join ' ') | Should -Match 'not evaluated'
    }
    It 'caps findings per rule' {
        $res = script:Eval (script:Rule @{}) @(1..50 | ForEach-Object { [pscustomobject]@{ name = 'x'; pid = $_ } }) 'ok' $null 5
        @($res.Findings).Count | Should -Be 5
        ($res.Notes -join ' ') | Should -Match 'cap'
    }
    It 'cannot be abused through templates' {
        $res = script:Eval (script:Rule @{ why = '{__class__} {pid} $(Get-Date)' }) @([pscustomobject]@{ name = 'x'; pid = 3 })
        $res.Findings[0].observation | Should -Match '<unavailable> 3 \$\(Get-Date\)'
    }
}

Describe 'Rule validation' {
    It 'rejects unsafe or malformed rules' {
        $bad = @(
            @{ id = 'bad-id' }, @{ severity = 'urgent' }, @{ confidence = 'sure' }, @{ false_positives = @() }, @{ unknown_key = 1 }, @{ version = 0 },
            @{ when = @(@{ field = 'x'; op = 'exec'; value = 'rm -rf' }) }, @{ when = @(@{ field = 'x y'; op = 'eq'; value = 1 }) },
            @{ when = @(@{ field = 'x'; op = 'regex'; value = '(a+)+$' }) }, @{ when = @(@{ field = 'x'; op = 'regex'; value = ('a' * 300) }) },
            @{ when = @(@{ field = 'x'; op = 'regex'; value = '[' }) }, @{ when = @(@{ field = 'x'; op = 'in'; value = 'str' }) }, @{ when = @() },
            @{ attack = @('X1') }, @{ type = 'code' }, @{ type = 'threshold' }, @{ type = 'baseline' })
        foreach ($b in $bad) { { script:Validate (script:Rule $b) } | Should -Throw }
    }
    It 'rejects duplicate ids and unreadable rule files' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("wir-rules-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
        $null = New-Item -ItemType Directory $dir
        try {
            $one = script:Rule @{}
            Set-Content (Join-Path $dir 'a.json') (@{ rules = @($one, $one) } | ConvertTo-Json -Depth 8)
            { Import-IRRule -Path $dir } | Should -Throw 'duplicate'
            Set-Content (Join-Path $dir 'a.json') '{ nope'
            { Import-IRRule -Path $dir } | Should -Throw
            Set-Content (Join-Path $dir 'a.json') '{ "other": 1 }'
            { Import-IRRule -Path $dir } | Should -Throw
            { Import-IRRule -Path (Join-Path $dir 'missing') } | Should -Throw
        }
        finally { Remove-Item -Recurse -Force $dir }
    }
}
