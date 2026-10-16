# Declarative detection rules (JSON). Rule files are DATA: no expression language, nothing is ever executed.

$script:RuleOps = @('eq', 'ne', 'in', 'not_in', 'startswith_any', 'endswith_any', 'contains_any', 'regex', 'exists', 'gte', 'lte', 'truthy', 'falsy')
$script:RuleKeys = @('id', 'version', 'title', 'description', 'category', 'severity', 'confidence', 'artifact', 'type', 'when', 'why', 'false_positives', 'next_steps', 'attack', 'group_by', 'threshold', 'window_seconds', 'key_fields', 'mode', 'compare_fields', 'enabled')
$script:MaxRegexLength = 256

function Test-IRRuleCondition {
    [CmdletBinding()]
    param($Condition, [string]$Where)
    $extra = @($Condition.PSObject.Properties.Name | Where-Object { $_ -notin @('field', 'op', 'value') })
    if ($extra.Count -gt 0) { throw "$Where`: condition may only have field/op/value" }
    $f = Get-IRProp $Condition 'field'; $op = Get-IRProp $Condition 'op'
    $vp = $Condition.PSObject.Properties['value']; $val = $null
    if ($vp) { $val = $vp.Value }   # direct read: Get-IRProp would unroll single-element lists
    if ($f -isnot [string] -or $f -notmatch '^[A-Za-z0-9_.]+$') { throw "$Where`: invalid field name '$f'" }
    if ($op -notin $script:RuleOps) { throw "$Where`: unknown op '$op'; allowed: $($script:RuleOps -join ', ')" }
    if ($op -in @('in', 'not_in', 'startswith_any', 'endswith_any', 'contains_any') -and $val -isnot [System.Collections.IEnumerable]) { throw "$Where`: op $op needs a list value" }
    if ($op -in @('in', 'not_in', 'startswith_any', 'endswith_any', 'contains_any') -and $val -is [string]) { throw "$Where`: op $op needs a list value" }
    if ($op -eq 'regex') {
        if ($val -isnot [string] -or $val.Length -gt $script:MaxRegexLength -or $val -match '\([^)]*[+*][^)]*\)[+*{]') { throw "$Where`: regex too long (>$($script:MaxRegexLength)) or has nested quantifiers (ReDoS risk)" }
        try { $null = [regex]::new($val) } catch { throw "$Where`: invalid regex: $($_.Exception.Message)" }
    }
    return [pscustomobject]@{ Field = $f; Op = $op; Value = $val }
}

function Test-IRRule {
    <#
    .SYNOPSIS
        Validates one rule object and returns it with compiled conditions.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Rule, [Parameter(Mandatory)][string]$Source)
    $rid = Get-IRProp $Rule 'id'
    $w = "$Source`:$rid"
    $unknown = @($Rule.PSObject.Properties.Name | Where-Object { $_ -notin $script:RuleKeys })
    if ($unknown.Count -gt 0) { throw "$w`: unknown keys $($unknown -join ', ')" }
    if ($rid -isnot [string] -or $rid -notmatch '^WIR-[A-Z]+-[0-9]{3}$') { throw "$w`: id must look like WIR-CATEGORY-001" }
    $ver = Get-IRProp $Rule 'version'
    if (($ver -isnot [int] -and $ver -isnot [long]) -or $ver -lt 1) { throw "$w`: version must be a positive integer" }
    foreach ($k in @('title', 'description', 'category', 'artifact', 'why')) {
        $v = Get-IRProp $Rule $k
        if ($v -isnot [string] -or [string]::IsNullOrWhiteSpace($v)) { throw "$w`: '$k' is required (non-empty string)" }
    }
    if ((Get-IRProp $Rule 'severity') -notin $script:Severities) { throw "$w`: severity must be one of $($script:Severities -join ', ')" }
    if ((Get-IRProp $Rule 'confidence') -notin $script:Confidences) { throw "$w`: confidence must be one of $($script:Confidences -join ', ')" }
    $type = Get-IRProp $Rule 'type'; if (-not $type) { $type = 'match' }
    if ($type -notin @('match', 'threshold', 'baseline')) { throw "$w`: type must be match, threshold or baseline" }
    foreach ($k in @('false_positives', 'next_steps')) {
        $v = @(Get-IRProp $Rule $k)
        if ($v.Count -eq 0 -or ($v | Where-Object { $_ -isnot [string] })) { throw "$w`: '$k' must be a non-empty list of strings" }
    }
    foreach ($t in @(Get-IRProp $Rule 'attack')) { if ($t -and "$t" -notmatch '^T[0-9]{4}(\.[0-9]{3})?$') { throw "$w`: invalid ATT&CK id '$t'" } }
    $conds = @()
    foreach ($c in @(Get-IRProp $Rule 'when')) { if ($c) { $conds += Test-IRRuleCondition -Condition $c -Where $w } }
    if ($type -eq 'match' -and $conds.Count -eq 0) { throw "$w`: match rules need at least one condition" }
    if ($type -eq 'threshold') {
        if ((Get-IRProp $Rule 'group_by') -isnot [string] -or [int](Get-IRProp $Rule 'threshold') -lt 1 -or [int](Get-IRProp $Rule 'window_seconds') -lt 1) { throw "$w`: threshold rules need group_by, threshold and window_seconds" }
    }
    if ($type -eq 'baseline') {
        $kf = Get-IRProp $Rule 'key_fields'
        if ($null -eq $kf -or @($kf).Count -eq 0) { throw "$w`: baseline rules need key_fields" }
        $mode = Get-IRProp $Rule 'mode'; if (-not $mode) { $mode = 'new' }
        if ($mode -notin @('new', 'changed')) { throw "$w`: baseline mode must be 'new' or 'changed'" }
        $cf = Get-IRProp $Rule 'compare_fields'
        if ($mode -eq 'changed' -and ($null -eq $cf -or @($cf).Count -eq 0)) { throw "$w`: baseline mode 'changed' needs compare_fields" }
    }
    return [pscustomobject]@{ Raw = $Rule; Conditions = $conds; Type = $type; Id = $rid }
}

function Import-IRRule {
    <#
    .SYNOPSIS
        Loads and validates all *.json rule files in a directory (default: the shipped rules).
    .PARAMETER Path
        Rules directory.
    .OUTPUTS
        Validated rule objects. Throws on any invalid rule or duplicate id.
    .EXAMPLE
        Import-IRRule | Measure-Object
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path $script:IRConfigRoot 'rules' }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Rules directory not found: $Path" }
    $rules = New-Object 'System.Collections.Generic.List[psobject]'
    $ids = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter '*.json' -File | Sort-Object Name)) {
        $doc = Read-IRJsonFile -Path $f.FullName -MaxBytes 1000000
        if ($null -eq (Get-IRProp $doc 'rules')) { throw "$($f.Name): top level must be an object with a 'rules' list" }
        foreach ($raw in @($doc.rules)) {
            $r = Test-IRRule -Rule $raw -Source $f.Name
            if ($ids.ContainsKey($r.Id)) { throw "$($f.Name): duplicate rule id $($r.Id)" }
            $ids[$r.Id] = $true
            $rules.Add($r)
        }
    }
    return , @($rules)
}

function Test-IRConditionMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Record, $Condition, [int]$MaxChars)
    $val = Get-IRProp $Record $Condition.Field
    $op = $Condition.Op; $operand = $Condition.Value
    if ($op -eq 'exists') { return (($null -ne $val) -eq [bool]$(if ($null -ne $operand) { $operand } else { $true })) }
    if ($op -eq 'truthy') { return [bool]$val }
    if ($op -eq 'falsy') { return ($null -ne $val -and -not $val) }
    if ($null -eq $val) { return $false }
    $items = if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { @($val) } else { @($val) }
    foreach ($item in $items) {
        if ($op -in @('gte', 'lte')) {
            $d = 0.0; $o = 0.0
            if ([double]::TryParse("$item", [ref]$d) -and [double]::TryParse("$operand", [ref]$o)) {
                if (($op -eq 'gte' -and $d -ge $o) -or ($op -eq 'lte' -and $d -le $o)) { return $true }
            }
            continue
        }
        $s = "$item"; if ($s.Length -gt $MaxChars) { $s = $s.Substring(0, $MaxChars) }
        $sl = $s.ToLowerInvariant()
        switch ($op) {
            'eq' { if ($sl -eq "$operand".ToLowerInvariant()) { return $true } }
            'ne' { if ($sl -ne "$operand".ToLowerInvariant()) { return $true } }
            'in' { if (@($operand | ForEach-Object { "$_".ToLowerInvariant() }) -contains $sl) { return $true } }
            'not_in' { if (@($operand | ForEach-Object { "$_".ToLowerInvariant() }) -notcontains $sl) { return $true } }
            'startswith_any' { foreach ($o in $operand) { if ($sl.StartsWith("$o".ToLowerInvariant())) { return $true } } }
            'endswith_any' { foreach ($o in $operand) { if ($sl.EndsWith("$o".ToLowerInvariant())) { return $true } } }
            'contains_any' { foreach ($o in $operand) { if ($sl.Contains("$o".ToLowerInvariant())) { return $true } } }
            'regex' {
                try { if ([regex]::IsMatch($s, $operand, 'IgnoreCase', [TimeSpan]::FromMilliseconds(250))) { return $true } }
                catch [Text.RegularExpressions.RegexMatchTimeoutException] { }
            }
        }
    }
    return $false
}

function Test-IRRecordMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Record, $Rule, [int]$MaxChars)
    foreach ($c in $Rule.Conditions) { if (-not (Test-IRConditionMatch -Record $Record -Condition $c -MaxChars $MaxChars)) { return $false } }
    return $true
}

function Format-IRTemplate {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Template, $Record)
    return [regex]::Replace($Template, '\{([A-Za-z0-9_.]+)\}', {
            param($m)
            $v = Get-IRProp $Record $m.Groups[1].Value
            if ($null -eq $v) { return '<unavailable>' }
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = (@($v) | Select-Object -First 5) -join ', ' }
            $s = "$v"; if ($s.Length -gt 300) { $s = $s.Substring(0, 300) }
            return $s
        })
}

function New-IRFinding {
    [CmdletBinding()]
    param($Rule, $Record, [int]$Index, [string]$Why, [System.Collections.IDictionary]$Extra)
    $ev = [ordered]@{}
    foreach ($p in $Record.PSObject.Properties) {
        if ($ev.Count -ge 30) { break }
        $v = ConvertTo-IRPlainValue $p.Value
        if ($null -eq $v -or $v -is [string] -or $v -is [ValueType]) {
            if ($v -is [string] -and $v.Length -gt 500) { $v = $v.Substring(0, 500) }
            $ev[$p.Name] = $v
        }
        elseif ($v -is [System.Collections.IEnumerable]) { $ev[$p.Name] = @($v | Select-Object -First 10 | ForEach-Object { if ("$_".Length -gt 300) { "$_".Substring(0, 300) } else { $_ } }) }
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $ev[$k] = $Extra[$k] } }
    $r = $Rule.Raw
    [pscustomobject][ordered]@{
        rule_id = $r.id; rule_version = [int]$r.version; title = $r.title; observation = $Why; rationale = $r.description
        category = $r.category; severity = $r.severity; confidence = $r.confidence; classification = 'heuristic'
        artifact = $r.artifact; evidence_ref = ("artifacts/{0}.json#records[{1}]" -f $r.artifact, $Index); evidence = [pscustomobject]$ev
        false_positives = @($r.false_positives); recommended_next_steps = @($r.next_steps); attack = @(Get-IRProp $r 'attack' | Where-Object { $_ })
    }
}

function Invoke-IRRuleEvaluation {
    <#
    .SYNOPSIS
        Evaluates validated rules against loaded artifact documents. Returns Findings and Notes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Rules, [Parameter(Mandatory)] $Artifacts, $Baseline, [int]$MaxPerRule = 200, [int]$MaxChars = 2048, [int]$MaxRecords = 200000)
    $findings = New-Object 'System.Collections.Generic.List[psobject]'
    $notes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rule in $Rules) {
        $r = $rule.Raw
        if ((Get-IRProp $r 'enabled') -eq $false) { continue }
        $doc = if ($Artifacts.Contains($r.artifact)) { $Artifacts[$r.artifact] } else { $null }
        if ($null -eq $doc) { $notes.Add("$($r.id): artifact '$($r.artifact)' not present in evidence; rule not evaluated"); continue }
        if ($doc.status -in @('failed', 'skipped', 'unavailable')) { $notes.Add("$($r.id): artifact '$($r.artifact)' status is $($doc.status); rule not evaluated"); continue }
        $recs = @($doc.records)
        if ($recs.Count -gt $MaxRecords) { $notes.Add("$($r.id): only first $MaxRecords records evaluated"); $recs = $recs[0..($MaxRecords - 1)] }
        $count = 0
        if ($rule.Type -eq 'match') {
            for ($i = 0; $i -lt $recs.Count; $i++) {
                if (Test-IRRecordMatch -Record $recs[$i] -Rule $rule -MaxChars $MaxChars) {
                    $findings.Add((New-IRFinding -Rule $rule -Record $recs[$i] -Index $i -Why (Format-IRTemplate $r.why $recs[$i])))
                    $count++
                    if ($count -ge $MaxPerRule) { $notes.Add("$($r.id): finding cap $MaxPerRule reached"); break }
                }
            }
        }
        elseif ($rule.Type -eq 'threshold') {
            $groups = @{}
            for ($i = 0; $i -lt $recs.Count; $i++) {
                if (-not (Test-IRRecordMatch -Record $recs[$i] -Rule $rule -MaxChars $MaxChars)) { continue }
                $key = Get-IRProp $recs[$i] $r.group_by
                $tsText = Get-IRProp $recs[$i] 'ts'
                $ts = [DateTime]::MinValue
                if ($null -eq $key -or -not [DateTime]::TryParse("$tsText", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ts)) { continue }
                if (-not $groups.ContainsKey("$key")) { $groups["$key"] = New-Object 'System.Collections.Generic.List[psobject]' }
                $groups["$key"].Add([pscustomobject]@{ Index = $i; Ts = $ts })
            }
            foreach ($key in @($groups.Keys | Sort-Object)) {
                $evs = @($groups[$key] | Sort-Object Ts)
                $lo = 0
                for ($hi = 0; $hi -lt $evs.Count; $hi++) {
                    while (($evs[$hi].Ts - $evs[$lo].Ts).TotalSeconds -gt $r.window_seconds) { $lo++ }
                    $n = $hi - $lo + 1
                    if ($n -ge $r.threshold) {
                        $first = $recs[$evs[$lo].Index]
                        $tmpl = [pscustomobject]@{ group = $key; count = $n }
                        $why = Format-IRTemplate $r.why $tmpl
                        $refs = @($evs[$lo..$hi] | Select-Object -First 20 | ForEach-Object { "artifacts/$($r.artifact).json#records[$($_.Index)]" })
                        $findings.Add((New-IRFinding -Rule $rule -Record $first -Index $evs[$lo].Index -Why $why -Extra ([ordered]@{ group = $key; count = $n; first_seen = $evs[$lo].Ts.ToString('yyyy-MM-ddTHH:mm:ssZ'); last_seen = $evs[$hi].Ts.ToString('yyyy-MM-ddTHH:mm:ssZ'); event_refs = $refs })))
                        $count++
                        break
                    }
                }
                if ($count -ge $MaxPerRule) { break }
            }
        }
        else {
            $bdoc = if ($Baseline -and $Baseline.Contains($r.artifact)) { $Baseline[$r.artifact] } else { $null }
            if ($null -eq $bdoc) { $notes.Add("$($r.id): no baseline supplied for '$($r.artifact)'; rule not evaluated"); continue }
            $mode = Get-IRProp $r 'mode'; if (-not $mode) { $mode = 'new' }
            $index = @{}
            foreach ($b in @($bdoc.records)) {
                if (Test-IRRecordMatch -Record $b -Rule $rule -MaxChars $MaxChars) {
                    $index[(@($r.key_fields | ForEach-Object { "$(Get-IRProp $b $_)".ToLowerInvariant() }) -join '|')] = $b
                }
            }
            for ($i = 0; $i -lt $recs.Count; $i++) {
                if (-not (Test-IRRecordMatch -Record $recs[$i] -Rule $rule -MaxChars $MaxChars)) { continue }
                $k = (@($r.key_fields | ForEach-Object { "$(Get-IRProp $recs[$i] $_)".ToLowerInvariant() }) -join '|')
                $old = if ($index.ContainsKey($k)) { $index[$k] } else { $null }
                if ($mode -eq 'new' -and $null -eq $old) {
                    $findings.Add((New-IRFinding -Rule $rule -Record $recs[$i] -Index $i -Why (Format-IRTemplate $r.why $recs[$i]))); $count++
                }
                elseif ($mode -eq 'changed' -and $null -ne $old) {
                    $diff = @($r.compare_fields | Where-Object { "$(Get-IRProp $old $_)" -ne "$(Get-IRProp $recs[$i] $_)" })
                    if ($diff.Count -gt 0) {
                        $findings.Add((New-IRFinding -Rule $rule -Record $recs[$i] -Index $i -Why (Format-IRTemplate $r.why $recs[$i]) -Extra ([ordered]@{ changed_fields = $diff }))); $count++
                    }
                }
                if ($count -ge $MaxPerRule) { $notes.Add("$($r.id): finding cap $MaxPerRule reached"); break }
            }
        }
    }
    [pscustomobject]@{ Findings = @($findings); Notes = @($notes) }
}
