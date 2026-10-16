# IOC file validation, normalisation and exact matching.

$script:IocTypes = @('sha256', 'process_name', 'file_path', 'ip', 'domain')
$script:IocFields = @{
    processes   = @{ sha256 = @('exe_sha256'); process_name = @('name', 'parent_name'); file_path = @('exe', 'parent_exe'); text = @('cmdline') }
    network     = @{ ip = @('remote_addr', 'local_addr'); process_name = @('process'); file_path = @('process_path') }
    persistence = @{ sha256 = @('exec_sha256', 'sha256'); file_path = @('exec_expanded', 'exec_binary', 'path'); text = @('command', 'query') }
    events      = @{ sha256 = @('sha256'); ip = @('src_ip', 'remote_addr'); file_path = @('process', 'image_path', 'script_path'); text = @('command_line', 'script_block_text', 'image_path') }
}

function ConvertTo-IRNormalizedIoc {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Value)
    $v = $Value.Trim()
    switch ($Type) {
        'sha256' { $v = $v.ToLowerInvariant(); if ($v -notmatch '^[0-9a-f]{64}$') { throw "invalid SHA-256: '$Value'" } }
        'ip' {
            $ip = $null
            if (-not [Net.IPAddress]::TryParse($v, [ref]$ip)) { throw "invalid IP address: '$Value'" }
            $v = $ip.ToString().ToLowerInvariant()
        }
        'domain' {
            $v = $v.ToLowerInvariant().TrimEnd('.')
            if ($v -notmatch '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$') { throw "invalid domain: '$Value'" }
        }
        'file_path' {
            $v = $v.Replace('/', '\')
            if ($v -notmatch '^[A-Za-z]:\\|^\\\\[^\\]+\\' -or $v.Contains([string][char]0) -or ($v -split '\\') -contains '..') { throw "file_path must be an absolute Windows path without traversal: '$Value'" }
            $v = ([regex]::Replace($v, '(?<!^)\\{2,}', '\')).TrimEnd('\').ToLowerInvariant()
        }
        'process_name' {
            if ($v -eq '' -or $v -match '[\\/\x00]' -or $v.Length -gt 255) { throw "process_name must be a bare file name without path separators: '$Value'" }
            $v = $v.ToLowerInvariant()
        }
        default { throw "unknown indicator type '$Type' (allowed: $($script:IocTypes -join ', '))" }
    }
    return $v
}

function Import-IRIoc {
    <#
    .SYNOPSIS
        Loads and validates a local IOC JSON file. Any invalid entry fails the whole file.
    .DESCRIPTION
        Schema: { "schema_version": 1, "name": "...", "synthetic": true, "indicators": [ { "type": "sha256|process_name|file_path|ip|domain",
        "value": "...", "severity": "low|medium|high|...", "description": "...", "source": "..." } ] }
        Values are normalised (lower-case, canonical IP, Windows path form); duplicates are ignored with a warning.
        The file is never downloaded, uploaded or executed.
    .PARAMETER Path
        Path to the IOC file.
    .OUTPUTS
        PSCustomObject: Name, Description, Synthetic, Indicators, Warnings.
    .EXAMPLE
        Import-IRIoc -Path .\examples\iocs.json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "IOC file not found: $Path" }
    $doc = Read-IRJsonFile -Path $Path -MaxBytes 10485760
    if ($doc -isnot [pscustomobject]) { throw 'IOC file root must be an object' }
    if ((Get-IRProp $doc 'schema_version') -ne 1) { throw 'schema_version must be 1' }
    $extraRoot = @($doc.PSObject.Properties.Name | Where-Object { $_ -notin @('schema_version', 'name', 'description', 'indicators', 'synthetic') })
    if ($extraRoot.Count -gt 0) { throw "unknown top-level keys: $($extraRoot -join ', ')" }
    $items = Get-IRProp $doc 'indicators'
    if ($null -eq $items -or $items -is [string]) { throw "'indicators' must be a list" }
    $items = @($items)
    if ($items.Count -gt 100000) { throw 'too many indicators (max 100000)' }
    $out = New-Object 'System.Collections.Generic.List[psobject]'
    $warn = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    for ($i = 0; $i -lt $items.Count; $i++) {
        $it = $items[$i]
        if ($it -isnot [pscustomobject]) { throw "indicators[$i] must be an object" }
        $extra = @($it.PSObject.Properties.Name | Where-Object { $_ -notin @('type', 'value', 'severity', 'description', 'source') })
        if ($extra.Count -gt 0) { throw "indicators[$i] has unknown keys: $($extra -join ', ')" }
        $t = Get-IRProp $it 'type'; $v = Get-IRProp $it 'value'
        if ($t -isnot [string] -or $v -isnot [string]) { throw "indicators[$i] needs string 'type' and 'value'" }
        $sev = Get-IRProp $it 'severity'; if (-not $sev) { $sev = 'medium' }
        if ($sev -notin $script:Severities) { throw "indicators[$i] severity must be one of $($script:Severities -join ', ')" }
        try { $nv = ConvertTo-IRNormalizedIoc -Type $t -Value $v } catch { throw "indicators[$i]: $($_.Exception.Message)" }
        $key = "$t|$nv"
        if ($seen.ContainsKey($key)) { $warn.Add("duplicate indicator ignored: $t $nv"); continue }
        $seen[$key] = $true
        $out.Add([pscustomobject]@{ Type = $t; Value = $nv; Severity = $sev; Description = "$(Get-IRProp $it 'description')"; Source = "$(Get-IRProp $it 'source')" })
    }
    [pscustomobject]@{ Name = Get-IRProp $doc 'name'; Description = Get-IRProp $doc 'description'; Synthetic = [bool](Get-IRProp $doc 'synthetic'); Indicators = @($out); Warnings = @($warn) }
}

function Find-IRIocMatch {
    <#
    .SYNOPSIS
        Exact-match indicators against loaded artifacts; returns one finding per indicator per evidence record.
    .DESCRIPTION
        Hashes, paths, process names and IPs must be equal after normalisation. Domains are extracted from command
        lines and command text and compared exactly (subdomain matching only with -MatchSubdomains). A match is a
        lead, NOT confirmation of compromise.
    .EXAMPLE
        Find-IRIocMatch -Artifacts $analysis.Artifacts -Indicators $ioc.Indicators
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Artifacts, [Parameter(Mandatory)][AllowEmptyCollection()] $Indicators, [switch]$MatchSubdomains, [int]$MaxFindings = 500)
    $table = @{}
    foreach ($ind in $Indicators) { if (-not $table.ContainsKey($ind.Type)) { $table[$ind.Type] = @{} }; $table[$ind.Type][$ind.Value] = $ind }
    $findings = New-Object 'System.Collections.Generic.List[psobject]'
    $seen = @{}
    $nextSteps = @('Treat this as a lead, not a verdict: an IOC match is not confirmation of compromise.', 'Review the referenced evidence record and surrounding context (parent process, timeline, other artifacts).', 'Validate the indicator''s source/provenance and age before escalating.')
    $emit = {
        param($art, $idx, $ind, $field, $observed, $rec)
        $dedupe = "$($ind.Type)|$($ind.Value)|$art|$idx"
        if ($seen.ContainsKey($dedupe) -or $findings.Count -ge $MaxFindings) { return }
        $seen[$dedupe] = $true
        $ev = [ordered]@{}
        foreach ($k in @('pid', 'name', 'exe', 'path', 'exec_binary', 'proto', 'local_port', 'remote_addr', 'remote_port', 'ts', 'event_type', 'user', 'sha256', 'exe_sha256', 'exec_sha256', 'process')) {
            if (Test-IRHasProp $rec $k) { $ev[$k] = Get-IRProp $rec $k }
        }
        $desc = if ($ind.Description) { $ind.Description } else { "Evidence value equals a supplied $($ind.Type) indicator." }
        $findings.Add([pscustomobject][ordered]@{
                rule_id = "IOC-MATCH-$($ind.Type.ToUpperInvariant())"; rule_version = 1; title = "IOC match: $($ind.Type) $($ind.Value)"; observation = "Field '$field' = '$observed' exactly matches indicator $($ind.Type)='$($ind.Value)' (indicator source: $(if ($ind.Source) { $ind.Source } else { 'unspecified' }))."
                rationale = $desc; category = 'ioc'; severity = $ind.Severity; confidence = 'medium'; classification = 'ioc_match'; artifact = $art
                evidence_ref = "artifacts/$art.json#records[$idx]"; evidence = [pscustomobject]$ev
                false_positives = @('Indicator may be stale, too generic, or from an unreliable source.', 'Benign software or analyst activity can legitimately touch the same value.')
                recommended_next_steps = $nextSteps; attack = @()
            })
    }
    foreach ($art in @($Artifacts.Keys)) {
        $spec = $script:IocFields[$art]
        if (-not $spec) { continue }
        $recs = @($Artifacts[$art].records)
        for ($idx = 0; $idx -lt $recs.Count; $idx++) {
            $rec = $recs[$idx]
            foreach ($itype in @('sha256', 'process_name', 'file_path', 'ip')) {
                if (-not $table.ContainsKey($itype) -or -not $spec.ContainsKey($itype)) { continue }
                foreach ($field in $spec[$itype]) {
                    foreach ($val in @(Get-IRProp $rec $field)) {
                        if ($null -eq $val -or "$val" -eq '') { continue }
                        try { $nv = ConvertTo-IRNormalizedIoc -Type $itype -Value "$val" } catch { continue }
                        if ($table[$itype].ContainsKey($nv)) { & $emit $art $idx $table[$itype][$nv] $field "$val" $rec }
                    }
                }
            }
            if (($table.ContainsKey('ip') -or $table.ContainsKey('domain')) -and $spec.ContainsKey('text')) {
                foreach ($field in $spec['text']) {
                    foreach ($val in @(Get-IRProp $rec $field)) {
                        if ($null -eq $val -or "$val" -eq '') { continue }
                        $text = "$val"; if ($text.Length -gt 4096) { $text = $text.Substring(0, 4096) }
                        if ($table.ContainsKey('ip')) {
                            foreach ($m in [regex]::Matches($text, '(?<![0-9A-Za-z.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z])')) {
                                $ip = $null
                                if ([Net.IPAddress]::TryParse($m.Value, [ref]$ip) -and $table['ip'].ContainsKey($ip.ToString())) { & $emit $art $idx $table['ip'][$ip.ToString()] $field $ip.ToString() $rec }
                            }
                        }
                        if ($table.ContainsKey('domain')) {
                            foreach ($m in [regex]::Matches($text.ToLowerInvariant(), '(?<![a-z0-9-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?![a-z0-9-])')) {
                                $d = $m.Value
                                if ($table['domain'].ContainsKey($d)) { & $emit $art $idx $table['domain'][$d] $field $d $rec }
                                elseif ($MatchSubdomains) { foreach ($base in $table['domain'].Keys) { if ($d.EndsWith(".$base")) { & $emit $art $idx $table['domain'][$base] $field $d $rec } } }
                            }
                        }
                    }
                }
            }
        }
    }
    return $findings.ToArray()
}
