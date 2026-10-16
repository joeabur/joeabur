# Report model construction and renderers (JSON, CSV, safely escaped HTML).

$script:StaticNotAssessed = @(
    'Memory contents, disk slack/unallocated space and deleted-file recovery (live collection only).',
    'Browser profiles, credential stores (LSASS, DPAPI, vault), private keys and credential hashes are never collected by design.',
    'Kernel-mode malware and anything that falsifies what user-mode APIs return cannot be assessed from user space.',
    'Remote/centralised logs, other hosts, and persistence mechanisms outside the documented list (COM hijacks, AppInit, IFEO, drivers, BITS).'
)
$script:CsvFields = @('rule_id', 'rule_version', 'classification', 'severity', 'confidence', 'category', 'title', 'artifact', 'evidence_ref', 'observation', 'rationale', 'attack', 'false_positives', 'recommended_next_steps')

function Get-IRObservation {
    [CmdletBinding()]
    param($Artifacts, $Manifest)
    $obs = New-Object 'System.Collections.Generic.List[string]'
    if ($Artifacts.Contains('inventory')) {
        $h = @($Artifacts['inventory'].records | Where-Object { $_.kind -eq 'host' }) | Select-Object -First 1
        if ($h) { $obs.Add("Host $($h.hostname) runs $($h.os_caption) (version $($h.os_version), build $($h.os_build), $($h.architecture)); PowerShell $($h.powershell_version) ($($h.powershell_edition)); elevated=$($h.elevated); uptime $($h.uptime_seconds)s.") }
    }
    if ($Artifacts.Contains('processes')) {
        $p = @($Artifacts['processes'].records)
        $obs.Add("$($p.Count) processes were recorded; $(@($p | Where-Object { $_.visibility -eq 'limited' }).Count) had limited visibility.")
    }
    if ($Artifacts.Contains('network')) {
        $s = @($Artifacts['network'].records | Where-Object { $_.kind -eq 'socket' })
        $obs.Add("$($s.Count) sockets recorded, $(@($s | Where-Object { $_.state -eq 'Listen' }).Count) listening.")
    }
    if ($Artifacts.Contains('persistence')) {
        $g = @($Artifacts['persistence'].records | Group-Object kind | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })
        $obs.Add("Persistence items: $($g -join ', ').")
    }
    if ($Artifacts.Contains('events')) {
        $g = @($Artifacts['events'].records | Where-Object { $_.kind -eq 'event' } | Group-Object event_type | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })
        $obs.Add("Events in window: $(if ($g.Count) { $g -join ', ' } else { 'none' }).")
    }
    if ($Manifest) { $obs.Add("Collection ran $($Manifest.started_at) to $($Manifest.finished_at) (UTC); privileged=$($Manifest.privileged).") }
    return @($obs)
}

function New-IRReportModel {
    <#
    .SYNOPSIS
        Builds the report object (redacted) from an analysis result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Analysis, [Parameter(Mandatory)] $Redactor)
    $arts = $Analysis.Artifacts; $manifest = $Analysis.Manifest
    $heur = @($Analysis.Findings | Where-Object { $_.classification -eq 'heuristic' })
    $iocs = @($Analysis.Findings | Where-Object { $_.classification -eq 'ioc_match' })
    $errors = New-Object 'System.Collections.Generic.List[psobject]'
    $coverage = [ordered]@{}
    $unexamined = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $arts.Keys) {
        $st = [string]$arts[$name].status
        if (-not $coverage.Contains($st)) { $coverage[$st] = @() }
        $coverage[$st] = @($coverage[$st]) + $name
        foreach ($e in @($arts[$name].errors)) { $errors.Add([pscustomobject][ordered]@{ artifact = $name; source = $e.source; kind = $e.kind; message = $e.message }) }
    }
    if ($manifest) {
        foreach ($n in @($manifest.coverage.skipped)) { $unexamined.Add("collector '$n' was not run") }
        foreach ($a in @($manifest.artifacts)) { if ($a.status -in @('partial', 'failed', 'unavailable')) { $unexamined.Add("collector '$($a.name)' status=$($a.status)") } }
    }
    $count = { param($set) $o = [ordered]@{}; foreach ($s in $script:Severities) { $o[$s] = @($set | Where-Object { $_.severity -eq $s }).Count }; $o }
    $steps = New-Object 'System.Collections.Generic.List[string]'
    if ($Analysis.Verification -and -not $Analysis.Verification.Ok) { $steps.Add('Evidence integrity verification FAILED: do not rely on these results until resolved.') }
    if ($iocs.Count) { $steps.Add('Triage IOC matches first: validate indicator provenance and trace each evidence reference.') }
    if ($heur.Count) { $steps.Add('Review heuristic findings by severity; each lists false positives and next steps.') }
    if ($errors.Count) { $steps.Add('Review collection errors; re-run affected collectors elevated only if justified and authorised.') }
    $steps.Add('Preserve the evidence directory and store a copy of the manifest SHA-256 separately.')
    $model = [ordered]@{
        schema_version = 1
        tool = [ordered]@{ name = $script:ToolName; version = $script:ToolVersion }
        generated_at = Get-IRUtcNowIso
        platform = 'Windows'
        host = if ($manifest) { $manifest.host } else { $null }
        scope = [ordered]@{ profile = Get-IRProp $manifest 'profile'; collectors_requested = Get-IRProp $manifest 'collectors_requested'; started_at = Get-IRProp $manifest 'started_at'; finished_at = Get-IRProp $manifest 'finished_at'; privileged = Get-IRProp $manifest 'privileged'; event_window_hours = Get-IRProp $manifest 'event_window_hours' }
        integrity = $Analysis.Verification
        artifact_counts = [ordered]@{}
        coverage = $coverage
        detection_counts_by_severity = & $count $heur
        ioc_counts_by_severity = & $count $iocs
        confirmed_observations = @(Get-IRObservation -Artifacts $arts -Manifest $manifest)
        heuristic_findings = $heur
        ioc_matches = $iocs
        ioc_file = $Analysis.IocMeta
        collection_errors = @($errors)
        not_assessed = @($script:StaticNotAssessed) + @($unexamined) + @($Analysis.Notes)
        limitations = $script:Limitations
        recommended_next_steps = @($steps)
    }
    foreach ($n in $arts.Keys) { $model.artifact_counts[$n] = @($arts[$n].records).Count }
    return (Protect-IRObject -InputObject ([pscustomobject]$model) -Redactor $Redactor)
}

function ConvertTo-IRCsvText {
    <#
    .SYNOPSIS
        Renders findings as CSV. Cells that could be interpreted as spreadsheet formulas are prefixed with an apostrophe.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Report)
    $q = {
        param($v)
        $s = "$v"
        if ($s.Length -gt 0 -and ('=+-@'.IndexOf($s[0]) -ge 0 -or $s[0] -eq "`t" -or $s[0] -eq "`r")) { $s = "'" + $s }
        '"' + $s.Replace('"', '""').Replace("`r", ' ').Replace("`n", ' ') + '"'
    }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add(($script:CsvFields | ForEach-Object { & $q $_ }) -join ',')
    foreach ($f in @($Report.heuristic_findings) + @($Report.ioc_matches)) {
        $cells = foreach ($k in $script:CsvFields) {
            $v = Get-IRProp $f $k
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = @($v) -join ' | ' }
            & $q $v
        }
        $lines.Add($cells -join ',')
    }
    return ($lines -join "`r`n") + "`r`n"
}

function ConvertTo-IRHtmlText {
    <#
    .SYNOPSIS
        Renders the report as a single self-contained HTML page. EVERY dynamic value is HTML-encoded; no scripts, no
        external resources, restrictive Content-Security-Policy.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Report)
    $e = { param($v) if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = @($v) -join ', ' }; [Net.WebUtility]::HtmlEncode("$v") }
    $sb = New-Object Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; img-src data:">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine("<title>Windows IR report - $(& $e (Get-IRProp $Report 'host.hostname'))</title>")
    $null = $sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;max-width:70rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top}th{background:#eee}.sev-critical,.sev-high{color:#a00;font-weight:bold}.sev-medium{color:#a60}.note{background:#fff7d6;border:1px solid #e0c060;padding:8px}code{background:#f2f2f2;padding:0 3px}</style></head><body>')
    $null = $sb.AppendLine("<h1>Windows Incident Response report</h1><p>Generated $(& $e $Report.generated_at) UTC &middot; $(& $e $Report.tool.name) $(& $e $Report.tool.version) &middot; host <strong>$(& $e (Get-IRProp $Report 'host.hostname'))</strong></p>")
    $null = $sb.AppendLine('<p class="note">Findings are indicators and leads. A finding or IOC match is <strong>not</strong> confirmation of compromise, and the absence of findings is <strong>not</strong> proof that the host is clean, especially when collection coverage is incomplete.</p>')
    $integ = $Report.integrity
    $integText = if ($integ -and $integ.Ok) { "PASSED ($(& $e $integ.Verified) files verified)" } else { 'FAILED or not performed: treat results with caution' }
    $null = $sb.AppendLine("<h2>Integrity</h2><p>Manifest verification: <strong>$(& $e $integText)</strong></p>")
    $null = $sb.AppendLine('<h2>Counts</h2><table><tr><th>Severity</th><th>Heuristic findings</th><th>IOC matches</th></tr>')
    foreach ($s in @($script:Severities | Sort-Object { - [array]::IndexOf($script:Severities, $_) })) {
        $null = $sb.AppendLine("<tr><td>$(& $e $s)</td><td>$(& $e $Report.detection_counts_by_severity.$s)</td><td>$(& $e $Report.ioc_counts_by_severity.$s)</td></tr>")
    }
    $null = $sb.AppendLine('</table><h2>Collection coverage</h2><table><tr><th>Status</th><th>Artifacts</th></tr>')
    foreach ($k in $Report.coverage.PSObject.Properties) { $null = $sb.AppendLine("<tr><td>$(& $e $k.Name)</td><td>$(& $e $k.Value)</td></tr>") }
    $null = $sb.AppendLine('</table><h2>Confirmed observations</h2><ul>')
    foreach ($o in @($Report.confirmed_observations)) { $null = $sb.AppendLine("<li>$(& $e $o)</li>") }
    foreach ($section in @(@('Heuristic findings', 'heuristic_findings'), @('IOC matches (a match is not a confirmed compromise)', 'ioc_matches'))) {
        $null = $sb.AppendLine("</ul><h2>$(& $e $section[0])</h2>")
        $items = @($Report.($section[1]))
        if ($items.Count -eq 0) { $null = $sb.AppendLine('<p>None.</p>'); continue }
        $null = $sb.AppendLine('<table><tr><th>ID</th><th>Severity / confidence</th><th>Observation</th><th>Rationale</th><th>Evidence</th><th>False positives</th><th>Next steps</th></tr>')
        foreach ($f in $items) {
            $null = $sb.AppendLine("<tr><td>$(& $e $f.rule_id) v$(& $e $f.rule_version)<br>$(& $e $f.title)</td><td class=""sev-$(& $e $f.severity)"">$(& $e $f.severity) / $(& $e $f.confidence)</td><td>$(& $e $f.observation)</td><td>$(& $e $f.rationale)</td><td><code>$(& $e $f.evidence_ref)</code></td><td>$(& $e $f.false_positives)</td><td>$(& $e $f.recommended_next_steps)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }
    $null = $sb.AppendLine('<h2>Collection errors</h2>')
    $errs = @($Report.collection_errors)
    if ($errs.Count -eq 0) { $null = $sb.AppendLine('<p>None.</p>') }
    else {
        $null = $sb.AppendLine('<table><tr><th>Artifact</th><th>Source</th><th>Kind</th><th>Message</th></tr>')
        foreach ($x in $errs) { $null = $sb.AppendLine("<tr><td>$(& $e $x.artifact)</td><td>$(& $e $x.source)</td><td>$(& $e $x.kind)</td><td>$(& $e $x.message)</td></tr>") }
        $null = $sb.AppendLine('</table>')
    }
    $null = $sb.AppendLine('<h2>Areas not assessed</h2><ul>')
    foreach ($x in @($Report.not_assessed)) { $null = $sb.AppendLine("<li>$(& $e $x)</li>") }
    $null = $sb.AppendLine('</ul><h2>Known limitations</h2><ul>')
    foreach ($x in @($Report.limitations)) { $null = $sb.AppendLine("<li>$(& $e $x)</li>") }
    $null = $sb.AppendLine('</ul><h2>Recommended next steps</h2><ol>')
    foreach ($x in @($Report.recommended_next_steps)) { $null = $sb.AppendLine("<li>$(& $e $x)</li>") }
    $null = $sb.AppendLine('</ol></body></html>')
    return $sb.ToString()
}

function Test-IRReportSchema {
    <#
    .SYNOPSIS
        Checks a report object against the documented schema (src/Configuration/schemas/report.schema.json).
    .OUTPUTS
        PSCustomObject: Valid, Problems.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report)
    $schema = Read-IRJsonFile -Path (Join-Path $script:IRConfigRoot 'schemas/report.schema.json')
    $problems = New-Object 'System.Collections.Generic.List[string]'
    foreach ($k in @($schema.required)) { if (-not (Test-IRHasProp $Report $k)) { $problems.Add("missing top-level key: $k") } }
    foreach ($section in @('heuristic_findings', 'ioc_matches')) {
        $items = @(Get-IRProp $Report $section | Where-Object { $null -ne $_ })
        for ($i = 0; $i -lt $items.Count; $i++) {
            foreach ($k in @($schema.finding_required)) { if (-not (Test-IRHasProp $items[$i] $k)) { $problems.Add("$section[$i] missing key: $k") } }
            if ($items[$i].severity -notin $script:Severities) { $problems.Add("$section[$i] invalid severity") }
            if ($items[$i].confidence -notin $script:Confidences) { $problems.Add("$section[$i] invalid confidence") }
        }
    }
    foreach ($s in $script:Severities) { if (-not (Test-IRHasProp (Get-IRProp $Report 'detection_counts_by_severity') $s)) { $problems.Add("detection_counts_by_severity missing $s") } }
    [pscustomobject]@{ Valid = ($problems.Count -eq 0); Problems = @($problems) }
}
