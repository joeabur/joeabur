function Export-IRReport {
    <#
    .SYNOPSIS
        Writes JSON, CSV and HTML reports (plus a copy of the evidence manifest and its SHA-256) from an analysis result.
    .DESCRIPTION
        Reports are redacted with the configured patterns. Files are created with CreateNew: existing files are never
        overwritten. The HTML report HTML-encodes every dynamic value, loads nothing external and contains no script.
    .PARAMETER Analysis
        Result of Invoke-IRAnalysis.
    .PARAMETER OutputPath
        Report directory (created if missing; must not contain '..').
    .PARAMETER Format
        Json, Csv, Html (default: all three).
    .PARAMETER EvidencePath
        Evidence directory, used to copy manifest.json next to the reports.
    .PARAMETER Config
        Configuration hashtable.
    .OUTPUTS
        System.String[] paths of the files written.
    .EXAMPLE
        Invoke-IRAnalysis -Path .\sample-data\case-001 | Export-IRReport -OutputPath .\reports\demo
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Analysis, [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Json', 'Csv', 'Html')][string[]]$Format = @('Json', 'Csv', 'Html'), [string]$EvidencePath, [System.Collections.IDictionary]$Config
    )
    process {
        if (-not $Config) { $Config = Get-IRConfiguration }
        try { $out = Resolve-IROutputPath -Path $OutputPath } catch { New-IRTerminatingError -Id IRUsage -Message $_.Exception.Message }
        $redactor = New-IRRedactor -Patterns (@($Config.redaction.patterns) + @($Config.redaction.extraPatterns)) -Enabled $Config.redaction.enabled
        $report = New-IRReportModel -Analysis $Analysis -Redactor $redactor
        if (-not (Test-Path -LiteralPath $out)) { $null = New-Item -ItemType Directory -Path $out -Force; Set-IRRestrictivePermission -Path $out }
        $targets = [ordered]@{}
        if ($Format -contains 'Json') { $targets['report.json'] = (ConvertTo-IRJson -InputObject $report) + "`n" }
        if ($Format -contains 'Csv') { $targets['findings.csv'] = ConvertTo-IRCsvText -Report $report }
        if ($Format -contains 'Html') { $targets['report.html'] = ConvertTo-IRHtmlText -Report $report }
        foreach ($name in $targets.Keys) { if (Test-Path -LiteralPath (Join-Path $out $name)) { throw "Refusing to overwrite existing file: $(Join-Path $out $name)" } }
        $written = New-Object 'System.Collections.Generic.List[string]'
        foreach ($name in $targets.Keys) {
            $p = Join-Path $out $name
            Write-IRFileExclusive -Path $p -Text $targets[$name]
            $written.Add($p)
        }
        if ($EvidencePath -and (Test-Path -LiteralPath (Join-Path $EvidencePath 'manifest.json'))) {
            $bytes = [IO.File]::ReadAllBytes((Join-Path $EvidencePath 'manifest.json'))
            Write-IRFileExclusive -Path (Join-Path $out 'evidence-manifest.json') -Text ((New-Object Text.UTF8Encoding($false)).GetString($bytes))
            Write-IRFileExclusive -Path (Join-Path $out 'evidence-manifest.sha256') -Text ("{0}  evidence-manifest.json`n" -f (Get-IRBytesSha256 -Bytes $bytes))
            $written.Add((Join-Path $out 'evidence-manifest.json')); $written.Add((Join-Path $out 'evidence-manifest.sha256'))
        }
        return $written.ToArray()
    }
}
