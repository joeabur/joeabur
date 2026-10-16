# Evidence layout, manifest generation, verification and loading.

$script:ManifestName = 'manifest.json'
$script:Limitations = @(
    'Live-response collection is not a forensic disk or memory image; volatile state changed while collecting.',
    'The manifest is stored beside the evidence: it detects accidental or naive changes but is not independently tamper-proof. Store a copy of the manifest SHA-256 (or a signed manifest) separately.',
    'Timestamps are normalised to UTC from host-reported values; clock accuracy is not verified. Original local times are retained where relevant.',
    'Inaccessible or unexamined sources are listed in the coverage section; absence of data is not absence of activity, and incomplete collection never means the host is clean.'
)

function New-IRArtifactDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)][string]$CollectedAt)
    return [ordered]@{
        schema_version = 1
        artifact       = $Result.Name
        collected_at   = $CollectedAt
        status         = $Result.Status
        sources        = @($Result.Sources)
        notes          = @($Result.Notes)
        errors         = @($Result.Errors)
        records        = @($Result.Records)
    }
}

function Write-IRArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidenceDir, [Parameter(Mandatory)] $Document)
    $dir = Join-Path $EvidenceDir 'artifacts'
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir; Set-IRRestrictivePermission -Path $dir }
    $target = Join-IRSafePath -Base $EvidenceDir -Relative ("artifacts/{0}.json" -f $Document.artifact)
    Write-IRFileExclusive -Path $target -Text ((ConvertTo-IRJson -InputObject $Document) + "`n")
    return $target
}

function Get-IREvidenceFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidenceDir)
    $root = (Resolve-Path -LiteralPath $EvidenceDir).ProviderPath.TrimEnd('\', '/')
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Sort-Object FullName)) {
        $rel = $f.FullName.Substring($root.Length + 1).Replace('\', '/')
        if ($rel -eq $script:ManifestName) { continue }
        [pscustomobject]@{ Path = $rel; FullName = $f.FullName; Item = $f }
    }
}

function New-IREvidenceManifest {
    <#
    .SYNOPSIS
        Builds (but does not write) a manifest describing every file below an evidence directory.
    .PARAMETER EvidenceDir
        Evidence directory containing an artifacts folder.
    .PARAMETER Metadata
        Ordered dictionary of collection metadata (host, profile, start/finish times ...).
    .PARAMETER NotRun
        Hashtable name -> reason for collectors that were deliberately not executed.
    .EXAMPLE
        New-IREvidenceManifest -EvidenceDir .\evidence\host-1 -Metadata @{ profile = 'imported' }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidenceDir, [System.Collections.IDictionary]$Metadata = @{}, [hashtable]$NotRun = @{})
    $files = New-Object 'System.Collections.Generic.List[psobject]'
    $arts = New-Object 'System.Collections.Generic.List[psobject]'
    $coverage = [ordered]@{ ok = @(); partial = @(); failed = @(); skipped = @(); unavailable = @() }
    foreach ($f in @(Get-IREvidenceFile -EvidenceDir $EvidenceDir)) {
        if ($f.Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing to seal a symbolic link/reparse point inside the evidence directory: $($f.Path)" }
        $files.Add([pscustomobject][ordered]@{ path = $f.Path; size = [long]$f.Item.Length; sha256 = (Get-IRFileSha256 -Path $f.FullName) })
        if ($f.Path -like 'artifacts/*.json') {
            $doc = Read-IRJsonFile -Path $f.FullName
            $arts.Add([pscustomobject][ordered]@{ name = $doc.artifact; path = $f.Path; status = $doc.status; record_count = @($doc.records).Count; sources = @($doc.sources); errors = @($doc.errors); notes = @($doc.notes) })
            $coverage[$doc.status] = @($coverage[$doc.status]) + $doc.artifact
        }
    }
    foreach ($k in $NotRun.Keys) {
        $coverage['skipped'] = @($coverage['skipped']) + $k
        $arts.Add([pscustomobject][ordered]@{ name = $k; path = $null; status = 'skipped'; record_count = 0; sources = @(); errors = @(); notes = @($NotRun[$k]) })
    }
    $manifest = [ordered]@{ schema_version = 1; tool = [ordered]@{ name = $script:ToolName; version = $script:ToolVersion } }
    foreach ($k in $Metadata.Keys) { $manifest[$k] = $Metadata[$k] }
    $manifest['artifacts'] = @($arts)
    $manifest['coverage'] = $coverage
    $manifest['files'] = @($files)
    $manifest['limitations'] = $script:Limitations
    return $manifest
}

function Write-IREvidenceManifest {
    <#
    .SYNOPSIS
        Writes manifest.json (never overwriting) and returns its path and SHA-256.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidenceDir, [Parameter(Mandatory)] $Manifest)
    $text = (ConvertTo-IRJson -InputObject $Manifest) + "`n"
    $path = Join-Path $EvidenceDir $script:ManifestName
    Write-IRFileExclusive -Path $path -Text $text
    [pscustomobject]@{ Path = $path; Sha256 = (Get-IRBytesSha256 -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($text))) }
}

function Test-IREvidenceManifest {
    <#
    .SYNOPSIS
        Verifies evidence files against manifest.json (read-only).
    .DESCRIPTION
        Recomputes SHA-256 and size for each listed file and reports modified, missing, unexpected and unsafe
        (traversal, reparse point) entries. The manifest is not independently tamper-proof: also compare
        ManifestSha256 with a copy stored elsewhere.
    .PARAMETER Path
        Evidence directory.
    .OUTPUTS
        PSCustomObject: Ok, ManifestSha256, Verified, Modified, Missing, Unexpected, Unsafe, Error.
    .EXAMPLE
        Test-IREvidenceManifest -Path .\sample-data\case-001 | Format-List
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)
    $r = [ordered]@{ Ok = $false; ManifestSha256 = $null; Verified = 0; Modified = @(); Missing = @(); Unexpected = @(); Unsafe = @(); Error = $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { $r.Error = "Evidence directory not found: $Path"; return [pscustomobject]$r }
    $mpath = Join-Path $Path $script:ManifestName
    if (-not (Test-Path -LiteralPath $mpath -PathType Leaf)) { $r.Error = "$($script:ManifestName) not found in $Path"; return [pscustomobject]$r }
    $raw = [IO.File]::ReadAllBytes($mpath)
    $r.ManifestSha256 = Get-IRBytesSha256 -Bytes $raw
    try {
        $manifest = (New-Object Text.UTF8Encoding($false)).GetString($raw) | ConvertFrom-Json
        $entries = @($manifest.files)
        if ($null -eq $manifest.files) { throw 'no files list' }
    }
    catch { $r.Error = 'manifest is not valid JSON or lacks a "files" list'; return [pscustomobject]$r }
    $listed = @{}
    foreach ($e in $entries) {
        try { $full = Join-IRSafePath -Base $Path -Relative ([string]$e.path) }
        catch { $r.Unsafe += "$($e.path): $($_.Exception.Message)"; continue }
        $listed[([string]$e.path)] = $true
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $r.Missing += [string]$e.path; continue }
        $item = Get-Item -LiteralPath $full -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $r.Unsafe += "$($e.path): is a symbolic link/reparse point"; continue }
        try { $actual = Get-IRFileSha256 -Path $full } catch { $r.Modified += [pscustomobject]@{ path = [string]$e.path; reason = "unreadable: $($_.Exception.Message)" }; continue }
        if ($actual -ne [string]$e.sha256 -or [long]$item.Length -ne [long]$e.size) { $r.Modified += [pscustomobject]@{ path = [string]$e.path; expected = [string]$e.sha256; actual = $actual } }
        else { $r.Verified++ }
    }
    foreach ($f in @(Get-IREvidenceFile -EvidenceDir $Path)) { if (-not $listed.ContainsKey($f.Path)) { $r.Unexpected += $f.Path } }
    $r.Ok = (@($r.Modified).Count + @($r.Missing).Count + @($r.Unexpected).Count + @($r.Unsafe).Count) -eq 0
    return [pscustomobject]$r
}

function Read-IREvidence {
    <#
    .SYNOPSIS
        Loads artifact documents (and the manifest, if present) from an evidence directory.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $adir = Join-Path $Path 'artifacts'
    if (-not (Test-Path -LiteralPath $adir -PathType Container)) { throw "$Path does not look like an evidence directory (no artifacts folder)." }
    $arts = [ordered]@{}
    foreach ($f in @(Get-ChildItem -LiteralPath $adir -Filter '*.json' -File | Sort-Object Name)) {
        if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing to follow link: $($f.Name)" }
        try {
            $doc = Read-IRJsonFile -Path $f.FullName
            if ($null -eq (Get-IRProp $doc 'artifact') -or $null -eq $doc.PSObject.Properties['records']) { throw 'missing "artifact" or "records"' }
        }
        catch { throw "Malformed artifact file $($f.Name): $($_.Exception.Message)" }
        $arts[[string]$doc.artifact] = $doc
    }
    $manifest = $null
    $mp = Join-Path $Path $script:ManifestName
    if (Test-Path -LiteralPath $mp -PathType Leaf) {
        try { $manifest = Read-IRJsonFile -Path $mp } catch { throw "manifest.json is not valid JSON: $($_.Exception.Message)" }
    }
    [pscustomobject]@{ Artifacts = $arts; Manifest = $manifest }
}
