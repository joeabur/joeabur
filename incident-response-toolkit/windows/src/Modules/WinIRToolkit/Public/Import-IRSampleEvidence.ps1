function Protect-IREvidenceDirectory {
    <#
    .SYNOPSIS
        Creates manifest.json for an existing evidence directory that has only artifacts (imported or synthetic evidence).
    .DESCRIPTION
        Refuses to overwrite an existing manifest. Used to seal the synthetic fixtures in sample-data/.
    .PARAMETER Path
        Directory containing an 'artifacts' folder.
    .OUTPUTS
        PSCustomObject: Path, Sha256.
    .EXAMPLE
        Protect-IREvidenceDirectory -Path .\my-imported-evidence
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath (Join-Path $Path 'artifacts') -PathType Container)) { New-IRTerminatingError -Id IRUsage -Message 'Path must contain an artifacts directory.' }
    if (Test-Path -LiteralPath (Join-Path $Path 'manifest.json')) { New-IRTerminatingError -Id IRRuntime -Message 'manifest.json already exists; refusing to overwrite.' }
    $meta = [ordered]@{ platform = 'Windows'; profile = 'imported'; collectors_requested = @(); started_at = $null; finished_at = Get-IRUtcNowIso; host = [ordered]@{ hostname = 'imported' }; privileged = $false }
    $m = New-IREvidenceManifest -EvidenceDir $Path -Metadata $meta
    Write-IREvidenceManifest -EvidenceDir $Path -Manifest $m
}
