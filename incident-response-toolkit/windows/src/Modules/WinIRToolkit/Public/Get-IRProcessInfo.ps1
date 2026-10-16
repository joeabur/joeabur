function Get-IRProcessInfo {
    <#
    .SYNOPSIS
        Read-only process inventory with parent/child relationships, redacted command lines, signer and SHA-256.
    .DESCRIPTION
        Uses Win32_Process. Executables are hashed/signature-checked by path only (never run). Command lines are
        redacted with the configured patterns. A null CommandLine/ExecutablePath marks the record visibility=limited
        (typically a protected process or missing elevation) rather than implying absence.
    .PARAMETER Config
        Configuration hashtable. Defaults to the built-in configuration.
    .PARAMETER SkipSignature
        Skip Authenticode checks (faster).
    .PARAMETER SkipHash
        Skip SHA-256 hashing of executables.
    .OUTPUTS
        PSCustomObject collector result.
    .NOTES
        Permissions: unprivileged runs see most command lines for the current user only; elevation adds others'.
    .EXAMPLE
        (Get-IRProcessInfo).Records | Where-Object { $_.visibility -eq 'limited' }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([System.Collections.IDictionary]$Config, [switch]$SkipSignature, [switch]$SkipHash)
    if (-not $Config) { $Config = Get-IRConfiguration }
    $redactor = New-IRRedactor -Patterns (@($Config.redaction.patterns) + @($Config.redaction.extraPatterns)) -Enabled $Config.redaction.enabled
    $res = New-IRCollectorResult -Name 'processes'
    try { $procs = @(Get-IRRawProcess); $res.Sources.Add('Win32_Process') }
    catch { Add-IRCaughtError $res 'Win32_Process' $_; return (Complete-IRCollectorResult $res) }
    $byId = @{}
    foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
    $limit = [int]$Config.limits.maxProcesses
    $hashCache = @{}; $sigCache = @{}; $ownerLookups = 0; $hashBudget = [int]$Config.limits.maxHashedExecutables; $sigBudget = [int]$Config.limits.maxSignatureChecks
    $maxCmd = [int]$Config.limits.commandLineMaxChars
    foreach ($p in ($procs | Select-Object -First $limit)) {
        $exe = $p.ExecutablePath
        $cmd = $p.CommandLine
        $parent = $null
        if ($byId.ContainsKey([int]$p.ParentProcessId)) { $parent = $byId[[int]$p.ParentProcessId] }
        $rec = [ordered]@{
            pid = [int]$p.ProcessId; ppid = [int]$p.ParentProcessId; name = $p.Name; exe = $exe
            cmdline = if ($null -ne $cmd) { $c = Protect-IRText -Text ([string]$cmd) -Redactor $redactor; if ($c.Length -gt $maxCmd) { $c.Substring(0, $maxCmd) } else { $c } } else { $null }
            start_time = ConvertTo-IRUtcIso $p.CreationDate; session_id = Get-IRProp $p 'SessionId'
            parent_name = if ($parent) { $parent.Name } else { $null }; parent_exe = if ($parent) { $parent.ExecutablePath } else { $null }
            parent_exists = [bool]$parent
            visibility = if ($null -eq $cmd -or [string]::IsNullOrEmpty($exe)) { 'limited' } else { 'full' }
        }
        if ($ownerLookups -lt [int]$Config.limits.maxOwnerLookups -and $p.ProcessId -gt 4) {
            $ownerLookups++
            try { $o = Get-IRRawProcessOwner -ProcessId $p.ProcessId; $rec['user'] = if ($o) { "$($o.Domain)\$($o.User)" } else { $null } }
            catch { $rec['user'] = $null }
        }
        if ($exe -and -not [string]::IsNullOrEmpty($exe)) {
            $key = $exe.ToLowerInvariant()
            if (-not $SkipHash) {
                if (-not $hashCache.ContainsKey($key) -and $hashCache.Count -lt $hashBudget) {
                    try { $hashCache[$key] = @{ Hash = (Get-IRRawFileHash -Path $exe -MaxBytes ([long]$Config.limits.maxHashBytes)); Error = $null } }
                    catch { $hashCache[$key] = @{ Hash = $null; Error = ($_.Exception.Message -replace '\s+', ' ') } }
                }
                if ($hashCache.ContainsKey($key)) { $rec['exe_sha256'] = $hashCache[$key].Hash; if ($hashCache[$key].Error) { $rec['exe_hash_error'] = $hashCache[$key].Error } }
            }
            if (-not $SkipSignature) {
                if (-not $sigCache.ContainsKey($key) -and $sigCache.Count -lt $sigBudget) {
                    try { $sigCache[$key] = Get-IRRawSignature -Path $exe } catch { $sigCache[$key] = [pscustomobject]@{ Status = 'Unknown'; SignerSubject = $null; SignerThumbprint = $null } }
                }
                if ($sigCache.ContainsKey($key)) { $rec['signature_status'] = $sigCache[$key].Status; $rec['signer'] = $sigCache[$key].SignerSubject }
            }
        }
        $res.Records.Add([pscustomobject]$rec)
    }
    if ($procs.Count -gt $limit) { Add-IRCollectionError $res 'Win32_Process' 'truncated' "stopped at maxProcesses=$limit" }
    $limited = @($res.Records | Where-Object { $_.visibility -eq 'limited' }).Count
    if ($limited -gt 0) { $res.Notes.Add("$limited process(es) had limited visibility (no command line or path: protected process or missing elevation). Absence of detail is not absence of activity.") }
    if ($hashCache.Count -ge $hashBudget) { $res.Notes.Add('Executable hashing stopped at maxHashedExecutables; remaining executables are unhashed.') }
    $res.Notes.Add('Processes that exited during collection are not listed. A process list is a point-in-time snapshot.')
    return (Complete-IRCollectorResult $res)
}
