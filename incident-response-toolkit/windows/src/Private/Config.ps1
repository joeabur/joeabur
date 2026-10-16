# Configuration loading and strict validation (JSON, versioned).

function Get-IRConfigRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:IRConfigRoot
}

function ConvertTo-IRHashtable {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in $InputObject.Keys) { $h[$k] = ConvertTo-IRHashtable $InputObject[$k] }; return $h
    }
    if ($InputObject -is [pscustomobject]) {
        $h = [ordered]@{}; foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-IRHashtable $p.Value }; return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return , @(foreach ($i in $InputObject) { ConvertTo-IRHashtable $i })
    }
    return $InputObject
}

function Merge-IRConfig {
    param([System.Collections.IDictionary]$Base, [System.Collections.IDictionary]$Override, [string]$Path = '')
    $out = [ordered]@{}
    foreach ($k in $Base.Keys) { $out[$k] = $Base[$k] }
    foreach ($k in $Override.Keys) {
        $here = if ($Path) { "$Path.$k" } else { $k }
        if (-not $Base.Contains($k)) { throw "Unknown configuration key: $here" }
        $b = $Base[$k]; $o = $Override[$k]
        if ($b -is [System.Collections.IDictionary] -and $k -ne 'profiles') {
            if ($o -isnot [System.Collections.IDictionary]) { throw "$here must be an object" }
            $out[$k] = Merge-IRConfig -Base $b -Override $o -Path $here
        }
        elseif ($k -eq 'profiles') {
            if ($o -isnot [System.Collections.IDictionary]) { throw 'profiles must be an object' }
            $merged = [ordered]@{}
            foreach ($pk in $b.Keys) { $merged[$pk] = $b[$pk] }
            foreach ($pk in $o.Keys) { $merged[$pk] = $o[$pk] }
            $out[$k] = $merged
        }
        elseif ($b -is [bool]) { if ($o -isnot [bool]) { throw "$here must be true or false" }; $out[$k] = $o }
        elseif ($b -is [int] -or $b -is [long]) {
            if ($o -isnot [int] -and $o -isnot [long]) { throw "$here must be an integer" }
            $out[$k] = $o
        }
        elseif ($b -is [string]) { if ($o -isnot [string]) { throw "$here must be a string" }; $out[$k] = $o }
        else { $out[$k] = $o }
    }
    return $out
}

function Test-IRConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Config)
    foreach ($k in $Config.limits.Keys) {
        if ($Config.limits[$k] -le 0) { throw "limits.$k must be a positive integer" }
    }
    if ($Config.events.windowHours -lt 1 -or $Config.events.windowHours -gt 2160) { throw 'events.windowHours must be between 1 and 2160' }
    $collectors = @($script:CollectorNames)
    foreach ($name in $Config.profiles.Keys) {
        $p = $Config.profiles[$name]
        if ($p -isnot [System.Collections.IDictionary]) { throw "profile '$name' must be an object" }
        $extra = @($p.Keys | Where-Object { $_ -notin @('collectors', 'description', 'logs') })
        if ($extra.Count -gt 0) { throw "profile '$name' has unknown keys: $($extra -join ', ')" }
        $cols = @($p['collectors'])
        if ($cols.Count -eq 0) { throw "profile '$name': collectors must be a non-empty list" }
        $bad = @($cols | Where-Object { $_ -notin $collectors })
        if ($bad.Count -gt 0) { throw "profile '$name': unknown collectors: $($bad -join ', ')" }
    }
    foreach ($p in @($Config.redaction.patterns) + @($Config.redaction.extraPatterns)) {
        if ($null -eq $p) { continue }
        $pat = Get-IRProp $p 'pattern'
        if ([string]::IsNullOrEmpty($pat) -or $pat.Length -gt 500) { throw 'redaction patterns need a "pattern" of at most 500 characters' }
        try { $null = [regex]::new($pat) } catch { throw "Invalid redaction regex '$pat': $($_.Exception.Message)" }
    }
}

function Get-IRConfiguration {
    <#
    .SYNOPSIS
        Loads the default configuration and optionally merges (and strictly validates) a user JSON file.
    .PARAMETER Path
        Optional path to a JSON configuration file. Unknown keys and wrongly typed values are rejected.
    .EXAMPLE
        Get-IRConfiguration
    #>
    [CmdletBinding()]
    param([string]$Path)
    $defaultPath = Join-Path $script:IRConfigRoot 'default.json'
    $cfg = ConvertTo-IRHashtable (Read-IRJsonFile -Path $defaultPath)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Configuration file not found: $Path" }
        $user = ConvertTo-IRHashtable (Read-IRJsonFile -Path $Path)
        if ($user -isnot [System.Collections.IDictionary]) { throw 'Configuration root must be an object' }
        if ($user.Contains('schemaVersion') -and $user['schemaVersion'] -ne $cfg['schemaVersion']) { throw "Unsupported configuration schemaVersion $($user['schemaVersion']); expected $($cfg['schemaVersion'])" }
        $cfg = Merge-IRConfig -Base $cfg -Override $user
    }
    Test-IRConfig -Config $cfg
    return $cfg
}
