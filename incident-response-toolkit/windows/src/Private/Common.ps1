# Common helpers: platform detection, UTC time, safe property access, JSON I/O, result objects.

$script:ToolName = 'windows-ir-toolkit'
$script:Severities = @('info', 'low', 'medium', 'high', 'critical')
$script:Confidences = @('low', 'medium', 'high')
$script:ErrorKinds = @('not_found', 'permission_denied', 'timeout', 'parse_error', 'unavailable', 'truncated', 'other')

# Exit codes used by scripts/winir.ps1 (documented in docs/user-guide.md)
$script:ExitCodes = @{ Ok = 0; Error = 1; Usage = 2; VerifyFailed = 3; Findings = 10 }

function Test-IRWindowsHost {
    <#
    .SYNOPSIS
        Returns $true when running on Windows (Windows PowerShell 5.1 or PowerShell 7+).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return [bool]$IsWindows
}

function Get-IRUtcNowIso {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-IRUtcIso {
    <#
    .SYNOPSIS
        Converts a DateTime/DateTimeOffset/string to a UTC ISO 8601 string; returns $null for empty or invalid input.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)] $Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try {
        if ($Value -is [DateTimeOffset]) { $dt = $Value.UtcDateTime }
        elseif ($Value -is [DateTime]) {
            if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $dt = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Local).ToUniversalTime() }
            else { $dt = $Value.ToUniversalTime() }
        }
        else {
            $parsed = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $null }
            $dt = $parsed.UtcDateTime
        }
        if ($dt.Year -lt 1980) { return $null }   # WMI/registry "never" sentinel values
        return $dt.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    }
    catch { return $null }
}

function Get-IRProp {
    <#
    .SYNOPSIS
        Strict-mode-safe property/dictionary access with dotted paths. Returns $null if anything is missing.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)] $InputObject, [Parameter(Mandatory, Position = 1)][string]$Path)
    $cur = $InputObject
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($part)) { $cur = $cur[$part] } else { return $null }
        }
        else {
            $p = $cur.PSObject.Properties[$part]
            if ($null -eq $p) { return $null }
            $cur = $p.Value
        }
    }
    return (ConvertTo-IRPlainValue $cur)
}

function ConvertTo-IRPlainValue {
    <#
    .SYNOPSIS
        PowerShell 7 turns ISO date strings in JSON into DateTime; Windows PowerShell 5.1 keeps strings. Normalise to the string form.
    #>
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    return $Value
}

function Test-IRHasProp {
    [CmdletBinding()]
    [OutputType([bool])]
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function ConvertTo-IRJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()] $InputObject, [int]$Depth = 12)
    return (ConvertTo-Json -InputObject $InputObject -Depth $Depth)
}

function Read-IRJsonFile {
    <#
    .SYNOPSIS
        Reads and parses a JSON file defensively (size limit, clear errors).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = 52428800)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -gt $MaxBytes) { throw "File $Path exceeds the $MaxBytes byte limit." }
    $text = [IO.File]::ReadAllText($item.FullName, [Text.Encoding]::UTF8)
    try { return ($text | ConvertFrom-Json) }
    catch { throw "File $Path is not valid JSON: $($_.Exception.Message)" }
}

function Get-IRErrorKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    $msg = "$($ex.Message)"
    if ($ex -is [UnauthorizedAccessException] -or $msg -match '(?i)access (is )?denied|unauthorized|not authorized|privilege|requires elevation|administrator') { return 'permission_denied' }
    if ($msg -match '(?i)timed out|timeout') { return 'timeout' }
    if ($ex -is [Management.Automation.CommandNotFoundException] -or $msg -match '(?i)is not recognized|not supported|unavailable|not available|invalid namespace|invalid class') { return 'unavailable' }
    if ($ex -is [IO.FileNotFoundException] -or $ex -is [IO.DirectoryNotFoundException] -or $msg -match '(?i)cannot find|not found|does not exist|no such') { return 'not_found' }
    return 'other'
}

function New-IRCollectorResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    return [pscustomobject]@{
        Name    = $Name
        Status  = 'ok'
        Records = New-Object 'System.Collections.Generic.List[psobject]'
        Errors  = New-Object 'System.Collections.Generic.List[psobject]'
        Sources = New-Object 'System.Collections.Generic.List[string]'
        Notes   = New-Object 'System.Collections.Generic.List[string]'
    }
}

function Add-IRCollectionError {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Message)
    if ($script:ErrorKinds -notcontains $Kind) { $Kind = 'other' }
    $Result.Errors.Add([pscustomobject][ordered]@{ collector = $Result.Name; source = $Source; kind = $Kind; message = $Message })
}

function Add-IRCaughtError {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)] $ErrorRecord)
    Add-IRCollectionError -Result $Result -Source $Source -Kind (Get-IRErrorKind $ErrorRecord) -Message ("$($ErrorRecord.Exception.Message)" -replace '\s+', ' ')
}

function Complete-IRCollectorResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result)
    if ($Result.Status -in @('skipped', 'unavailable')) { return $Result }
    if ($Result.Errors.Count -gt 0 -and $Result.Records.Count -eq 0) { $Result.Status = 'failed' }
    elseif ($Result.Errors.Count -gt 0) { $Result.Status = 'partial' }
    else { $Result.Status = 'ok' }
    return $Result
}

function Get-IRCommandLineExecutable {
    <#
    .SYNOPSIS
        Extracts the executable path from a command line string (static parsing, nothing is executed).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $s = $CommandLine.Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 1) { return $s.Substring(1, $end - 1) }
        return $s.TrimStart('"')
    }
    # Unquoted: take the longest prefix ending in a known executable extension, else the first token.
    $m = [regex]::Match($s, '^(?<p>.+?\.(exe|com|bat|cmd|ps1|vbs|js|dll|msi|scr|sys))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups['p'].Value }
    return $s.Split(' ')[0]
}

function Test-IRUnquotedServicePath {
    <#
    .SYNOPSIS
        $true when a command line starts unquoted and its executable path contains a space (a known misconfiguration pattern).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.Trim()
    if ($p.StartsWith('"')) { return $false }
    $m = [regex]::Match($p, '^(?<exe>[A-Za-z]:\\.+?\.exe)(\s|$)', 'IgnoreCase')
    return ($m.Success -and $m.Groups['exe'].Value.Contains(' '))
}
