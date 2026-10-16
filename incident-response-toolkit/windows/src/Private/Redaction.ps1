# Configurable redaction of secrets in command lines, event data and reports.

function New-IRRedactor {
    <#
    .SYNOPSIS
        Builds a redactor from a list of {name, pattern, replacement} objects.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Patterns, [bool]$Enabled = $true)
    $compiled = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($p in @($Patterns)) {
        $pat = Get-IRProp $p 'pattern'
        if ([string]::IsNullOrEmpty($pat)) { throw 'Redaction pattern entries need a non-empty "pattern".' }
        if ($pat.Length -gt 500) { throw 'Redaction pattern too long (max 500 characters).' }
        $repl = Get-IRProp $p 'replacement'
        if ($null -eq $repl) { $repl = '[REDACTED]' }
        try { $rx = New-Object Text.RegularExpressions.Regex($pat, 'IgnoreCase', [TimeSpan]::FromMilliseconds(250)) }
        catch { throw "Invalid redaction pattern '$pat': $($_.Exception.Message)" }
        $compiled.Add([pscustomobject]@{ Regex = $rx; Replacement = $repl })
    }
    return [pscustomobject]@{ Enabled = $Enabled; Compiled = $compiled }
}

function Protect-IRText {
    <#
    .SYNOPSIS
        Applies redaction patterns to a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory)] $Redactor)
    if ([string]::IsNullOrEmpty($Text) -or -not $Redactor.Enabled) { return $Text }
    foreach ($c in $Redactor.Compiled) {
        try { $Text = $c.Regex.Replace($Text, $c.Replacement) }
        catch [Text.RegularExpressions.RegexMatchTimeoutException] { $Text = '[REDACTED: pattern timeout]' }
    }
    return $Text
}

function Protect-IRObject {
    <#
    .SYNOPSIS
        Recursively redacts every string inside a JSON-like object graph (returns a new graph).
    #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] $Redactor)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { return (Protect-IRText -Text $InputObject -Redactor $Redactor) }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $o[$k] = Protect-IRObject -InputObject $InputObject[$k] -Redactor $Redactor }
        return $o
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return , @(foreach ($i in $InputObject) { Protect-IRObject -InputObject $i -Redactor $Redactor })
    }
    if ($InputObject -is [pscustomobject]) {
        $o = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $o[$p.Name] = Protect-IRObject -InputObject $p.Value -Redactor $Redactor }
        return [pscustomobject]$o
    }
    return $InputObject
}
