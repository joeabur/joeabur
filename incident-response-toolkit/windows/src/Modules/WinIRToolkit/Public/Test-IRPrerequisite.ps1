function Test-IRPrerequisite {
    <#
    .SYNOPSIS
        Readiness checks (the 'doctor' command): returns Status (OK/WARN/FAIL), Check and Detail per item.
    .DESCRIPTION
        Never changes any setting. Explains what elevation would add; the toolkit never elevates itself.
    .OUTPUTS
        PSCustomObject[]
    .NOTES
        Permissions: none.
    .EXAMPLE
        Test-IRPrerequisite | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()
    $info = Get-IRPlatformInfo
    $out = New-Object 'System.Collections.Generic.List[psobject]'
    $add = { param($s, $c, $d) $out.Add([pscustomobject]@{ Status = $s; Check = $c; Detail = $d }) }
    & $add $(if ($info.is_windows) { 'OK' } else { 'FAIL' }) 'operating system' $(if ($info.is_windows) { $info.os } else { "$($info.os): live collection is unsupported here (analysis, reporting and manifest verification still work)" })
    $v = $PSVersionTable.PSVersion
    & $add $(if ($v.Major -ge 5) { 'OK' } else { 'FAIL' }) 'PowerShell' "$v ($($info.powershell_edition)); Windows PowerShell 5.1 and PowerShell 7+ are supported"
    & $add $(if ($info.elevated) { 'WARN' } else { 'OK' }) 'privileges' $(if ($info.elevated) { 'elevated: more visibility, but evidence is more sensitive' } else { 'not elevated: the Security log, other users'' processes and some WMI data may be partial. The toolkit never elevates itself; you decide whether to re-run specific collectors as administrator.' })
    foreach ($k in $info.cmdlets.PSObject.Properties) { & $add $(if ($k.Value) { 'OK' } else { 'WARN' }) "cmdlet:$($k.Name)" $(if ($k.Value) { 'available' } else { 'not available (the related data will be partial)' }) }
    & $add 'OK' 'execution policy' "Process/user policy is $($info.execution_policy). Importing the module does not require changing it when the repository is trusted; see docs/troubleshooting.md."
    return , @($out)
}
