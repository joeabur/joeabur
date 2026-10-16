function New-IRTerminatingError {
    <#
    .SYNOPSIS
        Throws a categorised terminating error whose FullyQualifiedErrorId drives scripts/winir.ps1 exit codes.
    .PARAMETER Id
        IRUsage | IRVerificationFailed | IRRuntime
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('IRUsage', 'IRVerificationFailed', 'IRRuntime')][string]$Id, [Parameter(Mandatory)][string]$Message)
    $cat = switch ($Id) { 'IRUsage' { [Management.Automation.ErrorCategory]::InvalidArgument } 'IRVerificationFailed' { [Management.Automation.ErrorCategory]::InvalidData } default { [Management.Automation.ErrorCategory]::NotSpecified } }
    $rec = New-Object Management.Automation.ErrorRecord((New-Object InvalidOperationException($Message)), $Id, $cat, $null)
    throw $rec
}
