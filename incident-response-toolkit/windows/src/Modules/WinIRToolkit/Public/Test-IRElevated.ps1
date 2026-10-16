function Test-IRElevated {
    <#
    .SYNOPSIS
        Returns $true when the current process is elevated (Windows administrator token) or root (Unix, for demos/CI).
    .EXAMPLE
        if (-not (Test-IRElevated)) { Write-Warning 'Some sources will be partial.' }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        if (Test-IRWindowsHost) {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        return ((& id -u 2>$null) -eq '0')
    }
    catch { return $false }
}
