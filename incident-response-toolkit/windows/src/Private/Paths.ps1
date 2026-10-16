# Path safety, hashing, exclusive writes and restrictive permissions.

function Resolve-IROutputPath {
    <#
    .SYNOPSIS
        Validates an output directory path (no traversal tricks, no device paths) and returns its full path.
        The directory is not created.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Output path must not be empty.' }
    if ($Path.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0 -or $Path.Contains([string][char]0)) { throw "Output path contains invalid characters: $Path" }
    if ($Path -match '^(\\\\\.\\|\\\\\?\\|//\./|//\?/)') { throw "Device paths are not allowed as output paths: $Path" }
    if (($Path -split '[\\/]') -contains '..') { throw "Output path must not contain '..' segments: $Path" }
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full -PathType Leaf) { throw "Output path is an existing file, not a directory: $full" }
    return $full
}

function Join-IRSafePath {
    <#
    .SYNOPSIS
        Joins a relative path to a base directory, refusing rooted paths, '..' and links that escape the base.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Relative)
    if ([string]::IsNullOrWhiteSpace($Relative) -or [IO.Path]::IsPathRooted($Relative) -or $Relative.Contains([string][char]0) -or $Relative.StartsWith('/') -or $Relative.StartsWith('\') -or $Relative -match '^[A-Za-z]:') {
        throw "Unsafe relative path: '$Relative'"
    }
    if (($Relative -split '[\\/]') -contains '..') { throw "Path traversal rejected: '$Relative'" }
    $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $target = [IO.Path]::GetFullPath((Join-Path $baseFull $Relative))
    $cmp = if (Test-IRWindowsHost) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not $target.StartsWith($baseFull + [IO.Path]::DirectorySeparatorChar, $cmp)) { throw "Path escapes base directory: '$Relative'" }
    return $target
}

function Get-IRFileSha256 {
    <#
    .SYNOPSIS
        Streams a SHA-256 (lower-case hex). Throws if the file exceeds MaxBytes (when specified).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = 0)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]'ReadWrite, Delete'))
        try {
            if ($MaxBytes -gt 0 -and $fs.Length -gt $MaxBytes) { throw "file larger than hash limit ($MaxBytes bytes)" }
            return ([BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '').ToLowerInvariant())
        }
        finally { $fs.Dispose() }
    }
    finally { $sha.Dispose() }
}

function Get-IRBytesSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()) }
    finally { $sha.Dispose() }
}

function Write-IRFileExclusive {
    <#
    .SYNOPSIS
        Writes UTF-8 (no BOM) text with FileMode.CreateNew: never overwrites an existing file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { throw "Directory does not exist: $dir" }
    if (Test-Path -LiteralPath $Path) { throw "Refusing to overwrite existing file: $Path" }
    try { $fs = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None) }
    catch {
        # Windows PowerShell 5.1 wraps constructor failures; CreateNew fails only if the file appeared in the meantime.
        if ($_.Exception -is [IO.IOException] -or $_.Exception.InnerException -is [IO.IOException]) { throw "Refusing to overwrite existing file: $Path" }
        throw
    }
    try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
    Set-IRRestrictivePermission -Path $Path
}

function Set-IRRestrictivePermission {
    <#
    .SYNOPSIS
        Best-effort owner-only permissions: ACL (Windows) or mode 0700/0600 (Unix, used by the synthetic demo/CI).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $isDir = Test-Path -LiteralPath $Path -PathType Container
        if (Test-IRWindowsHost) {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited rules
            foreach ($id in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
                $inherit = if ($isDir) { 'ContainerInherit,ObjectInherit' } else { 'None' }
                $rule = New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', $inherit, 'None', 'Allow')
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
        elseif ($PSVersionTable.PSVersion.Major -ge 7) {
            $mode = if ($isDir) { 'UserRead, UserWrite, UserExecute' } else { 'UserRead, UserWrite' }
            [IO.File]::SetUnixFileMode($Path, [IO.UnixFileMode]$mode)
        }
    }
    catch { Write-Verbose "Could not apply restrictive permissions to ${Path}: $($_.Exception.Message)" }
}

function New-IRUniqueDirectory {
    <#
    .SYNOPSIS
        Creates a new, uniquely named subdirectory (never reuses an existing one) with restrictive permissions.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Parent, [Parameter(Mandatory)][string]$Prefix)
    if (-not (Test-Path -LiteralPath $Parent)) {
        $null = New-Item -ItemType Directory -Path $Parent -Force
        Set-IRRestrictivePermission -Path $Parent
    }
    for ($i = 0; $i -lt 20; $i++) {
        $suffix = [Guid]::NewGuid().ToString('N').Substring(0, 6)
        $candidate = Join-Path $Parent "$Prefix-$suffix"
        if (-not (Test-Path -LiteralPath $candidate)) {
            $null = New-Item -ItemType Directory -Path $candidate
            Set-IRRestrictivePermission -Path $candidate
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }
    throw 'Could not allocate a unique output directory.'
}
