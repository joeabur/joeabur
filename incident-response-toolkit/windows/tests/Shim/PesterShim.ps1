<#
.SYNOPSIS
    A minimal Pester-5-compatible runner used ONLY when real Pester 5 is unavailable (offline development, sandboxes).
.DESCRIPTION
    Implements the small subset of Pester syntax used by tests/Unit and tests/Integration: Describe, Context, It
    (-Skip), BeforeAll, BeforeEach, AfterAll, AfterEach and Should (-Be -BeExactly -BeTrue -BeFalse -BeNullOrEmpty -Contain
    -Match -Throw -HaveCount -BeGreaterThan -BeLessThan -BeLike -BeOfType -Exist, with -Not). It is NOT a replacement:
    CI runs the real Pester. Test files must share state through $script: variables (also the Pester 5 best practice).
.PARAMETER Path
    Test files or directories (*.Tests.ps1).
.EXAMPLE
    pwsh -File tests/Shim/PesterShim.ps1 -Path tests/Unit
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Path)
$ErrorActionPreference = 'Stop'
$script:Passed = 0; $script:Failed = 0; $script:Skipped = 0
$script:Failures = New-Object 'System.Collections.Generic.List[string]'
$script:Stack = New-Object 'System.Collections.Generic.List[string]'
$script:EachBlocks = New-Object 'System.Collections.Generic.List[scriptblock]'
$script:AfterEachBlocks = New-Object 'System.Collections.Generic.List[scriptblock]'

function BeforeAll { param([scriptblock]$Script) & $Script }
function AfterAll { param([scriptblock]$Script) & $Script }
function BeforeDiscovery { param([scriptblock]$Script) & $Script }
function BeforeEach { param([scriptblock]$Script) $script:EachBlocks.Add($Script) }
function AfterEach { param([scriptblock]$Script) $script:AfterEachBlocks.Add($Script) }
function Describe { param([string]$Name, [scriptblock]$Fixture, [string[]]$Tag) Invoke-Block $Name $Fixture }
function Context { param([string]$Name, [scriptblock]$Fixture, [string[]]$Tag) Invoke-Block $Name $Fixture }
function Invoke-Block {
    param($Name, $Fixture)
    $script:Stack.Add($Name); $e = $script:EachBlocks.Count; $a = $script:AfterEachBlocks.Count
    try { & $Fixture } catch { Add-Fail "$($script:Stack -join ' > ') (block setup)" $_ }
    finally {
        while ($script:EachBlocks.Count -gt $e) { $script:EachBlocks.RemoveAt($script:EachBlocks.Count - 1) }
        while ($script:AfterEachBlocks.Count -gt $a) { $script:AfterEachBlocks.RemoveAt($script:AfterEachBlocks.Count - 1) }
        $script:Stack.RemoveAt($script:Stack.Count - 1)
    }
}
function Add-Fail { param($Name, $Err) $script:Failed++; $script:Failures.Add("[FAIL] $Name`n        $($Err.Exception.Message -replace "`n", "`n        ")"); Write-Host "  [-] $Name" -ForegroundColor Red }
function It {
    param([string]$Name, [scriptblock]$Test, [switch]$Skip, [string[]]$Tag)
    $full = ($script:Stack + $Name) -join ' > '
    if ($Skip) { $script:Skipped++; Write-Host "  [!] $full (skipped)" -ForegroundColor Yellow; return }
    try {
        foreach ($b in @($script:EachBlocks)) { & $b }
        & $Test
        foreach ($b in @($script:AfterEachBlocks)) { & $b }
        $script:Passed++; Write-Host "  [+] $full" -ForegroundColor Green
    }
    catch { Add-Fail $full $_ }
}
function Should {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $InputObject, [switch]$Not,
        [Parameter(Position = 0)] $Expected, [switch]$Be, [switch]$BeExactly, [switch]$BeTrue, [switch]$BeFalse, [switch]$BeNullOrEmpty,
        [switch]$Contain, [switch]$Match, [switch]$Throw, [switch]$HaveCount, [switch]$BeGreaterThan, [switch]$BeLessThan, [switch]$BeLike,
        [switch]$BeOfType, [switch]$Exist, [string]$ExpectedMessage, [string]$Because
    )
    begin { $items = New-Object 'System.Collections.Generic.List[object]' }
    process { if ($PSBoundParameters.ContainsKey('InputObject')) { $items.Add($InputObject) } }
    end {
        $actual = if ($items.Count -eq 1) { $items[0] } elseif ($items.Count -eq 0) { $null } else { $items.ToArray() }
        $ok = $false; $desc = ''
        if ($Throw) {
            $threw = $false; $msg = ''
            try { & $actual | Out-Null } catch { $threw = $true; $msg = $_.Exception.Message }
            $pattern = if ($ExpectedMessage) { $ExpectedMessage } else { $Expected }
            $ok = $threw -and (-not $pattern -or $msg -like "*$pattern*")
            $desc = "expected a throw$(if ($pattern) { " matching '$pattern'" }); threw=$threw message='$msg'"
        }
        elseif ($Be) { $ok = ($actual -eq $Expected); $desc = "expected '$Expected' but got '$actual'" }
        elseif ($BeExactly) { $ok = ($actual -ceq $Expected); $desc = "expected exactly '$Expected' but got '$actual'" }
        elseif ($BeTrue) { $ok = ($actual -eq $true); $desc = "expected `$true but got '$actual'" }
        elseif ($BeFalse) { $ok = ($actual -eq $false -and $null -ne $actual); $desc = "expected `$false but got '$actual'" }
        elseif ($BeNullOrEmpty) { $ok = ($null -eq $actual -or @($actual).Count -eq 0 -or "$actual" -eq ''); $desc = "expected null/empty but got '$actual'" }
        elseif ($Contain) { $ok = (@($actual) -contains $Expected); $desc = "expected collection to contain '$Expected'" }
        elseif ($Match) { $ok = ("$actual" -match $Expected); $desc = "expected '$actual' to match '$Expected'" }
        elseif ($HaveCount) { $n = if ($null -eq $actual) { 0 } else { @($actual).Count }; $ok = ($n -eq $Expected); $desc = "expected $Expected items but got $n" }
        elseif ($BeGreaterThan) { $ok = ($actual -gt $Expected); $desc = "expected '$actual' > '$Expected'" }
        elseif ($BeLessThan) { $ok = ($actual -lt $Expected); $desc = "expected '$actual' < '$Expected'" }
        elseif ($BeLike) { $ok = ("$actual" -like $Expected); $desc = "expected '$actual' like '$Expected'" }
        elseif ($BeOfType) { $ok = ($actual -is [type]$Expected); $desc = "expected type $Expected but got $($actual.GetType().FullName)" }
        elseif ($Exist) { $ok = (Test-Path -LiteralPath $actual); $desc = "expected path '$actual' to exist" }
        else { throw 'PesterShim: unsupported Should operator' }
        if ($Not) { $ok = -not $ok; $desc = "NOT: $desc" }
        if (-not $ok) { throw $desc }
    }
}

$files = foreach ($p in $Path) { if (Test-Path $p -PathType Container) { Get-ChildItem $p -Recurse -Filter '*.Tests.ps1' | Sort-Object FullName } else { Get-Item $p } }
foreach ($f in $files) {
    Write-Host "`n# $($f.Name)" -ForegroundColor Cyan
    $script:Stack.Clear(); $script:EachBlocks.Clear(); $script:AfterEachBlocks.Clear()
    $script:PSScriptRoot_Test = $f.DirectoryName
    try { . $f.FullName } catch { Add-Fail "$($f.Name) (file level)" $_ }
}
Write-Host ("`nTests: {0} passed, {1} failed, {2} skipped" -f $script:Passed, $script:Failed, $script:Skipped) -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
foreach ($m in $script:Failures) { Write-Host $m -ForegroundColor Red }
exit $(if ($script:Failed) { 1 } else { 0 })
