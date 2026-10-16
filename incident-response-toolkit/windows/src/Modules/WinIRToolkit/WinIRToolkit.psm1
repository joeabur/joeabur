# WinIRToolkit root module. Dot-sources private helpers and public commands, then exports only the public surface.
Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot
$script:SrcRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
$script:IRConfigRoot = Join-Path $script:SrcRoot 'Configuration'
$script:ToolVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'WinIRToolkit.psd1')).ModuleVersion
$script:CollectorNames = @('inventory', 'processes', 'network', 'accounts', 'persistence', 'events')

foreach ($dir in @((Join-Path $script:SrcRoot 'Private'), (Join-Path $PSScriptRoot 'Public'))) {
    foreach ($file in @(Get-ChildItem -Path $dir -Filter '*.ps1' -File | Sort-Object Name)) { . $file.FullName }
}

Export-ModuleMember -Function @(
    'Get-IRPlatformInfo', 'Test-IRPrerequisite', 'Test-IRElevated', 'Get-IRConfiguration', 'Get-IRCollectionPlan', 'Invoke-IRCollection',
    'Get-IRHostInventory', 'Get-IRProcessInfo', 'Get-IRNetworkInfo', 'Get-IRAccountInfo', 'Get-IRPersistenceInfo', 'Get-IREventLog',
    'Import-IRIoc', 'Find-IRIocMatch', 'Import-IRRule', 'Invoke-IRAnalysis', 'Export-IRReport', 'Test-IREvidenceManifest', 'Protect-IREvidenceDirectory', 'Test-IRReportSchema'
)
