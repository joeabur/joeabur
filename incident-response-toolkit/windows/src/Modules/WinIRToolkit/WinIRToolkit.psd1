@{
    RootModule            = 'WinIRToolkit.psm1'
    ModuleVersion         = '0.1.0'
    GUID                  = 'b6b2a3c4-5f1e-4d0a-9a37-5f3c1d2e8a11'
    Author                = 'Joseph Mark Ochieng'
    Copyright             = '(c) 2026 Joseph Mark Ochieng. MIT License.'
    Description           = 'Read-only Windows incident response collection, IOC matching, detections and reporting.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @(
        'Get-IRPlatformInfo', 'Test-IRPrerequisite', 'Test-IRElevated', 'Get-IRConfiguration', 'Get-IRCollectionPlan', 'Invoke-IRCollection',
        'Get-IRHostInventory', 'Get-IRProcessInfo', 'Get-IRNetworkInfo', 'Get-IRAccountInfo', 'Get-IRPersistenceInfo', 'Get-IREventLog',
        'Import-IRIoc', 'Find-IRIocMatch', 'Import-IRRule', 'Invoke-IRAnalysis', 'Export-IRReport', 'Test-IREvidenceManifest', 'Protect-IREvidenceDirectory', 'Test-IRReportSchema'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{ PSData = @{ Tags = @('IncidentResponse', 'DFIR', 'Windows', 'Security'); LicenseUri = 'https://opensource.org/licenses/MIT' } }
}
