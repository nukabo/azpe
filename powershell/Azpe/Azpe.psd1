@{
    RootModule        = 'Azpe.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = '8f3e2b1a-9c4d-4e5f-b6a7-0c8d9e1f2a3b'
    Author            = 'AZPE Authors'
    CompanyName       = 'AZPE Open Source Project'
    Copyright         = '(c) 2026 AZPE Authors. Licensed under MIT License.'
    Description       = 'AZPE (Azure Private Endpoint Connectivity Diagnostic Utility) PowerShell Compatibility Client for restricted Windows and Azure Virtual Desktop environments.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @('Invoke-AzpeProbe')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('azpe')

    PrivateData       = @{
        PSData = @{
            ProjectUri   = 'https://github.com/nukabo/azpe'
            LicenseUri   = 'https://github.com/nukabo/azpe/blob/main/LICENSE'
            Tags         = @('Azure', 'PrivateEndpoint', 'Diagnostics', 'DNS', 'Network', 'AVD')
            ReleaseNotes = 'Initial release of AZPE PowerShell Compatibility Client'
        }
    }
}
