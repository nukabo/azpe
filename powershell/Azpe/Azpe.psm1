# Azpe.psm1
# Root module for AZPE PowerShell Compatibility Client

Set-StrictMode -Version Latest

$privateFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "Private") -Filter "*.ps1" -ErrorAction SilentlyContinue
foreach ($file in $privateFiles) {
    . $file.FullName
}

$publicFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "Public") -Filter "*.ps1" -ErrorAction SilentlyContinue
foreach ($file in $publicFiles) {
    . $file.FullName
}

Export-ModuleMember -Function "Invoke-AzpeProbe" -Alias "azpe"
