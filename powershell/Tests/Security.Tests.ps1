# powershell/Tests/Security.Tests.ps1
# Security invariant checks asserting absence of bypass techniques and credentials in AZPE PowerShell Client

beforeAll {
    $script:prodFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot "../Azpe") -Recurse -Filter "*.ps1"
    $script:standaloneFile = Get-Item -Path (Join-Path $PSScriptRoot "../Invoke-AzpeProbe.ps1") -ErrorAction SilentlyContinue
}

describe "Security Invariants & No Security-Control Bypass" {
    it "Contains no forbidden bypass functions or commands in production code" {
        $forbiddenTerms = @(
            "Invoke-Expression",
            "IEX",
            "-EncodedCommand",
            "ExecutionPolicy Bypass",
            "Set-ExecutionPolicy",
            "Add-MpPreference",
            "Set-MpPreference",
            "Unblock-File",
            "InsecureSkipVerify",
            "ServerCertificateValidationCallback",
            "TrustAllCerts",
            "ServicePointManager",
            "FromBase64String",
            "DownloadString",
            "WebClient",
            "Invoke-WebRequest",
            "Invoke-RestMethod",
            "Start-BitsTransfer",
            "certutil",
            "rundll32",
            "regsvr32",
            "mshta"
        )

        foreach ($file in $script:prodFiles) {
            $content = Get-Content -Path $file.FullName -Raw
            foreach ($term in $forbiddenTerms) {
                $content | should -not -match [regex]::Escape($term)
            }
        }

        if ($script:standaloneFile) {
            $standaloneContent = Get-Content -Path $script:standaloneFile.FullName -Raw
            foreach ($term in $forbiddenTerms) {
                $standaloneContent | should -not -match [regex]::Escape($term)
            }
        }
    }

    it "Contains no insecure or credential-sending curl flags in argument arrays" {
        $forbiddenCurlFlags = @(
            "--insecure",
            "-k",
            "--proxy-insecure",
            "--ssl-no-revoke",
            "--user",
            "--header",
            "Authorization",
            "--cookie",
            "--netrc",
            "--proxy-user",
            "--location",
            "-L"
        )

        foreach ($file in $script:prodFiles) {
            $content = Get-Content -Path $file.FullName -Raw
            foreach ($flag in $forbiddenCurlFlags) {
                # Check for curl flag in literal string tokens
                $content | should -not -match "'$flag'"
                $content | should -not -match "`"$flag`""
            }
        }
    }
}
