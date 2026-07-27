# powershell/Tests/Azpe.Tests.ps1
# Pester unit tests for AZPE PowerShell Client

beforeAll {
    . (Join-Path $PSScriptRoot "../Invoke-AzpeProbe.ps1")
}

describe "Target Parsing & Normalization" {
    it "Parses plain hostname" {
        $t = Parse-AzpeTarget -RawInput "myvault.vault.azure.net"
        $t.Scheme | should -be "https"
        $t.Hostname | should -be "myvault.vault.azure.net"
        $t.Port | should -be 443
        $t.RequestPath | should -be "/"
        $t.TargetType | should -be "RECOGNIZED_AZURE_SERVICE"
        $t.AzureServiceFamily | should -be "KEY_VAULT"
    }

    it "Parses HTTPS URL with path and query" {
        $t = Parse-AzpeTarget -RawInput "https://mystorage.blob.core.windows.net/container/blob.txt?sig=secret123&api-version=2020-08-04"
        $t.Scheme | should -be "https"
        $t.Hostname | should -be "mystorage.blob.core.windows.net"
        $t.Port | should -be 443
        $t.RequestPath | should -be "/container/blob.txt?sig=secret123&api-version=2020-08-04"
        $t.AzureServiceFamily | should -be "STORAGE_BLOB"
    }

    it "Rejects embedded credentials" {
        { Parse-AzpeTarget -RawInput "https://user:pass@myvault.vault.azure.net" } | should -throw "URLs containing embedded credentials are not allowed"
    }

    it "Classifies IP literal" {
        $t = Parse-AzpeTarget -RawInput "10.0.0.1"
        $t.TargetType | should -be "IP_LITERAL"
        $t.AzureServiceFamily | should -be "NONE"
    }
}

describe "Azure Suffix Catalogue & Boundary Safety" {
    it "Recognizes Key Vault" {
        $c = Classify-AzpeTarget -Hostname "myvault.vault.azure.net"
        $c.TargetType | should -be "RECOGNIZED_AZURE_SERVICE"
        $c.AzureServiceFamily | should -be "KEY_VAULT"
    }

    it "Recognizes Managed HSM Key Vault" {
        $c = Classify-AzpeTarget -Hostname "myhsm.managedhsm.azure.net"
        $c.TargetType | should -be "RECOGNIZED_AZURE_SERVICE"
        $c.AzureServiceFamily | should -be "KEY_VAULT"
    }

    it "Recognizes Storage Blob" {
        $c = Classify-AzpeTarget -Hostname "mystorage.blob.core.windows.net"
        $c.TargetType | should -be "RECOGNIZED_AZURE_SERVICE"
        $c.AzureServiceFamily | should -be "STORAGE_BLOB"
    }

    it "Enforces boundary safety on attacker lookalike domain" {
        $c = Classify-AzpeTarget -Hostname "myvault.vault.azure.net.attacker.example"
        $c.TargetType | should -be "UNRECOGNIZED_TARGET"
        $c.AzureServiceFamily | should -be "NONE"
    }
}

describe "IP Address Classification" {
    it "Classifies IPv4 RFC 1918 Private addresses" {
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("10.1.2.3")) | should -be "PRIVATE"
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("172.16.5.10")) | should -be "PRIVATE"
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("192.168.1.1")) | should -be "PRIVATE"
    }

    it "Classifies IPv6 RFC 4193 Unique Local Private addresses" {
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("fd00::1")) | should -be "PRIVATE"
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("fc00::1234")) | should -be "PRIVATE"
    }

    it "Classifies Public IP addresses" {
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("20.42.64.44")) | should -be "PUBLIC"
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("8.8.8.8")) | should -be "PUBLIC"
    }

    it "Classifies Loopback and Link-Local addresses" {
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("127.0.0.1")) | should -be "LOOPBACK"
        Classify-AzpeIpAddress -IP ([System.Net.IPAddress]::Parse("169.254.169.254")) | should -be "LINK_LOCAL"
    }
}

describe "Query Parameter Redaction" {
    it "Redacts query parameter values in request path" {
        $red = Redact-AzpeQueryValues -PathAndQuery "/path/to/resource?sig=supersecret&api-version=2021-01-01"
        $red | should -be "/path/to/resource?sig=REDACTED&api-version=REDACTED"
    }

    it "Preserves paths without query parameters" {
        $red = Redact-AzpeQueryValues -PathAndQuery "/path/to/resource"
        $red | should -be "/path/to/resource"
    }

    it "Sanitizes userinfo from Location headers" {
        $san = Sanitize-AzpeLocation -Location "https://user:password@service.azure.com/path?token=abc"
        $san | should -not -match "password"
        $san | should -not -match "token=abc"
        $san | should -match "token=REDACTED"
    }
}
