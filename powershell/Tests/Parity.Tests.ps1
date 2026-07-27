# powershell/Tests/Parity.Tests.ps1
# Native vs PowerShell Result Semantics and Exit Code Parity Tests

beforeAll {
    . (Join-Path $PSScriptRoot "../Invoke-AzpeProbe.ps1")
}

describe "Assessment Scenario & Exit Code Parity" {
    it "Returns Exit Code 8 for IP literal targets" {
        $eval = Invoke-AzpeProbe -Target "10.0.0.1"
        $eval.ExitCode | should -be 8
        $eval.Title | should -be "The Azure service hostname is required"
        $eval.Scenario | should -be "IP_LITERAL"
    }

    it "Returns Exit Code 8 for unrecognized targets" {
        $eval = Invoke-AzpeProbe -Target "example.com"
        $eval.ExitCode | should -be 8
        $eval.Title | should -be "Cannot test this target"
        $eval.Scenario | should -be "UNRECOGNIZED_TARGET"
    }

    it "Returns Exit Code 0 for HTTP 403 Access Denied responses" {
        $tgt = [PSCustomObject]@{ OriginalInput = "myvault.vault.azure.net"; Scheme = "https"; Hostname = "myvault.vault.azure.net"; Port = 443; RequestPath = "/"; TargetType = "RECOGNIZED_AZURE_SERVICE"; AzureServiceFamily = "KEY_VAULT" }
        $dnsObs = [PSCustomObject]@{ status = "SUCCESS"; resolverMode = "GO_BUILTIN"; queryHostname = "myvault.vault.azure.net"; addresses = @([PSCustomObject]@{ address = "10.42.3.7"; classification = "PRIVATE" }); aggregateClassification = "PRIVATE_ONLY" }
        $addrObs = [PSCustomObject]@{ classification = "PRIVATE_ONLY"; privateIps = @("10.42.3.7"); publicIps = @() }
        $tcpObs = [PSCustomObject]@{ status = "SUCCESS"; aggregateStatus = "ALL_CONNECTED"; results = @([PSCustomObject]@{ address = "10.42.3.7"; destination = "10.42.3.7:443"; status = "CONNECTED"; durationMs = 5 }) }
        $tlsObs = [PSCustomObject]@{ status = "SUCCESS"; aggregateStatus = "ALL_VALID"; results = @([PSCustomObject]@{ address = "10.42.3.7"; destination = "10.42.3.7:443"; status = "VALID"; durationMs = 10 }) }
        $httpObs = [PSCustomObject]@{ status = "SUCCESS"; aggregateStatus = "ALL_RESPONDED"; results = @([PSCustomObject]@{ address = "10.42.3.7"; destination = "10.42.3.7:443"; statusCode = 403; statusText = "Forbidden"; responseCategory = "ACCESS_DENIED"; status = "RESPONDED"; durationMs = 20 }) }

        $eval = Get-AzpeEvaluation -Target $tgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $tcpObs -TLSObs $tlsObs -HTTPObs $httpObs
        $eval.ExitCode | should -be 0
        $eval.Title | should -be "The Azure service responded"
        $eval.Scenario | should -be "PRIVATE_HTTP_ACCESS_DENIED"
    }

    it "Returns Exit Code 5 when TCP fails for all private addresses" {
        $tgt = [PSCustomObject]@{ OriginalInput = "myvault.vault.azure.net"; Scheme = "https"; Hostname = "myvault.vault.azure.net"; Port = 443; RequestPath = "/"; TargetType = "RECOGNIZED_AZURE_SERVICE"; AzureServiceFamily = "KEY_VAULT" }
        $dnsObs = [PSCustomObject]@{ status = "SUCCESS"; resolverMode = "GO_BUILTIN"; queryHostname = "myvault.vault.azure.net"; addresses = @([PSCustomObject]@{ address = "10.42.3.7"; classification = "PRIVATE" }); aggregateClassification = "PRIVATE_ONLY" }
        $addrObs = [PSCustomObject]@{ classification = "PRIVATE_ONLY"; privateIps = @("10.42.3.7"); publicIps = @() }
        $tcpObs = [PSCustomObject]@{ status = "FAILED"; aggregateStatus = "NONE_CONNECTED"; results = @([PSCustomObject]@{ address = "10.42.3.7"; destination = "10.42.3.7:443"; status = "TIMED_OUT"; durationMs = 5000 }) }

        $eval = Get-AzpeEvaluation -Target $tgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $tcpObs -TLSObs $null -HTTPObs $null
        $eval.ExitCode | should -be 5
        $eval.Title | should -be "The private address cannot be reached"
        $eval.Scenario | should -be "PRIVATE_TCP_UNREACHABLE"
    }

    it "Returns Exit Code 4 when DNS resolves only to public IP addresses" {
        $tgt = [PSCustomObject]@{ OriginalInput = "myvault.vault.azure.net"; Scheme = "https"; Hostname = "myvault.vault.azure.net"; Port = 443; RequestPath = "/"; TargetType = "RECOGNIZED_AZURE_SERVICE"; AzureServiceFamily = "KEY_VAULT" }
        $dnsObs = [PSCustomObject]@{ status = "SUCCESS"; resolverMode = "GO_BUILTIN"; queryHostname = "myvault.vault.azure.net"; addresses = @([PSCustomObject]@{ address = "20.42.64.44"; classification = "PUBLIC" }); aggregateClassification = "PUBLIC_ONLY" }
        $addrObs = [PSCustomObject]@{ classification = "PUBLIC_ONLY"; privateIps = @(); publicIps = @("20.42.64.44") }

        $eval = Get-AzpeEvaluation -Target $tgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $null -TLSObs $null -HTTPObs $null
        $eval.ExitCode | should -be 4
        $eval.Title | should -be "This workload is not using private DNS"
        $eval.Scenario | should -be "PRIVATE_DNS_NOT_ACTIVE"
    }

    it "Returns Exit Code 3 when DNS resolution fails" {
        $tgt = [PSCustomObject]@{ OriginalInput = "nonexistent.vault.azure.net"; Scheme = "https"; Hostname = "nonexistent.vault.azure.net"; Port = 443; RequestPath = "/"; TargetType = "RECOGNIZED_AZURE_SERVICE"; AzureServiceFamily = "KEY_VAULT" }
        $dnsObs = [PSCustomObject]@{ status = "NOT_FOUND"; resolverMode = "GO_BUILTIN"; queryHostname = "nonexistent.vault.azure.net"; addresses = @(); aggregateClassification = "NONE" }
        $addrObs = [PSCustomObject]@{ classification = "NONE"; privateIps = @(); publicIps = @() }

        $eval = Get-AzpeEvaluation -Target $tgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $null -TLSObs $null -HTTPObs $null
        $eval.ExitCode | should -be 3
        $eval.Title | should -be "The Azure service name cannot be resolved"
        $eval.Scenario | should -be "DNS_LOOKUP_FAILED"
    }
}
