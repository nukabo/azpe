# Public/Invoke-AzpeProbe.ps1
# Primary cmdlet for AZPE PowerShell Compatibility Client

<#
.SYNOPSIS
    Diagnoses Azure Private Endpoint connectivity directly from Windows workloads.

.DESCRIPTION
    Invoke-AzpeProbe is the official PowerShell compatibility client for AZPE.
    It combines DNS resolution, IP classification, TCP connectivity probing,
    TLS validation, and minimal unauthenticated HTTPS health probing into a
    single plain-language diagnostic assessment.

    Designed for restricted Windows and Azure Virtual Desktop environments where
    arbitrary native binary EXEs cannot easily be executed.

    This client operates strictly within enterprise security controls (AppLocker,
    WDAC, Execution Policies, Constrained Language Mode). It does NOT alter or
    bypass any security policy.

.PARAMETER Target
    The Azure service hostname or URL to diagnose (e.g. myvault.vault.azure.net).

.PARAMETER TimeoutSeconds
    Operation deadline timeout in seconds (default: 5).

.PARAMETER Detailed
    Produces multi-section detailed terminal diagnostic output.

.PARAMETER Json
    Outputs machine-readable JSON (schemaVersion: 1) to stdout.

.PARAMETER NoHttp
    Skips the minimal HTTP probe phase and returns Phase 4 TLS results.

.PARAMETER NoColor
    Disables colorized terminal output.

.EXAMPLE
    Invoke-AzpeProbe myvault.vault.azure.net

.EXAMPLE
    Invoke-AzpeProbe -Target https://myvault.vault.azure.net/ -Detailed

.EXAMPLE
    Invoke-AzpeProbe myvault.vault.azure.net -Json

.NOTES
    No Azure login or credentials required.
    Run directly inside the affected workload environment.
#>

Set-StrictMode -Version Latest

function Invoke-AzpeProbe {
    [CmdletBinding()]
    [Alias("azpe")]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 5,

        [Parameter(Mandatory = $false)]
        [switch]$Detailed,

        [Parameter(Mandatory = $false)]
        [switch]$Json,

        [Parameter(Mandatory = $false)]
        [switch]$NoHttp,

        [Parameter(Mandatory = $false)]
        [switch]$NoColor
    )

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()

    # 1. Safety & Parameter Parsing
    try {
        Test-AzpeSafeInput -RawInput $Target
    } catch {
        $errEval = [PSCustomObject]@{
            Scenario    = "INVALID_INPUT"
            ExitCode    = 2
            Title       = "Invalid target"
            Explanation = $_.Exception.Message
            Impact      = "AZPE could not parse the requested target."
            Summary     = $_.Exception.Message
            State       = "UNKNOWN"
            LikelyOwner = "UNKNOWN"
            NextAction  = "Provide a valid Azure service hostname or URL."
            Warnings    = @()
        }
        if ($Json) {
            $cap = Get-AzpeCapability
            $dummyTgt = [PSCustomObject]@{ OriginalInput = $Target; Scheme = "https"; Hostname = $Target; Port = 443; RequestPath = "/"; TargetType = "UNRECOGNIZED_TARGET"; AzureServiceFamily = "NONE" }
            Format-AzpeJsonOutput -Target $dummyTgt -Capability $cap -Evaluation $errEval
        } else {
            Write-Output "AZPE`n`nInvalid target: $($_.Exception.Message)"
        }
        return $errEval
    }

    # 2. Parse & Normalize Target
    $parsedTgt = Parse-AzpeTarget -RawInput $Target
    $cap = Get-AzpeCapability

    # If IP literal or unrecognized non-Azure target, evaluate directly
    if ($parsedTgt.TargetType -in @("IP_LITERAL", "UNRECOGNIZED_TARGET", "POSSIBLE_AZURE_SERVICE")) {
        $eval = Get-AzpeEvaluation -Target $parsedTgt -DNSObs $null -AddrObs $null -TCPObs $null -TLSObs $null -HTTPObs $null
        $swTotal.Stop()

        if ($Json) {
            $jsonStr = Format-AzpeJsonOutput -Target $parsedTgt -Capability $cap -Evaluation $eval -DurationMs $swTotal.ElapsedMilliseconds
            Write-Output $jsonStr
        } else {
            $humanStr = Format-AzpeHumanOutput -Target $parsedTgt -Evaluation $eval -Detailed:$Detailed
            Write-Output $humanStr
        }

        return $eval
    }

    # 3. Phase 1 & 2: DNS Resolution & Address Classification
    $dnsResult = Resolve-AzpeHost -Hostname $parsedTgt.Hostname -Capability $cap -TimeoutSeconds $TimeoutSeconds
    $dnsObs = $dnsResult.DNSObservation
    $addrObs = $dnsResult.AddrObservation

    if ($dnsObs.status -ne "SUCCESS" -or $addrObs.classification -ne "PRIVATE_ONLY") {
        $eval = Get-AzpeEvaluation -Target $parsedTgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $null -TLSObs $null -HTTPObs $null
        $swTotal.Stop()

        if ($Json) {
            $jsonStr = Format-AzpeJsonOutput -Target $parsedTgt -Capability $cap -DNSObs $dnsObs -AddrObs $addrObs -Evaluation $eval -DurationMs $swTotal.ElapsedMilliseconds
            Write-Output $jsonStr
        } else {
            $humanStr = Format-AzpeHumanOutput -Target $parsedTgt -Evaluation $eval -Detailed:$Detailed
            Write-Output $humanStr
        }

        return $eval
    }

    # 4. Phase 3: Direct TCP Connectivity Probing
    $tcpObs = Test-AzpeTcpConnectivity -Hostname $parsedTgt.Hostname -Port $parsedTgt.Port -PrivateIPs $addrObs.privateIps -Capability $cap -TimeoutSeconds $TimeoutSeconds

    if ($tcpObs.aggregateStatus -ne "ALL_CONNECTED") {
        $eval = Get-AzpeEvaluation -Target $parsedTgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $tcpObs -TLSObs $null -HTTPObs $null
        $swTotal.Stop()

        if ($Json) {
            $jsonStr = Format-AzpeJsonOutput -Target $parsedTgt -Capability $cap -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $tcpObs -Evaluation $eval -DurationMs $swTotal.ElapsedMilliseconds
            Write-Output $jsonStr
        } else {
            $humanStr = Format-AzpeHumanOutput -Target $parsedTgt -Evaluation $eval -Detailed:$Detailed
            Write-Output $humanStr
        }

        return $eval
    }

    # 5. Phase 4 & 5: TLS & HTTPS Probing
    $connectedIps = @()
    foreach ($r in $tcpObs.results) {
        if ($r.status -eq "CONNECTED") {
            $connectedIps += $r.address
        }
    }

    $probeResult = Invoke-AzpeCurlHttpsProbe -Hostname $parsedTgt.Hostname -Port $parsedTgt.Port -Scheme $parsedTgt.Scheme -PathAndQuery $parsedTgt.RequestPath -ConnectedIPs $connectedIps -Capability $cap -TimeoutSeconds $TimeoutSeconds -NoHttp:$NoHttp
    $tlsObs = $probeResult.TLSObservation
    $httpObs = $probeResult.HTTPObservation

    # 6. Evaluation Decision Engine
    $eval = Get-AzpeEvaluation -Target $parsedTgt -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $tcpObs -TLSObs $tlsObs -HTTPObs $httpObs -NoHttp:$NoHttp
    $swTotal.Stop()

    # 7. Render Output
    if ($Json) {
        $jsonStr = Format-AzpeJsonOutput -Target $parsedTgt -Capability $cap -DNSObs $dnsObs -AddrObs $addrObs -TCPObs $tcpObs -TLSObs $tlsObs -HTTPObs $httpObs -Evaluation $eval -DurationMs $swTotal.ElapsedMilliseconds
        Write-Output $jsonStr
    } else {
        $humanStr = Format-AzpeHumanOutput -Target $parsedTgt -Evaluation $eval -Detailed:$Detailed
        Write-Output $humanStr
    }

    return $eval
}

function Parse-AzpeTarget {
    [CmdletBinding()]
    param (
        [string]$RawInput
    )

    $trimmed = $RawInput.Trim()

    $hasScheme = $trimmed.Contains("://")
    $scheme = "https"
    $rawToParse = $trimmed

    if ($hasScheme) {
        $schemeEnd = $trimmed.IndexOf("://")
        $scheme = $trimmed.Substring(0, $schemeEnd).ToLower()
        if ($scheme -ne "http" -and $scheme -ne "https") {
            throw "unsupported scheme '$scheme' (only http and https are supported)"
        }
    } else {
        $rawToParse = "https://$trimmed"
    }

    $uri = [System.Uri]::new($rawToParse)

    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
        throw "URLs containing embedded credentials are not allowed"
    }

    $hostname = $uri.DnsSafeHost
    if ([string]::IsNullOrEmpty($hostname)) {
        $hostname = $uri.Host
    }

    $hostname = $hostname.Trim('[', ']')
    if ([string]::IsNullOrEmpty($hostname)) {
        throw "missing hostname in target"
    }

    $port = $uri.Port
    if ($port -le 0) {
        $port = if ($scheme -eq "http") { 80 } else { 443 }
    }

    $requestPath = $uri.PathAndQuery
    if ([string]::IsNullOrEmpty($requestPath)) {
        $requestPath = "/"
    }

    $cls = Classify-AzpeTarget -Hostname $hostname

    return [PSCustomObject]@{
        OriginalInput      = $trimmed
        Scheme             = $scheme
        Hostname           = $hostname
        Port               = $port
        RequestPath        = $requestPath
        TargetType         = $cls.TargetType
        AzureServiceFamily = $cls.AzureServiceFamily
    }
}
