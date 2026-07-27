# Private/Output.ps1
# Terminal rendering and JSON output formatting for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Format-AzpeHumanOutput {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Target,
        [PSCustomObject]$Evaluation,
        [switch]$Detailed
    )

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine("AZPE")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine($Evaluation.Title)
    [void]$sb.AppendLine()
    [void]$sb.AppendLine($Evaluation.Summary)

    if ($Detailed) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("--- DETAILED OBSERVATIONS ---")
        [void]$sb.AppendLine("Target FQDN:          $($Target.Hostname)")
        [void]$sb.AppendLine("Target Port:          $($Target.Port)")
        [void]$sb.AppendLine("Target Type:          $($Target.TargetType)")
        [void]$sb.AppendLine("Azure Service Family: $($Target.AzureServiceFamily)")
        [void]$sb.AppendLine("Engine Name:          POWERSHELL_COMPAT")
        [void]$sb.AppendLine("Engine Version:       0.2.0-rc.1")
        [void]$sb.AppendLine("Language Mode:        $($ExecutionContext.SessionState.LanguageMode)")
    }

    return $sb.ToString()
}

function Format-AzpeJsonOutput {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Target,
        [PSCustomObject]$Capability,
        [PSCustomObject]$DNSObs,
        [PSCustomObject]$AddrObs,
        [PSCustomObject]$TCPObs,
        [PSCustomObject]$TLSObs,
        [PSCustomObject]$HTTPObs,
        [PSCustomObject]$Evaluation,
        [int]$DurationMs = 0
    )

    # Force array wrapping for PowerShell single-element array collapsing
    $dnsAddresses = if ($DNSObs -and $DNSObs.addresses) { @($DNSObs.addresses) } else { @() }
    $addrAddresses = if ($AddrObs -and $AddrObs.addresses) { @($AddrObs.addresses) } else { @() }
    $privIps = if ($AddrObs -and $AddrObs.privateIps) { @($AddrObs.privateIps) } else { @() }
    $pubIps = if ($AddrObs -and $AddrObs.publicIps) { @($AddrObs.publicIps) } else { @() }
    $tcpResults = if ($TCPObs -and $TCPObs.results) { @($TCPObs.results) } else { @() }
    $tlsResults = if ($TLSObs -and $TLSObs.results) { @($TLSObs.results) } else { @() }
    $httpResults = if ($HTTPObs -and $HTTPObs.results) { @($HTTPObs.results) } else { @() }
    $warnings = if ($Evaluation -and $Evaluation.Warnings) { @($Evaluation.Warnings) } else { @() }
    $errors = @()

    $osVer = [System.Environment]::OSVersion.VersionString
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

    $jsonObj = [ordered]@{
        schemaVersion = 1
        toolVersion   = "0.1.0"
        timestamp     = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        durationMs    = $DurationMs
        engine        = [ordered]@{
            name              = "POWERSHELL_COMPAT"
            version           = "0.1.0"
            powerShellVersion = $Capability.PowerShellVersion
            powerShellEdition = $Capability.PowerShellEdition
            languageMode      = $Capability.LanguageMode
        }
        target        = [ordered]@{
            originalInput      = $Target.OriginalInput
            scheme             = $Target.Scheme
            hostname           = $Target.Hostname
            port               = $Target.Port
            requestPath        = $Target.RequestPath
            targetType         = $Target.TargetType
            azureServiceFamily = $Target.AzureServiceFamily
        }
        environment   = [ordered]@{
            os          = $osVer
            architecture = $arch
            hostName    = [System.Environment]::MachineName
            isContainer = $false
            userScope   = if ([System.Environment]::UserName) { $System.Environment.UserName } else { "user" }
        }
        dns           = [ordered]@{
            status                  = if ($DNSObs) { $DNSObs.status } else { "NOT_ATTEMPTED" }
            resolverMode            = "GO_BUILTIN"
            queryHostname           = $Target.Hostname
            durationMs              = if ($DNSObs) { $DNSObs.durationMs } else { 0 }
            addresses               = $dnsAddresses
            aggregateClassification = if ($DNSObs) { $DNSObs.aggregateClassification } else { "NONE" }
            isIpLiteral             = if ($DNSObs) { $DNSObs.isIpLiteral } else { $false }
        }
        address       = [ordered]@{
            classification = if ($AddrObs) { $AddrObs.classification } else { "NONE" }
            addresses      = $addrAddresses
            privateIps     = $privIps
            publicIps      = $pubIps
        }
        tcp           = [ordered]@{
            status          = if ($TCPObs) { $TCPObs.status } else { "NOT_ATTEMPTED" }
            aggregateStatus = if ($TCPObs) { $TCPObs.aggregateStatus } else { "NOT_ATTEMPTED" }
            port            = $Target.Port
            durationMs      = if ($TCPObs) { $TCPObs.durationMs } else { 0 }
            results         = $tcpResults
        }
        tls           = [ordered]@{
            status          = if ($TLSObs) { $TLSObs.status } else { "NOT_ATTEMPTED" }
            aggregateStatus = if ($TLSObs) { $TLSObs.aggregateStatus } else { "NOT_ATTEMPTED" }
            serverName      = $Target.Hostname
            durationMs      = if ($TLSObs) { $TLSObs.durationMs } else { 0 }
            results         = $tlsResults
        }
        http          = [ordered]@{
            status          = if ($HTTPObs) { $HTTPObs.status } else { "NOT_ATTEMPTED" }
            aggregateStatus = if ($HTTPObs) { $HTTPObs.aggregateStatus } else { "NOT_ATTEMPTED" }
            method          = "GET"
            path            = $Target.RequestPath
            durationMs      = if ($HTTPObs) { $HTTPObs.durationMs } else { 0 }
            results         = $httpResults
        }
        assessment    = [ordered]@{
            scenario    = $Evaluation.Scenario
            exitCode    = $Evaluation.ExitCode
            title       = $Evaluation.Title
            explanation = $Evaluation.Explanation
            impact      = $Evaluation.Impact
            summary     = $Evaluation.Summary
            state       = $Evaluation.State
            likelyOwner = $Evaluation.LikelyOwner
            nextAction  = $Evaluation.NextAction
        }
        errors        = $errors
        warnings      = $warnings
    }

    return (ConvertTo-Json $jsonObj -Depth 10)
}
