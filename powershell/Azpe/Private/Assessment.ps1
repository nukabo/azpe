# Private/Assessment.ps1
# Assessment decision engine and evaluation logic for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Get-AzpeEvaluation {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Target,
        [PSCustomObject]$DNSObs,
        [PSCustomObject]$AddrObs,
        [PSCustomObject]$TCPObs,
        [PSCustomObject]$TLSObs,
        [PSCustomObject]$HTTPObs,
        [switch]$NoHttp
    )

    $hostname = $Target.Hostname

    # 1. IP Literal Target
    if ($Target.TargetType -eq "IP_LITERAL") {
        $ex = "An IP address was provided instead of an Azure service hostname."
        $imp = "An IP address cannot test Private Endpoint DNS."
        $sum = "You entered an IP address:`n$hostname`n`n$imp`n`nUse the Azure service hostname configured in your application."
        return [PSCustomObject]@{
            Scenario    = "IP_LITERAL"
            ExitCode    = 8
            Title       = "The Azure service hostname is required"
            Explanation = $ex
            Impact      = $imp
            Summary     = $sum
            State       = "UNKNOWN"
            LikelyOwner = "UNKNOWN"
            NextAction  = "Use the Azure service hostname configured in your application."
            Warnings    = @()
        }
    }

    # 2. Unrecognized Non-Azure Target
    if ($Target.TargetType -eq "UNRECOGNIZED_TARGET") {
        $ex = "$hostname is not a recognized Azure Private Endpoint service hostname."
        $imp = "AZPE can only diagnose recognized Azure Private Endpoint targets."
        $sum = "$ex`n`nUse the Azure service hostname configured in your application, for example:`n  myvault.vault.azure.net`n  mystorage.blob.core.windows.net`n  mysearch.search.windows.net"
        return [PSCustomObject]@{
            Scenario    = "UNRECOGNIZED_TARGET"
            ExitCode    = 8
            Title       = "Cannot test this target"
            Explanation = $ex
            Impact      = $imp
            Summary     = $sum
            State       = "UNKNOWN"
            LikelyOwner = "UNKNOWN"
            NextAction  = "Use the Azure service hostname configured in your application."
            Warnings    = @()
        }
    }

    # 3. Possible Azure Service
    if ($Target.TargetType -eq "POSSIBLE_AZURE_SERVICE") {
        $ex = "AZPE's service catalogue does not recognize this specific Azure hostname pattern yet."
        $imp = "No Private Endpoint conclusion was made."
        $sum = "$hostname`n`n$imp`n`nYou can use -Detailed to view target information."
        return [PSCustomObject]@{
            Scenario    = "POSSIBLE_AZURE"
            ExitCode    = 8
            Title       = "This Azure service is not supported yet"
            Explanation = $ex
            Impact      = $imp
            Summary     = $sum
            State       = "UNKNOWN"
            LikelyOwner = "UNKNOWN"
            NextAction  = "You can use -Detailed to view target information."
            Warnings    = @()
        }
    }

    # 4. Recognized Azure Service - Evaluate DNS Results
    if ($DNSObs.status -in @("NOT_FOUND", "TIMEOUT", "TEMPORARY_FAILURE", "FAILURE")) {
        $ex = "The Azure service hostname could not be resolved."
        $imp = "DNS resolution failed from this execution environment."
        $sum = "$hostname`n`nWhat to do:`nRun this check inside the affected workload. If it still fails, send this result to your network or DNS team."
        return [PSCustomObject]@{
            Scenario    = "DNS_LOOKUP_FAILED"
            ExitCode    = 3
            Title       = "The Azure service name cannot be resolved"
            Explanation = $ex
            Impact      = $imp
            Summary     = $sum
            State       = "BROKEN"
            LikelyOwner = "DNS_OR_NETWORK"
            NextAction  = "Run this check inside the affected workload. If it still fails, send this result to your network or DNS team."
            Warnings    = @()
        }
    }

    switch ($AddrObs.classification) {
        "PRIVATE_ONLY" {
            # Evaluate TCP Connectivity
            if ($TCPObs -and $TCPObs.aggregateStatus -ne "NOT_ATTEMPTED") {
                switch ($TCPObs.aggregateStatus) {
                    "ALL_CONNECTED" {
                        # Evaluate TLS/HTTPS
                        if ($TLSObs -and $TLSObs.aggregateStatus -ne "NOT_ATTEMPTED") {
                            switch ($TLSObs.aggregateStatus) {
                                "ALL_VALID" {
                                    # Evaluate HTTP Probing
                                    if ($HTTPObs -and $HTTPObs.aggregateStatus -ne "NOT_ATTEMPTED") {
                                        switch ($HTTPObs.aggregateStatus) {
                                            "ALL_RESPONDED" {
                                                return Build-AzpeHttpRespondedEvaluation -Target $Target -Results $HTTPObs.results
                                            }
                                            "NONE_RESPONDED" {
                                                $lines = @()
                                                foreach ($r in $HTTPObs.results) {
                                                    $lines += "$hostname -> $($r.destination)"
                                                }
                                                $destBlock = $lines -join "`n"
                                                $ex = "The secure connection works, but no HTTP response was received before the timeout."
                                                $imp = "The HTTP request timed out waiting for headers from the Azure service."
                                                $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   Response timed out`n`nThe secure connection works, but no HTTP response was received before the timeout.`n`nWhat to do:`nSend the detailed result to the application platform or service owner team."
                                                return [PSCustomObject]@{
                                                    Scenario    = "PRIVATE_HTTP_TIMEOUT"
                                                    ExitCode    = 7
                                                    Title       = "The Azure service did not respond in time"
                                                    Explanation = $ex
                                                    Impact      = $imp
                                                    Summary     = $sum
                                                    State       = "BROKEN"
                                                    LikelyOwner = "APPLICATION_OR_SERVICE"
                                                    NextAction  = "Send the detailed result to the application platform or service owner team."
                                                    Warnings    = @()
                                                }
                                            }
                                            "PARTIALLY_RESPONDED" {
                                                $lines = @()
                                                foreach ($r in $HTTPObs.results) {
                                                    if ($r.status -eq "RESPONDED") {
                                                        $lines += "$($r.destination.PadRight(18)) HTTP $($r.statusCode) $($r.statusText)"
                                                    } else {
                                                        $lines += "$($r.destination.PadRight(18)) HTTP probe failed"
                                                    }
                                                }
                                                $destBlock = $lines -join "`n"
                                                $ex = "At least one private address returned an HTTP response and at least one did not."
                                                $imp = "The application may behave failure-prone or intermittently depending on which address it uses."
                                                $sum = "$destBlock`n`nThe application may behave intermittently depending on which address it uses.`n`nWhat to do:`nSend the detailed result to your application platform or service owner team."
                                                return [PSCustomObject]@{
                                                    Scenario    = "PRIVATE_HTTP_PARTIAL"
                                                    ExitCode    = 8
                                                    Title       = "The Azure service responded on only some private addresses"
                                                    Explanation = $ex
                                                    Impact      = $imp
                                                    Summary     = $sum
                                                    State       = "UNKNOWN"
                                                    LikelyOwner = "APPLICATION_OR_SERVICE"
                                                    NextAction  = "Send the detailed result to your application platform or service owner team."
                                                    Warnings    = @()
                                                }
                                            }
                                        }
                                    }

                                    # TLS Valid fallback (when -NoHttp is used)
                                    $title = if ($TLSObs.results.Count -gt 1) { "Secure private connections look correct" } else { "Secure private connection looks correct" }
                                    $lines = @()
                                    foreach ($r in $TLSObs.results) {
                                        if ($TLSObs.results.Count -eq 1) {
                                            $lines += "$hostname -> $($r.destination)"
                                        } else {
                                            $lines += "$($r.destination.PadRight(18)) TLS valid"
                                        }
                                    }
                                    $destBlock = $lines -join "`n"
                                    $connStatusStr = if ($TLSObs.results.Count -gt 1) { "Working for all addresses" } else { "Working" }
                                    $tlsStatusStr = if ($TLSObs.results.Count -gt 1) { "Valid for all addresses" } else { "Valid" }
                                    $ex = "The Azure service hostname resolved privately, and this workload established a valid, trusted TLS connection to every private address."
                                    $imp = "DNS, TCP, and TLS validation look correct."
                                    $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      $connStatusStr`nTLS             $tlsStatusStr`nAzure service   Not tested`n`nHTTP probing was disabled with -NoHttp."
                                    return [PSCustomObject]@{
                                        Scenario    = "PRIVATE_TLS_VALID"
                                        ExitCode    = 0
                                        Title       = $title
                                        Explanation = $ex
                                        Impact      = $imp
                                        Summary     = $sum
                                        State       = "WORKING"
                                        LikelyOwner = "UNKNOWN"
                                        NextAction  = ""
                                        Warnings    = @()
                                    }
                                }

                                "NONE_VALID" {
                                    $lines = @()
                                    foreach ($r in $TLSObs.results) {
                                        $lines += "$hostname -> $($r.destination)"
                                    }
                                    $destBlock = $lines -join "`n"

                                    $domStatus = $TLSObs.results[0].status
                                    if ($domStatus -eq "HOSTNAME_MISMATCH") {
                                        $ex = "The private address is reachable, but it presented a certificate for a different hostname."
                                        $imp = "The application cannot establish a secure connection because certificate hostname validation failed."
                                        $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Hostname mismatch`n`nThe address is reachable, but it presented a certificate for a different hostname.`n`nWhat to do:`nSend the detailed result to your network security team."
                                        return [PSCustomObject]@{
                                            Scenario    = "PRIVATE_TLS_HOSTNAME_MISMATCH"
                                            ExitCode    = 6
                                            Title       = "The certificate does not match the Azure service name"
                                            Explanation = $ex
                                            Impact      = $imp
                                            Summary     = $sum
                                            State       = "BROKEN"
                                            LikelyOwner = "SECURITY_OR_PROXY"
                                            NextAction  = "Send the detailed result to your network security team."
                                            Warnings    = @()
                                        }
                                    } elseif ($domStatus -eq "UNTRUSTED_CERTIFICATE") {
                                        $ex = "The private address is reachable, but the certificate presented is not trusted by this workload."
                                        $imp = "The application cannot establish a secure connection because certificate trust validation failed."
                                        $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Certificate not trusted`n`nWhat to do:`nSend the detailed result to your application platform or network security team."
                                        return [PSCustomObject]@{
                                            Scenario    = "PRIVATE_TLS_UNTRUSTED"
                                            ExitCode    = 6
                                            Title       = "The certificate is not trusted by this workload"
                                            Explanation = $ex
                                            Impact      = $imp
                                            Summary     = $sum
                                            State       = "BROKEN"
                                            LikelyOwner = "SECURITY_OR_PROXY"
                                            NextAction  = "Send the detailed result to your application platform or network security team."
                                            Warnings    = @()
                                        }
                                    } else {
                                        $ex = "The private address is reachable, but TLS negotiation failed."
                                        $imp = "The application cannot establish a secure TLS connection."
                                        $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Failed`n`nThe private address is reachable, but TLS negotiation failed.`n`nWhat to do:`nSend the detailed result to your application platform or network security team."
                                        return [PSCustomObject]@{
                                            Scenario    = "PRIVATE_TLS_FAILED"
                                            ExitCode    = 6
                                            Title       = "The secure connection could not be established"
                                            Explanation = $ex
                                            Impact      = $imp
                                            Summary     = $sum
                                            State       = "BROKEN"
                                            LikelyOwner = "SECURITY_OR_PROXY"
                                            NextAction  = "Send the detailed result to your application platform or network security team."
                                            Warnings    = @()
                                        }
                                    }
                                }

                                "PARTIALLY_VALID" {
                                    $lines = @()
                                    foreach ($r in $TLSObs.results) {
                                        if ($r.status -eq "VALID") {
                                            $lines += "$($r.destination.PadRight(18)) TLS valid"
                                        } else {
                                            $lines += "$($r.destination.PadRight(18)) TLS failed"
                                        }
                                    }
                                    $destBlock = $lines -join "`n"
                                    $ex = "At least one private address validated TLS and at least one did not."
                                    $imp = "The application may behave differently depending on which address it uses."
                                    $sum = "$destBlock`n`nThe application may behave differently depending on which address it uses.`n`nWhat to do:`nSend the detailed result to your network security team."
                                    return [PSCustomObject]@{
                                        Scenario    = "PRIVATE_TLS_PARTIAL"
                                        ExitCode    = 8
                                        Title       = "TLS works for only some private addresses"
                                        Explanation = $ex
                                        Impact      = $imp
                                        Summary     = $sum
                                        State       = "UNKNOWN"
                                        LikelyOwner = "SECURITY_OR_PROXY"
                                        NextAction  = "Send the detailed result to your network security team."
                                        Warnings    = @()
                                    }
                                }
                            }
                        }
                    }

                    "NONE_CONNECTED" {
                        $title = if ($TCPObs.results.Count -gt 1) { "The private addresses cannot be reached" } else { "The private address cannot be reached" }
                        $lines = @()
                        foreach ($r in $TCPObs.results) {
                            if ($TCPObs.results.Count -eq 1) {
                                $failReason = if ($r.status -eq "TIMED_OUT") { "Timed out" } else { "Connection refused" }
                                $lines += "$hostname -> $($r.destination)`nResult: $failReason"
                            } else {
                                $lines += "$($r.destination.PadRight(18)) Connection failed"
                            }
                        }
                        $destBlock = $lines -join "`n"
                        $connStatusStr = if ($TCPObs.results.Count -gt 1) { "Failed for all addresses" } else { "Failed" }
                        $ex = "The Azure service hostname resolved privately, but this workload could not establish a TCP connection to the returned address."
                        $imp = "The application cannot currently connect to the Azure service on the requested port."
                        $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      $connStatusStr`n`nWhat to do:`nSend this result to your network team."
                        return [PSCustomObject]@{
                            Scenario    = "PRIVATE_TCP_UNREACHABLE"
                            ExitCode    = 5
                            Title       = $title
                            Explanation = $ex
                            Impact      = $imp
                            Summary     = $sum
                            State       = "BROKEN"
                            LikelyOwner = "NETWORK"
                            NextAction  = "Send this result to your network team."
                            Warnings    = @()
                        }
                    }

                    "PARTIALLY_CONNECTED" {
                        $lines = @()
                        foreach ($r in $TCPObs.results) {
                            if ($r.status -eq "CONNECTED") {
                                $lines += "$($r.destination.PadRight(18)) connected in $($r.durationMs) ms"
                            } else {
                                $lines += "$($r.destination.PadRight(18)) Connection failed"
                            }
                        }
                        $destBlock = $lines -join "`n"
                        $ex = "At least one returned private address accepted the TCP connection and at least one did not."
                        $imp = "The application may behave intermittently depending on which address it uses."
                        $sum = "$destBlock`n`nThe application may work intermittently depending on which address it uses.`n`nWhat to do:`nSend this result to your network team."
                        return [PSCustomObject]@{
                            Scenario    = "PRIVATE_TCP_PARTIAL"
                            ExitCode    = 8
                            Title       = "Some private addresses cannot be reached"
                            Explanation = $ex
                            Impact      = $imp
                            Summary     = $sum
                            State       = "UNKNOWN"
                            LikelyOwner = "NETWORK"
                            NextAction  = "Send this result to your network team."
                            Warnings    = @()
                        }
                    }
                }
            }

            # Phase 2 Private DNS fallback
            $lines = @()
            foreach ($a in $AddrObs.privateIps) {
                $lines += "$hostname -> $a (private)"
            }
            $destBlock = $lines -join "`n"
            $ex = "The service name points to a private address from this workload."
            $imp = "Connection not tested yet."
            $sum = "$destBlock`n`n$ex`n`n$imp"
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_DNS_ACTIVE"
                ExitCode    = 0
                Title       = "Private DNS looks correct"
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = "UNKNOWN"
                LikelyOwner = "UNKNOWN"
                NextAction  = ""
                Warnings    = @()
            }
        }

        "PUBLIC_ONLY" {
            $lines = @()
            foreach ($a in $AddrObs.publicIps) {
                $lines += "$hostname -> $a (public)"
            }
            $destBlock = $lines -join "`n"
            $ex = "The Azure service resolved to public addresses."
            $imp = "The application will attempt to use the public Azure endpoint."
            $sum = "$destBlock`n`n$imp`n`nWhat to do:`nIf you ran AZPE inside the affected workload, send this result to your network or DNS team."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_DNS_NOT_ACTIVE"
                ExitCode    = 4
                Title       = "This workload is not using private DNS"
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = "NOT_PRIVATE"
                LikelyOwner = "DNS_OR_NETWORK"
                NextAction  = "If this test ran inside the affected workload, send this result to your network or DNS team."
                Warnings    = @()
            }
        }

        "MIXED_PRIVATE_PUBLIC" {
            $lines = @()
            foreach ($ipObs in $AddrObs.addresses) {
                $clsStr = if ($ipObs.classification -eq "PRIVATE") { "private" } else { "public" }
                $lines += "$hostname -> $($ipObs.address) ($clsStr)"
            }
            $destBlock = $lines -join "`n"
            $ex = "DNS returned a mixture of private and public IP addresses."
            $imp = "The application may use different network paths depending on which address it selects."
            $sum = "$destBlock`n`n$imp`n`nWhat to do:`nSend this result to your network or DNS team."
            return [PSCustomObject]@{
                Scenario    = "DNS_MIXED"
                ExitCode    = 8
                Title       = "DNS is returning both private and public addresses"
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = "UNKNOWN"
                LikelyOwner = "DNS_OR_NETWORK"
                NextAction  = "Send this result to your network or DNS team."
                Warnings    = @("DNS returned a mixture of private and public IP addresses.")
            }
        }

        "SPECIAL_ONLY" {
            $ex = "DNS returned special-purpose IP addresses."
            $imp = "This result cannot be used to evaluate Azure Private Endpoint connectivity."
            $sum = "$hostname`n`n$imp`n`nWhat to do:`nSend the detailed result to your network or DNS team."
            return [PSCustomObject]@{
                Scenario    = "SPECIAL_ONLY"
                ExitCode    = 8
                Title       = "DNS returned an unexpected address"
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = "UNKNOWN"
                LikelyOwner = "DNS_OR_NETWORK"
                NextAction  = "Send the detailed result to your network or DNS team."
                Warnings    = @()
            }
        }

        default {
            $ex = "DNS returned an ambiguous response."
            $imp = "This result cannot be used to evaluate Azure Private Endpoint connectivity."
            $sum = "$hostname`n`nWhat to do:`nSend this result to your network or DNS team."
            return [PSCustomObject]@{
                Scenario    = "DNS_MIXED"
                ExitCode    = 8
                Title       = "DNS result is inconclusive"
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = "UNKNOWN"
                LikelyOwner = "DNS_OR_NETWORK"
                NextAction  = "Send this result to your network or DNS team."
                Warnings    = @()
            }
        }
    }
}

function Build-AzpeHttpRespondedEvaluation {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Target,
        [PSCustomObject[]]$Results
    )

    $hostname = $Target.Hostname
    $res = $Results[0]
    $cat = $res.responseCategory

    $lines = @()
    foreach ($r in $Results) {
        $lines += "$hostname -> $($r.destination)`nHTTP $($r.statusCode) $($r.statusText)"
    }
    $destBlock = $lines -join "`n`n"

    $title = "The Azure service responded"
    $state = "WORKING"

    switch ($cat) {
        "SUCCESS" {
            $serviceLine = "Responded successfully"
            $ex = "The private network and HTTPS path look correct. The Azure service returned a successful response."
            $imp = "End-to-end network and HTTPS transport are working."
            $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   $serviceLine`n`nThe private network and HTTPS path look correct."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_HTTP_RESPONDED"
                ExitCode    = 0
                Title       = $title
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = $state
                LikelyOwner = "UNKNOWN"
                NextAction  = ""
                Warnings    = @()
            }
        }

        "AUTHENTICATION_REQUIRED" {
            $serviceLine = "Authentication required"
            $ex = "The private connection is working. The Azure service responded and requires authentication."
            $imp = "Network and HTTPS transport are working. The application may be missing or sending invalid credentials."
            $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   $serviceLine`n`nThe private connection is working. The service requires authentication.`n`nWhat to do:`nIf the application still fails, check how it obtains and sends its Azure credentials."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_HTTP_AUTH_REQUIRED"
                ExitCode    = 0
                Title       = $title
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = $state
                LikelyOwner = "APPLICATION_OR_IDENTITY"
                NextAction  = "If the application still fails, check how it obtains and sends its Azure credentials."
                Warnings    = @()
            }
        }

        "ACCESS_DENIED" {
            $serviceLine = "Access denied"
            $ex = "The private connection is working. The Azure service denied this unauthenticated request."
            $imp = "Network and HTTPS transport are working. The application may require an authorized identity or RBAC role."
            $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   $serviceLine`n`nThe private connection is working. The service denied this unauthenticated request.`n`nWhat to do:`nIf the application still fails, check its identity and Azure permissions."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_HTTP_ACCESS_DENIED"
                ExitCode    = 0
                Title       = $title
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = $state
                LikelyOwner = "APPLICATION_OR_IDENTITY"
                NextAction  = "If the application still fails, check its identity and Azure permissions."
                Warnings    = @()
            }
        }

        "NOT_FOUND" {
            $serviceLine = "Requested path not found"
            $ex = "The private connection is working. The Azure service responded that the requested path was not found."
            $imp = "Network and HTTPS transport are working."
            $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   $serviceLine`n`nThe private connection is working. The requested path was not found."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_HTTP_NOT_FOUND"
                ExitCode    = 0
                Title       = $title
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = $state
                LikelyOwner = "APPLICATION"
                NextAction  = ""
                Warnings    = @()
            }
        }

        "THROTTLED" {
            $serviceLine = "Request throttled"
            $ex = "The private connection is working. The Azure service is currently throttling requests."
            $imp = "Network and HTTPS transport are working. Service rate limits are active."
            $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   $serviceLine`n`nThe private connection is working. The service is currently throttling requests.`n`nWhat to do:`nCheck the application retry behavior and service limits."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_HTTP_THROTTLED"
                ExitCode    = 0
                Title       = $title
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = $state
                LikelyOwner = "APPLICATION_OR_SERVICE"
                NextAction  = "Check the application retry behavior and service limits."
                Warnings    = @()
            }
        }

        default {
            $serviceLine = "Responded (HTTP $($res.statusCode))"
            $ex = "The private connection is working. The Azure service returned an HTTP response."
            $imp = "Network and HTTPS transport are working."
            $sum = "$destBlock`n`nPrivate DNS     Looks correct`nConnection      Working`nTLS             Valid`nAzure service   $serviceLine`n`nThe private connection is working."
            return [PSCustomObject]@{
                Scenario    = "PRIVATE_HTTP_RESPONDED"
                ExitCode    = 0
                Title       = $title
                Explanation = $ex
                Impact      = $imp
                Summary     = $sum
                State       = $state
                LikelyOwner = "APPLICATION_OR_SERVICE"
                NextAction  = ""
                Warnings    = @()
            }
        }
    }
}
