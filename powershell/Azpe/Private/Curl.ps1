# Private/Curl.ps1
# Windows curl.exe discovery, direct-IP --resolve execution, and HTTP response parsing for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Invoke-AzpeCurlHttpsProbe {
    [CmdletBinding()]
    param (
        [string]$Hostname,
        [int]$Port = 443,
        [string]$Scheme = "https",
        [string]$PathAndQuery = "/",
        [string[]]$ConnectedIPs,
        [PSCustomObject]$Capability,
        [int]$TimeoutSeconds = 5,
        [switch]$NoHttp
    )

    if ($null -eq $ConnectedIPs -or $ConnectedIPs.Count -eq 0 -or -not $Capability.HasCurl) {
        return [PSCustomObject]@{
            TLSObservation  = [PSCustomObject]@{
                status          = "SKIPPED"
                aggregateStatus = "NOT_ATTEMPTED"
                serverName      = $Hostname
                durationMs      = 0
                results         = @()
                note            = "TLS probe not performed"
            }
            HTTPObservation = [PSCustomObject]@{
                status          = "SKIPPED"
                aggregateStatus = "NOT_ATTEMPTED"
                method          = "GET"
                path            = $PathAndQuery
                durationMs      = 0
                results         = @()
                note            = "HTTP probe not performed"
            }
        }
    }

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()

    $tlsResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $httpResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    $tlsValidCount = 0
    $tlsFailedCount = 0

    $httpRespondedCount = 0
    $httpFailedCount = 0

    # Determine null device path (NUL on Windows, /dev/null on Unix)
    $nullDevice = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { "NUL" } else { "/dev/null" }

    $targetUrl = "$Scheme`://$Hostname`:$Port$PathAndQuery"
    $redactedPath = Redact-AzpeQueryValues -PathAndQuery $PathAndQuery

    foreach ($ip in $ConnectedIPs) {
        # Format destination and resolve string
        $dest = if ($ip.Contains(':')) { "[$ip]:$Port" } else { "$ip`:$Port" }
        $resolveEntry = if ($ip.Contains(':')) { "${Hostname}:${Port}:[$ip]" } else { "${Hostname}:${Port}:${ip}" }

        # Construct curl argument array (No shell command string concatenation!)
        $curlArgs = @(
            "--silent",
            "--show-error",
            "--output", $nullDevice,
            "--write-out", "%{http_code}\n%{time_total}\n%{remote_ip}\n%{ssl_verify_result}",
            "--connect-timeout", $TimeoutSeconds.ToString(),
            "--max-time", $TimeoutSeconds.ToString(),
            "--noproxy", "*",
            "--max-redirs", "0",
            "--resolve", $resolveEntry,
            "--",
            $targetUrl
        )

        $swIp = [System.Diagnostics.Stopwatch]::StartNew()

        $curlExitCode = -1
        $curlStdout = ""
        $curlStderr = ""

        try {
            # Execute curl.exe directly using array arguments
            $pinfo = [System.Diagnostics.ProcessStartInfo]::new()
            $pinfo.FileName = $Capability.CurlPath
            $pinfo.UseShellExecute = $false
            $pinfo.RedirectStandardOutput = $true
            $pinfo.RedirectStandardError = $true
            $pinfo.CreateNoWindow = $true

            foreach ($arg in $curlArgs) {
                $pinfo.ArgumentList.Add($arg)
            }

            $proc = [System.Diagnostics.Process]::Start($pinfo)
            $curlStdout = $proc.StandardOutput.ReadToEnd()
            $curlStderr = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit()
            $curlExitCode = $proc.ExitCode
        } catch {
            $curlExitCode = 99
            $curlStderr = $_.Exception.Message
        }

        $swIp.Stop()

        # Parse curl stdout write-out format
        $httpCode = 0
        $timeTotalSec = 0.0
        $remoteIp = ""
        $sslVerifyResult = -1

        if (-not [string]::IsNullOrEmpty($curlStdout)) {
            $lines = $curlStdout.Trim().Split("`n")
            if ($lines.Count -ge 1) { [int]::TryParse($lines[0].Trim(), [ref]$httpCode) | Out-Null }
            if ($lines.Count -ge 2) { [double]::TryParse($lines[1].Trim(), [ref]$timeTotalSec) | Out-Null }
            if ($lines.Count -ge 3) { $remoteIp = $lines[2].Trim() }
            if ($lines.Count -ge 4) { [int]::TryParse($lines[3].Trim(), [ref]$sslVerifyResult) | Out-Null }
        }

        # Classify TLS and HTTP observation for this address
        $tlsStatusStr = "ERROR"
        $tlsErrCat = ""
        $tlsErrMsg = ""
        $bTrue = $true
        $bFalse = $false

        $httpStatusStr = "ERROR"
        $httpErrCat = ""
        $httpErrMsg = ""

        if ($curlExitCode -eq 0 -or $httpCode -gt 0) {
            # TLS handshake succeeded
            $tlsStatusStr = "VALID"
            $tlsValidCount++

            # HTTP response received
            $httpStatusStr = "RESPONDED"
            $httpRespondedCount++

            $statusText = Get-AzpeHttpStatusText -Code $httpCode
            $cat = Categorize-AzpeHttpStatusCode -Code $httpCode

            $httpResults.Add([PSCustomObject]@{
                address          = $ip
                destination      = $dest
                serverName       = $Hostname
                host             = $Hostname
                method           = "GET"
                requestUri       = $redactedPath
                status           = "RESPONDED"
                statusCode       = $httpCode
                statusText       = $statusText
                responseCategory = $cat
                durationMs       = $swIp.ElapsedMilliseconds
                redirectFollowed = $false
            })

            $tlsResults.Add([PSCustomObject]@{
                address            = $ip
                destination        = $dest
                port               = $Port
                serverName         = $Hostname
                status             = "VALID"
                hostnameValid      = $true
                certificateTrusted = $true
                durationMs         = $swIp.ElapsedMilliseconds
            })
        } else {
            # Categorize curl exit errors
            $tlsFailedCount++
            $httpFailedCount++

            $errStr = $curlStderr.Trim()

            switch ($curlExitCode) {
                28 { # Timeout
                    $tlsStatusStr = "HANDSHAKE_TIMEOUT"
                    $tlsErrCat = "TIMEOUT"
                    $tlsErrMsg = "TLS handshake timed out"

                    $httpStatusStr = "TIMEOUT"
                    $httpErrCat = "TIMEOUT"
                    $httpErrMsg = "HTTP request timed out"
                }
                35 { # Handshake failed
                    $tlsStatusStr = "HANDSHAKE_FAILED"
                    $tlsErrCat = "HANDSHAKE_FAILED"
                    $tlsErrMsg = if ($errStr) { $errStr } else { "TLS handshake failed" }

                    $httpStatusStr = "TLS_FAILED"
                    $httpErrCat = "HANDSHAKE_FAILED"
                    $httpErrMsg = $tlsErrMsg
                }
                51 { # Hostname mismatch
                    $tlsStatusStr = "HOSTNAME_MISMATCH"
                    $tlsErrCat = "HOSTNAME_MISMATCH"
                    $tlsErrMsg = "TLS certificate hostname mismatch"

                    $httpStatusStr = "TLS_FAILED"
                    $httpErrCat = "HOSTNAME_MISMATCH"
                    $httpErrMsg = $tlsErrMsg
                }
                60 { # Peer certificate cannot be authenticated (untrusted)
                    $tlsStatusStr = "UNTRUSTED_CERTIFICATE"
                    $tlsErrCat = "UNTRUSTED_CERTIFICATE"
                    $tlsErrMsg = "Certificate is not trusted by system trust store"

                    $httpStatusStr = "TLS_FAILED"
                    $httpErrCat = "UNTRUSTED_CERTIFICATE"
                    $httpErrMsg = $tlsErrMsg
                }
                default {
                    if ($errStr -match 'certificate' -or $errStr -match 'SSL' -or $errStr -match 'TLS') {
                        if ($errStr -match 'match') {
                            $tlsStatusStr = "HOSTNAME_MISMATCH"
                            $tlsErrCat = "HOSTNAME_MISMATCH"
                        } elseif ($errStr -match 'expire') {
                            $tlsStatusStr = "EXPIRED_CERTIFICATE"
                            $tlsErrCat = "EXPIRED_CERTIFICATE"
                        } else {
                            $tlsStatusStr = "UNTRUSTED_CERTIFICATE"
                            $tlsErrCat = "UNTRUSTED_CERTIFICATE"
                        }
                        $tlsErrMsg = $errStr
                        $httpStatusStr = "TLS_FAILED"
                        $httpErrCat = $tlsErrCat
                        $httpErrMsg = $tlsErrMsg
                    } else {
                        $tlsStatusStr = "HANDSHAKE_FAILED"
                        $tlsErrCat = "HANDSHAKE_FAILED"
                        $tlsErrMsg = if ($errStr) { $errStr } else { "TLS handshake failed" }

                        $httpStatusStr = "CONNECTION_FAILED"
                        $httpErrCat = "CONNECTION_FAILED"
                        $httpErrMsg = $tlsErrMsg
                    }
                }
            }

            $tlsResults.Add([PSCustomObject]@{
                address       = $ip
                destination   = $dest
                port          = $Port
                serverName    = $Hostname
                status        = $tlsStatusStr
                durationMs    = $swIp.ElapsedMilliseconds
                errorCategory = $tlsErrCat
                errorMessage  = $tlsErrMsg
            })

            $httpResults.Add([PSCustomObject]@{
                address       = $ip
                destination   = $dest
                serverName    = $Hostname
                host          = $Hostname
                method        = "GET"
                requestUri    = $redactedPath
                status        = $httpStatusStr
                durationMs    = $swIp.ElapsedMilliseconds
                errorCategory = $httpErrCat
                errorMessage  = $httpErrMsg
            })
        }
    }

    $swTotal.Stop()

    # Aggregate TLS status
    $aggTlsStatus = "NONE_VALID"
    $topTlsStatus = "FAILED"
    if ($tlsValidCount -eq $ConnectedIPs.Count) {
        $aggTlsStatus = "ALL_VALID"
        $topTlsStatus = "SUCCESS"
    } elseif ($tlsValidCount -gt 0 -and $tlsFailedCount -gt 0) {
        $aggTlsStatus = "PARTIALLY_VALID"
        $topTlsStatus = "PARTIAL"
    }

    # Aggregate HTTP status
    $aggHttpStatus = "NONE_RESPONDED"
    $topHttpStatus = "FAILED"
    if ($httpRespondedCount -eq $ConnectedIPs.Count) {
        $aggHttpStatus = "ALL_RESPONDED"
        $topHttpStatus = "SUCCESS"
    } elseif ($httpRespondedCount -gt 0 -and $httpFailedCount -gt 0) {
        $aggHttpStatus = "PARTIALLY_RESPONDED"
        $topHttpStatus = "PARTIAL"
    }

    if ($NoHttp) {
        $httpObs = [PSCustomObject]@{
            status          = "SKIPPED"
            aggregateStatus = "NOT_ATTEMPTED"
            method          = "GET"
            path            = $redactedPath
            durationMs      = 0
            results         = @()
            note            = "HTTP probing was disabled with -NoHttp"
        }
    } else {
        $httpObs = [PSCustomObject]@{
            status          = $topHttpStatus
            aggregateStatus = $aggHttpStatus
            method          = "GET"
            path            = $redactedPath
            durationMs      = $swTotal.ElapsedMilliseconds
            results         = $httpResults.ToArray()
        }
    }

    $tlsObs = [PSCustomObject]@{
        status          = $topTlsStatus
        aggregateStatus = $aggTlsStatus
        serverName      = $Hostname
        durationMs      = $swTotal.ElapsedMilliseconds
        results         = $tlsResults.ToArray()
    }

    return [PSCustomObject]@{
        TLSObservation  = $tlsObs
        HTTPObservation = $httpObs
    }
}

function Categorize-AzpeHttpStatusCode {
    [CmdletBinding()]
    param (
        [int]$Code
    )

    if ($Code -eq 200 -or ($Code -ge 201 -and $Code -le 299)) {
        return "SUCCESS"
    }
    if ($Code -eq 401) {
        return "AUTHENTICATION_REQUIRED"
    }
    if ($Code -eq 403) {
        return "ACCESS_DENIED"
    }
    if ($Code -eq 404) {
        return "NOT_FOUND"
    }
    if ($Code -eq 405) {
        return "METHOD_NOT_ALLOWED"
    }
    if ($Code -eq 409) {
        return "CONFLICT"
    }
    if ($Code -eq 429) {
        return "THROTTLED"
    }
    if ($Code -ge 500 -and $Code -le 599) {
        return "SERVER_ERROR"
    }
    if ($Code -ge 300 -and $Code -le 399) {
        return "REDIRECTION"
    }
    if ($Code -ge 400 -and $Code -le 499) {
        return "CLIENT_ERROR"
    }

    return "OTHER_RESPONSE"
}

function Get-AzpeHttpStatusText {
    [CmdletBinding()]
    param (
        [int]$Code
    )

    switch ($Code) {
        200 { return "OK" }
        201 { return "Created" }
        202 { return "Accepted" }
        204 { return "No Content" }
        301 { return "Moved Permanently" }
        302 { return "Found" }
        307 { return "Temporary Redirect" }
        308 { return "Permanent Redirect" }
        400 { return "Bad Request" }
        401 { return "Unauthorized" }
        403 { return "Forbidden" }
        404 { return "Not Found" }
        405 { return "Method Not Allowed" }
        409 { return "Conflict" }
        429 { return "Too Many Requests" }
        500 { return "Internal Server Error" }
        502 { return "Bad Gateway" }
        503 { return "Service Unavailable" }
        504 { return "Gateway Timeout" }
        default { return "HTTP $Code" }
    }
}
