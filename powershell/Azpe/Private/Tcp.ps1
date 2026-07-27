# Private/Tcp.ps1
# Direct TCP connectivity probing for captured IP addresses for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Test-AzpeTcpConnectivity {
    [CmdletBinding()]
    param (
        [string]$Hostname,
        [int]$Port = 443,
        [string[]]$PrivateIPs,
        [PSCustomObject]$Capability,
        [int]$TimeoutSeconds = 5
    )

    if ($null -eq $PrivateIPs -or $PrivateIPs.Count -eq 0) {
        return [PSCustomObject]@{
            status          = "SKIPPED"
            aggregateStatus = "NOT_ATTEMPTED"
            port            = $Port
            durationMs      = 0
            results         = @()
            note            = "TCP connectivity probe not performed"
        }
    }

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $connectedCount = 0
    $failedCount = 0

    foreach ($ip in $PrivateIPs) {
        # Format destination (IPv6 uses bracketed notation with port)
        $dest = if ($ip.Contains(':')) { "[$ip]:$Port" } else { "$ip`:$Port" }
        $swIp = [System.Diagnostics.Stopwatch]::StartNew()

        $isSuccess = $false
        $errCat = ""
        $errMsg = ""
        $statusStr = "ERROR"

        if ($Capability.HasTestNetConnection) {
            try {
                $tnc = Test-NetConnection -ComputerName $ip -Port $Port -InformationLevel Detailed -WarningAction SilentlyContinue
                if ($tnc -and $tnc.TcpTestSucceeded) {
                    $isSuccess = $true
                    $statusStr = "CONNECTED"
                } else {
                    $statusStr = "TIMED_OUT"
                    $errCat = "TIMEOUT"
                    $errMsg = "TCP connection to $dest timed out"
                }
            } catch {
                $statusStr = "CONNECTION_REFUSED"
                $errCat = "CONNECTION_REFUSED"
                $errMsg = $_.Exception.Message
            }
        } else {
            # Sockets TcpClient fallback
            try {
                $client = [System.Net.Sockets.TcpClient]::new()
                $asyncResult = $client.BeginConnect($ip, $Port, $null, $null)
                $waitResult = $asyncResult.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSeconds), $false)

                if ($waitResult -and $client.Connected) {
                    $client.EndConnect($asyncResult)
                    $isSuccess = $true
                    $statusStr = "CONNECTED"
                } else {
                    $statusStr = "TIMED_OUT"
                    $errCat = "TIMEOUT"
                    $errMsg = "TCP connection to $dest timed out"
                }
                $client.Close()
            } catch {
                $errStr = $_.Exception.Message
                if ($errStr -match 'refused') {
                    $statusStr = "CONNECTION_REFUSED"
                    $errCategory = "CONNECTION_REFUSED"
                } elseif ($errStr -match 'unreachable') {
                    $statusStr = "UNREACHABLE"
                    $errCategory = "UNREACHABLE"
                } else {
                    $statusStr = "ERROR"
                    $errCategory = "GENERIC_ERROR"
                }
                $errMsg = $errStr
            }
        }

        $swIp.Stop()

        if ($isSuccess) {
            $connectedCount++
        } else {
            $failedCount++
        }

        $results.Add([PSCustomObject]@{
            address       = $ip
            destination   = $dest
            port          = $Port
            status        = $statusStr
            durationMs    = $swIp.ElapsedMilliseconds
            errorCategory = $errCat
            errorMessage  = $errMsg
        })
    }

    $swTotal.Stop()

    $aggStatus = "NONE_CONNECTED"
    $topStatus = "FAILED"

    if ($connectedCount -eq $PrivateIPs.Count) {
        $aggStatus = "ALL_CONNECTED"
        $topStatus = "SUCCESS"
    } elseif ($connectedCount -gt 0 -and $failedCount -gt 0) {
        $aggStatus = "PARTIALLY_CONNECTED"
        $topStatus = "PARTIAL"
    }

    return [PSCustomObject]@{
        status          = $topStatus
        aggregateStatus = $aggStatus
        port            = $Port
        durationMs      = $swTotal.ElapsedMilliseconds
        results         = $results.ToArray()
    }
}
