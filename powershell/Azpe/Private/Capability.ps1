# Private/Capability.ps1
# Environment and capability detection for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Get-AzpeCapability {
    [CmdletBinding()]
    param ()

    $psVer = "Unknown"
    if ($PSVersionTable -and $PSVersionTable.PSVersion) {
        $psVer = $PSVersionTable.PSVersion.ToString()
    }

    $editionVal = "Unknown"
    if ($PSVersionTable -and $PSVersionTable.PSEdition) {
        $editionVal = $PSVersionTable.PSEdition
    }

    $langMode = "FullLanguage"
    if ($ExecutionContext -and $ExecutionContext.SessionState -and $ExecutionContext.SessionState.LanguageMode) {
        $langMode = $ExecutionContext.SessionState.LanguageMode.ToString()
    }

    $hasResolveDns = ($null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue))
    $hasTestNetConn = ($null -ne (Get-Command Test-NetConnection -ErrorAction SilentlyContinue))

    # Locate native curl.exe executable (must be Application command type, not alias)
    $curlCmd = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $hasCurl = ($null -ne $curlCmd)
    $curlPath = ""
    $curlVer = ""

    if ($hasCurl) {
        $curlPath = $curlCmd.Source
        try {
            # Bounded output from curl.exe --version
            $verOutput = & $curlCmd.Source --version 2>&1
            if ($verOutput) {
                $firstLine = $verOutput[0]
                if ($firstLine -match 'curl\s+([0-9]+\.[0-9]+\.[0-9]+)') {
                    $curlVer = $Matches[1]
                } else {
                    $curlVer = $firstLine
                }
            }
        } catch {
            $curlVer = "Unknown"
        }
    }

    $hasConvertToJson = ($null -ne (Get-Command ConvertTo-Json -ErrorAction SilentlyContinue))

    $dnsMethod = "UNAVAILABLE"
    if ($hasResolveDns) {
        $dnsMethod = "RESOLVE_DNS_NAME"
    } else {
        # Check if .NET DNS is available
        try {
            [void][System.Net.Dns]
            $dnsMethod = "DOTNET_DNS"
        } catch {
            $dnsMethod = "UNAVAILABLE"
        }
    }

    $tcpMethod = "UNAVAILABLE"
    if ($hasTestNetConn) {
        $tcpMethod = "TEST_NET_CONNECTION"
    } else {
        try {
            [void][System.Net.Sockets.TcpClient]
            $tcpMethod = "SOCKETS_TCP_CLIENT"
        } catch {
            $tcpMethod = "UNAVAILABLE"
        }
    }

    $tlsHttpMethod = "UNAVAILABLE"
    if ($hasCurl) {
        $tlsHttpMethod = "CURL_EXE_RESOLVE"
    }

    return [PSCustomObject]@{
        EngineName        = "POWERSHELL_COMPAT"
        EngineVersion     = "0.2.0-rc.1"
        PowerShellVersion = $psVer
        PowerShellEdition = $editionVal
        LanguageMode      = $langMode
        HasResolveDnsName = $hasResolveDns
        HasTestNetConnection = $hasTestNetConn
        HasCurl           = $hasCurl
        CurlPath          = $curlPath
        CurlVersion       = $curlVer
        HasConvertToJson  = $hasConvertToJson
        DnsMethod         = $dnsMethod
        TcpMethod         = $tcpMethod
        TlsHttpMethod     = $tlsHttpMethod
    }
}
