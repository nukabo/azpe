# Private/Dns.ps1
# Operating system DNS resolution and IP address classification for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Classify-AzpeIpAddress {
    [CmdletBinding()]
    param (
        [System.Net.IPAddress]$IP
    )

    if ($null -eq $IP) {
        return "UNKNOWN"
    }

    $bytes = $IP.GetAddressBytes()

    if ($IP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b0 = [int]$bytes[0]
        $b1 = [int]$bytes[1]
        $b2 = [int]$bytes[2]

        # UNSPECIFIED: 0.0.0.0
        if ($b0 -eq 0 -and $b1 -eq 0 -and $b2 -eq 0 -and $bytes[3] -eq 0) {
            return "UNSPECIFIED"
        }

        # LOOPBACK: 127.0.0.0/8
        if ($b0 -eq 127) {
            return "LOOPBACK"
        }

        # MULTICAST: 224.0.0.0/4 (224-239)
        if ($b0 -ge 224 -and $b0 -le 239) {
            return "MULTICAST"
        }

        # LINK_LOCAL: 169.254.0.0/16
        if ($b0 -eq 169 -and $b1 -eq 254) {
            return "LINK_LOCAL"
        }

        # DOCUMENTATION: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        if (($b0 -eq 192 -and $b1 -eq 0 -and $b2 -eq 2) -or
            ($b0 -eq 198 -and $b1 -eq 51 -and $b2 -eq 100) -or
            ($b0 -eq 203 -and $b1 -eq 0 -and $b2 -eq 113)) {
            return "DOCUMENTATION"
        }

        # BENCHMARK: 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
        if ($b0 -eq 198 -and ($b1 -eq 18 -or $b1 -eq 19)) {
            return "BENCHMARK"
        }

        # RESERVED: 240.0.0.0/4, 100.64.0.0/10 (CGNAT), 192.0.0.0/24, 192.88.99.0/24
        if (($b0 -ge 240) -or
            ($b0 -eq 100 -and $b1 -ge 64 -and $b1 -le 127) -or
            ($b0 -eq 192 -and $b1 -eq 0 -and $b2 -eq 0) -or
            ($b0 -eq 192 -and $b1 -eq 88 -and $b2 -eq 99)) {
            return "RESERVED"
        }

        # PRIVATE: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
        if ($b0 -eq 10) {
            return "PRIVATE"
        }
        if ($b0 -eq 172 -and $b1 -ge 16 -and $b1 -le 31) {
            return "PRIVATE"
        }
        if ($b0 -eq 192 -and $b1 -eq 168) {
            return "PRIVATE"
        }

        return "PUBLIC"
    }

    if ($IP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        # IPv6 Loopback: ::1
        if ($IP.Equals([System.Net.IPAddress]::IPv6Loopback)) {
            return "LOOPBACK"
        }
        # IPv6 Unspecified: ::
        if ($IP.Equals([System.Net.IPAddress]::IPv6Any)) {
            return "UNSPECIFIED"
        }
        # IPv6 Multicast: ff00::/8
        if ($bytes[0] -eq 0xff) {
            return "MULTICAST"
        }
        # IPv6 Link-Local: fe80::/10 (fe80-febf)
        if ($bytes[0] -eq 0xfe -and ($bytes[1] -band 0xc0) -eq 0x80) {
            return "LINK_LOCAL"
        }
        # IPv6 Documentation: 2001:db8::/32
        if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8) {
            return "DOCUMENTATION"
        }
        # IPv6 Unique Local Address / Private: fc00::/7 (fc00 - fdff, RFC 4193)
        if (($bytes[0] -band 0xfe) -eq 0xfc) {
            return "PRIVATE"
        }

        return "PUBLIC"
    }

    return "UNKNOWN"
}

function Calculate-AzpeAggregateClassification {
    [CmdletBinding()]
    param (
        [string[]]$Classifications
    )

    if ($null -eq $Classifications -or $Classifications.Count -eq 0) {
        return "NONE"
    }

    $hasPrivate = $false
    $hasPublic = $false
    $hasSpecial = $false

    foreach ($c in $Classifications) {
        switch ($c) {
            "PRIVATE" { $hasPrivate = $true }
            "PUBLIC"  { $hasPublic = $true }
            default   { $hasSpecial = $true }
        }
    }

    if ($hasPrivate -and -not $hasPublic -and -not $hasSpecial) {
        return "PRIVATE_ONLY"
    }
    if ($hasPublic -and -not $hasPrivate -and -not $hasSpecial) {
        return "PUBLIC_ONLY"
    }
    if ($hasPrivate -and $hasPublic) {
        return "MIXED_PRIVATE_PUBLIC"
    }
    if ($hasSpecial -and -not $hasPrivate -and -not $hasPublic) {
        return "SPECIAL_ONLY"
    }

    return "MIXED_PRIVATE_PUBLIC"
}

function Resolve-AzpeHost {
    [CmdletBinding()]
    param (
        [string]$Hostname,
        [PSCustomObject]$Capability,
        [int]$TimeoutSeconds = 5
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Check if Hostname is an IP literal
    [System.Net.IPAddress]$literalIp = $null
    if ([System.Net.IPAddress]::TryParse($Hostname.Trim('[', ']'), [ref]$literalIp)) {
        $sw.Stop()
        $cls = Classify-AzpeIpAddress -IP $literalIp
        $ver = if ($literalIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "IPv4" } else { "IPv6" }
        $aggCls = Calculate-AzpeAggregateClassification -Classifications @($cls)

        $ipObs = [PSCustomObject]@{
            address        = $literalIp.IPAddressToString
            version        = $ver
            classification = $cls
        }

        $dnsObs = [PSCustomObject]@{
            status                  = "NOT_APPLICABLE"
            resolverMode            = "GO_BUILTIN"
            queryHostname           = $Hostname
            durationMs              = $sw.ElapsedMilliseconds
            addresses               = @($ipObs)
            aggregateClassification = $aggCls
            isIpLiteral             = $true
            note                    = "Target is an IP literal. No hostname DNS resolution occurred."
        }

        $addrObs = [PSCustomObject]@{
            classification = $aggCls
            addresses      = @($ipObs)
            privateIps     = if ($cls -eq "PRIVATE") { @($literalIp.IPAddressToString) } else { @() }
            publicIps      = if ($cls -eq "PUBLIC") { @($literalIp.IPAddressToString) } else { @() }
            note           = ""
        }

        return [PSCustomObject]@{
            DNSObservation  = $dnsObs
            AddrObservation = $addrObs
        }
    }

    # Perform DNS resolution
    $rawIpList = [System.Collections.Generic.List[System.Net.IPAddress]]::new()
    $dnsStatus = "SUCCESS"
    $errCategory = ""
    $errMsg = ""

    if ($Capability.HasResolveDnsName) {
        try {
            $dnsRecords = Resolve-DnsName -Name $Hostname -Type A_AAAA -ErrorAction Stop
            foreach ($rec in $dnsRecords) {
                if ($rec.IPAddress) {
                    [System.Net.IPAddress]$parsed = $null
                    if ([System.Net.IPAddress]::TryParse($rec.IPAddress, [ref]$parsed)) {
                        $rawIpList.Add($parsed)
                    }
                }
            }
            if ($rawIpList.Count -eq 0) {
                $dnsStatus = "NOT_FOUND"
                $errCategory = "NOT_FOUND"
                $errMsg = "DNS resolution returned no A or AAAA records for $Hostname"
            }
        } catch {
            $errStr = $_.Exception.Message
            $errMsg = $errStr
            if ($errStr -match 'DNS name does not exist' -or $errStr -match 'not found' -or $errStr -match 'ResourceRecordNotFound') {
                $dnsStatus = "NOT_FOUND"
                $errCategory = "NOT_FOUND"
            } elseif ($errStr -match 'timed out' -or $errStr -match 'timeout') {
                $dnsStatus = "TIMEOUT"
                $errCategory = "TIMEOUT"
            } else {
                $dnsStatus = "FAILURE"
                $errCategory = "GENERIC_ERROR"
            }
        }
    } else {
        # .NET Fallback
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($Hostname)
            foreach ($a in $addrs) {
                $rawIpList.Add($a)
            }
            if ($rawIpList.Count -eq 0) {
                $dnsStatus = "NOT_FOUND"
                $errCategory = "NOT_FOUND"
                $errMsg = "DNS resolution returned no addresses for $Hostname"
            }
        } catch {
            $errStr = $_.Exception.Message
            $errMsg = $errStr
            if ($errStr -match 'No such host' -or $errStr -match 'not known') {
                $dnsStatus = "NOT_FOUND"
                $errCategory = "NOT_FOUND"
            } else {
                $dnsStatus = "FAILURE"
                $errCategory = "GENERIC_ERROR"
            }
        }
    }

    $sw.Stop()

    if ($dnsStatus -ne "SUCCESS") {
        $dnsObs = [PSCustomObject]@{
            status                  = $dnsStatus
            resolverMode            = "GO_BUILTIN"
            queryHostname           = $Hostname
            durationMs              = $sw.ElapsedMilliseconds
            addresses               = @()
            aggregateClassification = "NONE"
            isIpLiteral             = $false
            errorCategory           = $errCategory
            errorMessage            = $errMsg
            note                    = "DNS resolution failed"
        }
        $addrObs = [PSCustomObject]@{
            classification = "NONE"
            addresses      = @()
            privateIps     = @()
            publicIps      = @()
            note           = "No IP addresses resolved"
        }
        return [PSCustomObject]@{
            DNSObservation  = $dnsObs
            AddrObservation = $addrObs
        }
    }

    # Deduplicate and sort IP addresses deterministically
    $seenMap = [System.Collections.Generic.HashSet[string]]::new()
    $uniqueIpList = [System.Collections.Generic.List[System.Net.IPAddress]]::new()

    foreach ($ip in $rawIpList) {
        $str = $ip.IPAddressToString
        if ($seenMap.Add($str)) {
            $uniqueIpList.Add($ip)
        }
    }

    # Sort IP addresses by IP bytes comparison
    $sortedIps = $uniqueIpList | Sort-Object { $_.IPAddressToString }

    $ipObsList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $classList = [System.Collections.Generic.List[string]]::new()
    $privIps = [System.Collections.Generic.List[string]]::new()
    $pubIps = [System.Collections.Generic.List[string]]::new()

    foreach ($ip in $sortedIps) {
        $cls = Classify-AzpeIpAddress -IP $ip
        $ver = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "IPv4" } else { "IPv6" }
        $ipStr = $ip.IPAddressToString

        $classList.Add($cls)
        $ipObsList.Add([PSCustomObject]@{
            address        = $ipStr
            version        = $ver
            classification = $cls
        })

        if ($cls -eq "PRIVATE") {
            $privIps.Add($ipStr)
        } elseif ($cls -eq "PUBLIC") {
            $pubIps.Add($ipStr)
        }
    }

    $aggClass = Calculate-AzpeAggregateClassification -Classifications $classList.ToArray()

    $dnsObs = [PSCustomObject]@{
        status                  = "SUCCESS"
        resolverMode            = "GO_BUILTIN"
        queryHostname           = $Hostname
        durationMs              = $sw.ElapsedMilliseconds
        addresses               = $ipObsList.ToArray()
        aggregateClassification = $aggClass
        isIpLiteral             = $false
    }

    $addrObs = [PSCustomObject]@{
        classification = $aggClass
        addresses      = $ipObsList.ToArray()
        privateIps     = $privIps.ToArray()
        publicIps      = $pubIps.ToArray()
    }

    return [PSCustomObject]@{
        DNSObservation  = $dnsObs
        AddrObservation = $addrObs
    }
}
