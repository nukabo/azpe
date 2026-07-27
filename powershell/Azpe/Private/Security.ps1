# Private/Security.ps1
# Input sanitization, query value redaction, and string safety helpers for AZPE PowerShell Client

Set-StrictMode -Version Latest

function Redact-AzpeQueryValues {
    [CmdletBinding()]
    param (
        [string]$PathAndQuery
    )

    if ([string]::IsNullOrEmpty($PathAndQuery)) {
        return ""
    }

    $qIdx = $PathAndQuery.IndexOf('?')
    if ($qIdx -lt 0) {
        return $PathAndQuery
    }

    $basePath = $PathAndQuery.Substring(0, $qIdx)
    $queryStr = $PathAndQuery.Substring($qIdx + 1)
    if ([string]::IsNullOrEmpty($queryStr)) {
        return $PathAndQuery
    }

    $fragment = ""
    $fragIdx = $queryStr.IndexOf('#')
    if ($fragIdx -ge 0) {
        $fragment = $queryStr.Substring($fragIdx)
        $queryStr = $queryStr.Substring(0, $fragIdx)
    }

    $pairs = $queryStr.Split('&')
    $redactedPairs = [System.Collections.Generic.List[string]]::new()

    foreach ($pair in $pairs) {
        if ([string]::IsNullOrEmpty($pair)) {
            continue
        }
        $eqIdx = $pair.IndexOf('=')
        if ($eqIdx -ge 0) {
            $key = $pair.Substring(0, $eqIdx)
            $redactedPairs.Add("$key=REDACTED")
        } else {
            $redactedPairs.Add($pair)
        }
    }

    $result = $basePath + "?" + ($redactedPairs -join "&") + $fragment
    return $result
}

function Sanitize-AzpeLocation {
    [CmdletBinding()]
    param (
        [string]$Location
    )

    if ([string]::IsNullOrEmpty($Location)) {
        return ""
    }

    # Strip userinfo (user:pass@) if present in full URL
    $sanitized = $Location
    if ($sanitized -match '^(https?://)([^/@]+@)(.+)$') {
        $sanitized = $Matches[1] + $Matches[3]
    }

    return (Redact-AzpeQueryValues -PathAndQuery $sanitized)
}

function Test-AzpeSafeInput {
    [CmdletBinding()]
    param (
        [string]$RawInput
    )

    if ([string]::IsNullOrWhiteSpace($RawInput)) {
        throw "missing target"
    }

    # Reject control characters (CR, LF, NUL, TAB, etc.)
    foreach ($char in $RawInput.ToCharArray()) {
        if ([char]::IsControl($char)) {
            throw "target contains invalid control characters"
        }
    }

    # Reject URLs with embedded credentials (e.g. https://user:pass@host)
    if ($RawInput -match '://[^/]*@') {
        throw "URLs containing embedded credentials are not allowed"
    }

    return $true
}
