package assess

// AssessmentCode represents a small, stable, typed machine code for diagnostic outcomes.
type AssessmentCode string

const (
	CodeSuccess                    AssessmentCode = "success"
	CodeDNSFailure                 AssessmentCode = "dns_failure"
	CodeDNSTimeout                 AssessmentCode = "dns_timeout"
	CodeUnexpectedPublicResolution AssessmentCode = "unexpected_public_resolution"
	CodeMixedAddressResolution     AssessmentCode = "mixed_address_resolution"
	CodeTCPTimeout                 AssessmentCode = "tcp_timeout"
	CodeTCPRefused                 AssessmentCode = "tcp_refused"
	CodeTCPFailure                 AssessmentCode = "tcp_failure"
	CodeTLSUntrusted               AssessmentCode = "tls_untrusted"
	CodeTLSHostnameMismatch        AssessmentCode = "tls_hostname_mismatch"
	CodeTLSExpired                 AssessmentCode = "tls_expired"
	CodeTLSFailure                 AssessmentCode = "tls_failure"
	CodeHTTPAuthenticationRequired AssessmentCode = "http_authentication_required"
	CodeHTTPAuthorizationDenied    AssessmentCode = "http_authorization_denied"
	CodeHTTPRateLimited            AssessmentCode = "http_rate_limited"
	CodeHTTPServiceError           AssessmentCode = "http_service_error"
	CodeHTTPRedirected             AssessmentCode = "http_redirected"
	CodeOverallTimeout             AssessmentCode = "overall_timeout"
	CodeInconclusive               AssessmentCode = "inconclusive"
)

// String returns the stable string value of the assessment code.
func (c AssessmentCode) String() string {
	return string(c)
}

// DiagnosticPhase returns the diagnostic phase associated with this code.
func (c AssessmentCode) DiagnosticPhase() string {
	switch c {
	case CodeDNSFailure, CodeDNSTimeout, CodeUnexpectedPublicResolution, CodeMixedAddressResolution:
		return "dns"
	case CodeTCPTimeout, CodeTCPRefused, CodeTCPFailure:
		return "tcp"
	case CodeTLSUntrusted, CodeTLSHostnameMismatch, CodeTLSExpired, CodeTLSFailure:
		return "tls"
	case CodeHTTPAuthenticationRequired, CodeHTTPAuthorizationDenied, CodeHTTPRateLimited, CodeHTTPServiceError, CodeHTTPRedirected:
		return "http"
	case CodeOverallTimeout:
		return "overall"
	default:
		return "assessment"
	}
}

// Severity returns the severity classification for this code ("info", "warning", "error").
func (c AssessmentCode) Severity() string {
	switch c {
	case CodeSuccess, CodeHTTPAuthenticationRequired, CodeHTTPAuthorizationDenied, CodeHTTPRedirected:
		return "info"
	case CodeMixedAddressResolution, CodeHTTPRateLimited, CodeInconclusive:
		return "warning"
	default:
		return "error"
	}
}

// HumanSummary returns a concise human-readable summary for this code.
func (c AssessmentCode) HumanSummary() string {
	switch c {
	case CodeSuccess:
		return "Diagnostic checks succeeded."
	case CodeDNSFailure:
		return "DNS resolution failed."
	case CodeDNSTimeout:
		return "DNS resolution timed out."
	case CodeUnexpectedPublicResolution:
		return "Target resolved to public IP address."
	case CodeMixedAddressResolution:
		return "Target resolved to mixed public and private IP addresses."
	case CodeTCPTimeout:
		return "TCP connection attempt timed out."
	case CodeTCPRefused:
		return "TCP connection attempt was refused."
	case CodeTCPFailure:
		return "TCP connection attempt failed."
	case CodeTLSUntrusted:
		return "TLS certificate is untrusted."
	case CodeTLSHostnameMismatch:
		return "TLS certificate hostname mismatch."
	case CodeTLSExpired:
		return "TLS certificate has expired."
	case CodeTLSFailure:
		return "TLS handshake or certificate validation failed."
	case CodeHTTPAuthenticationRequired:
		return "HTTP authentication required (401)."
	case CodeHTTPAuthorizationDenied:
		return "HTTP authorization denied (403)."
	case CodeHTTPRateLimited:
		return "HTTP requests rate limited (429)."
	case CodeHTTPServiceError:
		return "HTTP service error (5xx)."
	case CodeHTTPRedirected:
		return "HTTP request redirected (3xx)."
	case CodeOverallTimeout:
		return "Overall diagnostic probing timed out."
	case CodeInconclusive:
		return "Diagnostic outcome is inconclusive."
	default:
		return "Diagnostic assessment completed."
	}
}

// RecommendationRule returns the rule-based operator next step.
func (c AssessmentCode) RecommendationRule() string {
	switch c {
	case CodeSuccess:
		return "No action required."
	case CodeDNSFailure, CodeDNSTimeout:
		return "Verify workload DNS configuration or Private DNS zone linkage."
	case CodeUnexpectedPublicResolution, CodeMixedAddressResolution:
		return "Check Private DNS zone configuration and ensure VNet is linked."
	case CodeTCPTimeout, CodeTCPRefused, CodeTCPFailure:
		return "Inspect VNet routing, NSG rules, and Private Endpoint connection state."
	case CodeTLSUntrusted, CodeTLSHostnameMismatch, CodeTLSExpired, CodeTLSFailure:
		return "Inspect TLS certificate configuration and trust chain on responder."
	case CodeHTTPAuthenticationRequired, CodeHTTPAuthorizationDenied:
		return "Verify application identity and Azure RBAC / access policies."
	case CodeHTTPRateLimited:
		return "Implement exponential backoff and inspect service rate limits."
	case CodeHTTPServiceError:
		return "Check service health logs or contact service owner."
	case CodeHTTPRedirected:
		return "Verify whether application handles redirects to the intended destination."
	case CodeOverallTimeout:
		return "Increase timeout or check network latency."
	case CodeInconclusive:
		return "Run AZPE with --details or check network environment."
	default:
		return "Review diagnostic details."
	}
}
