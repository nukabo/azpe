package cli

// Exit codes for AZPE CLI executions.
const (
	// ExitSuccess indicates the operation completed successfully (0).
	ExitSuccess = 0

	// ExitBrokenAssessment indicates probe assessment is broken or an assertion failed (1).
	ExitBrokenAssessment = 1

	// ExitUsageOrTargetError indicates invalid command-line usage or malformed target (2).
	ExitUsageOrTargetError = 2

	// ExitDNSFailure indicates a DNS resolution failure (3).
	ExitDNSFailure = 3

	// ExitNotPrivate indicates a public path was detected when a private path was required (4).
	ExitNotPrivate = 4

	// ExitTCPFailure indicates a TCP connection failure (5).
	ExitTCPFailure = 5

	// ExitTLSFailure indicates a TLS handshake or verification failure (6).
	ExitTLSFailure = 6

	// ExitHTTPFailure indicates an HTTP or service-level failure (7).
	ExitHTTPFailure = 7

	// ExitInconclusive indicates an incomplete or inconclusive probe (8).
	ExitInconclusive = 8

	// ExitInternalError indicates an unexpected internal tool error (10).
	ExitInternalError = 10
)
