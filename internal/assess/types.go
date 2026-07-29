package assess

// AssessmentScenario identifies the human-facing UX scenario.
type AssessmentScenario string

const (
	ScenarioPrivateDNSActive    AssessmentScenario = "PRIVATE_DNS_ACTIVE"
	ScenarioPrivateDNSNotActive AssessmentScenario = "PRIVATE_DNS_NOT_ACTIVE"
	ScenarioDNSLookupFailed     AssessmentScenario = "DNS_LOOKUP_FAILED"
	ScenarioDNSMixed            AssessmentScenario = "DNS_MIXED"
	ScenarioIPLiteral           AssessmentScenario = "IP_LITERAL"
	ScenarioUnrecognizedTarget  AssessmentScenario = "UNRECOGNIZED_TARGET"
	ScenarioPossibleAzure       AssessmentScenario = "POSSIBLE_AZURE"
	ScenarioSpecialOnly         AssessmentScenario = "SPECIAL_ONLY"

	// Phase 3 TCP Scenarios
	ScenarioPrivateTCPReachable   AssessmentScenario = "PRIVATE_TCP_REACHABLE"
	ScenarioPrivateTCPUnreachable AssessmentScenario = "PRIVATE_TCP_UNREACHABLE"
	ScenarioPrivateTCPPartial     AssessmentScenario = "PRIVATE_TCP_PARTIAL"

	// Phase 4 TLS Scenarios
	ScenarioPrivateTLSValid            AssessmentScenario = "PRIVATE_TLS_VALID"
	ScenarioPrivateTLSFailed           AssessmentScenario = "PRIVATE_TLS_FAILED"
	ScenarioPrivateTLSPartial          AssessmentScenario = "PRIVATE_TLS_PARTIAL"
	ScenarioPrivateTLSHostnameMismatch AssessmentScenario = "PRIVATE_TLS_HOSTNAME_MISMATCH"
	ScenarioPrivateTLSUntrusted        AssessmentScenario = "PRIVATE_TLS_UNTRUSTED"
	ScenarioPrivateTLSExpired          AssessmentScenario = "PRIVATE_TLS_EXPIRED"
	ScenarioPrivateTLSTimeout          AssessmentScenario = "PRIVATE_TLS_TIMEOUT"

	// Phase 5 HTTP Scenarios
	ScenarioPrivateHTTPResponded        AssessmentScenario = "PRIVATE_HTTP_RESPONDED"
	ScenarioPrivateHTTPAuthRequired     AssessmentScenario = "PRIVATE_HTTP_AUTH_REQUIRED"
	ScenarioPrivateHTTPAccessDenied     AssessmentScenario = "PRIVATE_HTTP_ACCESS_DENIED"
	ScenarioPrivateHTTPNotFound         AssessmentScenario = "PRIVATE_HTTP_NOT_FOUND"
	ScenarioPrivateHTTPMethodNotAllowed AssessmentScenario = "PRIVATE_HTTP_METHOD_NOT_ALLOWED"
	ScenarioPrivateHTTPThrottled        AssessmentScenario = "PRIVATE_HTTP_THROTTLED"
	ScenarioPrivateHTTPServerError      AssessmentScenario = "PRIVATE_HTTP_SERVER_ERROR"
	ScenarioPrivateHTTPRedirect         AssessmentScenario = "PRIVATE_HTTP_REDIRECT"
	ScenarioPrivateHTTPFailed           AssessmentScenario = "PRIVATE_HTTP_FAILED"
	ScenarioPrivateHTTPTimeout          AssessmentScenario = "PRIVATE_HTTP_TIMEOUT"
	ScenarioPrivateHTTPMalformed        AssessmentScenario = "PRIVATE_HTTP_MALFORMED"
	ScenarioPrivateHTTPTransportFailed  AssessmentScenario = "PRIVATE_HTTP_TRANSPORT_FAILED"
	ScenarioPrivateHTTPPartial          AssessmentScenario = "PRIVATE_HTTP_PARTIAL"
)

// Evaluation represents the structured outcome of the assessment decision engine.
type Evaluation struct {
	Scenario    AssessmentScenario
	ExitCode    int
	Title       string
	Explanation string
	Impact      string
	Summary     string
	State       AssessmentState
	LikelyOwner LikelyOwner
	NextAction  string
	Warnings    []string
}

// MinimalTCPObservation contains fields required for Evaluation without importing model package.
type MinimalTCPObservation interface {
	GetAggregateStatus() AggregateTCPStatus
	GetResults() []MinimalTCPResultItem
}

// MinimalTCPResultItem interface for per-address TCP result details.
type MinimalTCPResultItem interface {
	GetAddress() string
	GetDestination() string
	GetPort() int
	GetStatus() TCPAddressStatus
	GetDurationMs() int64
	GetErrorCategory() string
	GetError() string
}

// MinimalTLSObservation contains fields required for Evaluation without importing model package.
type MinimalTLSObservation interface {
	GetAggregateStatus() AggregateTLSStatus
	GetServerName() string
	GetResults() []MinimalTLSResultItem
}

// MinimalTLSResultItem interface for per-address TLS result details.
type MinimalTLSResultItem interface {
	GetAddress() string
	GetDestination() string
	GetPort() int
	GetServerName() string
	GetStatus() TLSAddressStatus
	GetStage() string
	GetDurationMs() int64
	GetTLSVersion() string
	GetCipherSuite() string
	GetErrorCategory() string
	GetError() string
}

// MinimalHTTPObservation contains fields required for Evaluation without importing model package.
type MinimalHTTPObservation interface {
	GetAggregateStatus() AggregateHTTPStatus
	GetMethod() string
	GetPath() string
	GetResults() []MinimalHTTPResultItem
}

// MinimalHTTPResultItem interface for per-address HTTP result details.
type MinimalHTTPResultItem interface {
	GetAddress() string
	GetDestination() string
	GetPort() int
	GetServerName() string
	GetHost() string
	GetMethod() string
	GetRequestURI() string
	GetStatus() HTTPAddressStatus
	GetStatusCode() int
	GetStatusText() string
	GetResponseCategory() HTTPResponseCategory
	GetDurationMs() int64
	GetRedirectFollowed() bool
	GetErrorCategory() string
	GetError() string
}
