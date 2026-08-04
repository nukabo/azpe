package assess

import (
	"testing"

	"github.com/nukabo/azpe/internal/target"
)

type mockTCPItem struct {
	status   TCPAddressStatus
	errCat   string
	dest     string
	duration int64
	err      string
}

func (m mockTCPItem) GetAddress() string          { return "10.0.0.1" }
func (m mockTCPItem) GetDestination() string      { return m.dest }
func (m mockTCPItem) GetPort() int                { return 443 }
func (m mockTCPItem) GetStatus() TCPAddressStatus { return m.status }
func (m mockTCPItem) GetDurationMs() int64        { return m.duration }
func (m mockTCPItem) GetErrorCategory() string    { return m.errCat }
func (m mockTCPItem) GetError() string            { return m.err }

type mockTCPObs struct {
	aggStatus AggregateTCPStatus
	items     []MinimalTCPResultItem
}

func (m mockTCPObs) GetAggregateStatus() AggregateTCPStatus { return m.aggStatus }
func (m mockTCPObs) GetResults() []MinimalTCPResultItem     { return m.items }

type mockTLSItem struct {
	status   TLSAddressStatus
	errCat   string
	dest     string
	duration int64
	err      string
}

func (m mockTLSItem) GetAddress() string          { return "10.0.0.1" }
func (m mockTLSItem) GetDestination() string      { return m.dest }
func (m mockTLSItem) GetPort() int                { return 443 }
func (m mockTLSItem) GetServerName() string       { return "myvault.vault.azure.net" }
func (m mockTLSItem) GetStatus() TLSAddressStatus { return m.status }
func (m mockTLSItem) GetStage() string            { return "COMPLETE" }
func (m mockTLSItem) GetDurationMs() int64        { return m.duration }
func (m mockTLSItem) GetTLSVersion() string       { return "TLS 1.3" }
func (m mockTLSItem) GetCipherSuite() string      { return "TLS_AES_256_GCM_SHA384" }
func (m mockTLSItem) GetErrorCategory() string    { return m.errCat }
func (m mockTLSItem) GetError() string            { return m.err }

type mockTLSObs struct {
	aggStatus  AggregateTLSStatus
	serverName string
	items      []MinimalTLSResultItem
}

func (m mockTLSObs) GetAggregateStatus() AggregateTLSStatus { return m.aggStatus }
func (m mockTLSObs) GetServerName() string                  { return m.serverName }
func (m mockTLSObs) GetResults() []MinimalTLSResultItem     { return m.items }

type mockHTTPItem struct {
	status   HTTPAddressStatus
	code     int
	text     string
	cat      HTTPResponseCategory
	location string
	dest     string
	duration int64
	errCat   string
	err      string
}

func (m mockHTTPItem) GetAddress() string                        { return "10.0.0.1" }
func (m mockHTTPItem) GetDestination() string                    { return m.dest }
func (m mockHTTPItem) GetPort() int                              { return 443 }
func (m mockHTTPItem) GetServerName() string                     { return "myvault.vault.azure.net" }
func (m mockHTTPItem) GetHost() string                           { return "myvault.vault.azure.net" }
func (m mockHTTPItem) GetMethod() string                         { return "GET" }
func (m mockHTTPItem) GetRequestURI() string                     { return "/" }
func (m mockHTTPItem) GetStatus() HTTPAddressStatus              { return m.status }
func (m mockHTTPItem) GetStatusCode() int                        { return m.code }
func (m mockHTTPItem) GetStatusText() string                     { return m.text }
func (m mockHTTPItem) GetResponseCategory() HTTPResponseCategory { return m.cat }
func (m mockHTTPItem) GetDurationMs() int64                      { return m.duration }
func (m mockHTTPItem) GetRedirectFollowed() bool                 { return false }
func (m mockHTTPItem) GetLocation() string                       { return m.location }
func (m mockHTTPItem) GetErrorCategory() string                  { return m.errCat }
func (m mockHTTPItem) GetError() string                          { return m.err }

type mockHTTPObs struct {
	aggStatus AggregateHTTPStatus
	method    string
	path      string
	items     []MinimalHTTPResultItem
}

func (m mockHTTPObs) GetAggregateStatus() AggregateHTTPStatus { return m.aggStatus }
func (m mockHTTPObs) GetMethod() string                       { return m.method }
func (m mockHTTPObs) GetPath() string                         { return m.path }
func (m mockHTTPObs) GetResults() []MinimalHTTPResultItem     { return m.items }

func TestAssessmentCodes_TableDriven(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")

	tests := []struct {
		name         string
		dnsStatus    DNSStatus
		aggClass     AggregateClassification
		tcpObs       MinimalTCPObservation
		tlsObs       MinimalTLSObservation
		httpObs      MinimalHTTPObservation
		expectedCode AssessmentCode
	}{
		{
			name:         "DNS lookup failure",
			dnsStatus:    DNSStatusNotFound,
			aggClass:     AggregateNone,
			expectedCode: CodeDNSFailure,
		},
		{
			name:         "DNS lookup timeout",
			dnsStatus:    DNSStatusTimeout,
			aggClass:     AggregateNone,
			expectedCode: CodeDNSTimeout,
		},
		{
			name:         "public resolution",
			dnsStatus:    DNSStatusSuccess,
			aggClass:     AggregatePublicOnly,
			expectedCode: CodeUnexpectedPublicResolution,
		},
		{
			name:         "private resolution only (DNS active fallback when no TCP tested)",
			dnsStatus:    DNSStatusSuccess,
			aggClass:     AggregatePrivateOnly,
			expectedCode: CodeSuccess,
		},
		{
			name:         "mixed resolution",
			dnsStatus:    DNSStatusSuccess,
			aggClass:     AggregateMixedPrivatePublic,
			expectedCode: CodeMixedAddressResolution,
		},
		{
			name:      "TCP timeout",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPNoneConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrTimedOut, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeTCPTimeout,
		},
		{
			name:      "TCP refusal",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPNoneConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnectionRefused, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeTCPRefused,
		},
		{
			name:      "TCP general failure",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPNoneConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrUnreachable, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeTCPFailure,
		},
		{
			name:      "TLS hostname mismatch",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSNoneValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrHostnameMismatch, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeTLSHostnameMismatch,
		},
		{
			name:      "untrusted certificate",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSNoneValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrUntrustedCertificate, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeTLSUntrusted,
		},
		{
			name:      "expired certificate",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSNoneValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrExpiredCertificate, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeTLSExpired,
		},
		{
			name:      "HTTP 401 (Authentication required)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPAllResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrResponded, code: 401, text: "Unauthorized", cat: HTTPCatAuthenticationRequired, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeHTTPAuthenticationRequired,
		},
		{
			name:      "HTTP 403 (Authorization denied)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPAllResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrResponded, code: 403, text: "Forbidden", cat: HTTPCatAccessDenied, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeHTTPAuthorizationDenied,
		},
		{
			name:      "HTTP 3xx (Redirected)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPAllResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrResponded, code: 302, text: "Found", cat: HTTPCatRedirection, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeHTTPRedirected,
		},
		{
			name:      "HTTP 429 (Rate limited)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPAllResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrResponded, code: 429, text: "Too Many Requests", cat: HTTPCatThrottled, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeHTTPRateLimited,
		},
		{
			name:      "HTTP 500 (Service error)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPAllResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrResponded, code: 500, text: "Internal Server Error", cat: HTTPCatServerError, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeHTTPServiceError,
		},
		{
			name:      "contradictory observations (malformed HTTP response)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPNoneResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrMalformedResponse, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeInconclusive,
		},
		{
			name:      "incomplete observations (partial HTTP response)",
			dnsStatus: DNSStatusSuccess,
			aggClass:  AggregatePrivateOnly,
			tcpObs: mockTCPObs{
				aggStatus: AggregateTCPAllConnected,
				items:     []MinimalTCPResultItem{mockTCPItem{status: TCPAddrConnected, dest: "10.0.0.1:443"}},
			},
			tlsObs: mockTLSObs{
				aggStatus: AggregateTLSAllValid,
				items:     []MinimalTLSResultItem{mockTLSItem{status: TLSAddrValid, dest: "10.0.0.1:443"}},
			},
			httpObs: mockHTTPObs{
				aggStatus: AggregateHTTPPartiallyResponded,
				items:     []MinimalHTTPResultItem{mockHTTPItem{status: HTTPAddrResponded, code: 200, cat: HTTPCatSuccess, dest: "10.0.0.1:443"}},
			},
			expectedCode: CodeInconclusive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := Evaluate(tgt, tt.dnsStatus, tt.aggClass, []string{"10.0.0.1"}, []AddressClassification{AddrPrivate}, "", "", tt.tcpObs, tt.tlsObs, tt.httpObs)
			if eval.Code != tt.expectedCode {
				t.Errorf("expected code %s, got %s", tt.expectedCode, eval.Code)
			}
		})
	}
}

func TestAssessmentCode_MetadataMethods(t *testing.T) {
	codes := []AssessmentCode{
		CodeSuccess, CodeDNSFailure, CodeDNSTimeout, CodeUnexpectedPublicResolution,
		CodeMixedAddressResolution, CodeTCPTimeout, CodeTCPRefused, CodeTCPFailure,
		CodeTLSUntrusted, CodeTLSHostnameMismatch, CodeTLSExpired, CodeTLSFailure,
		CodeHTTPAuthenticationRequired, CodeHTTPAuthorizationDenied, CodeHTTPRateLimited,
		CodeHTTPServiceError, CodeHTTPRedirected, CodeOverallTimeout, CodeInconclusive,
	}

	for _, c := range codes {
		if c.String() == "" {
			t.Errorf("code %s String() is empty", c)
		}
		if c.DiagnosticPhase() == "" {
			t.Errorf("code %s DiagnosticPhase() is empty", c)
		}
		if c.Severity() == "" {
			t.Errorf("code %s Severity() is empty", c)
		}
		if c.HumanSummary() == "" {
			t.Errorf("code %s HumanSummary() is empty", c)
		}
		if c.RecommendationRule() == "" {
			t.Errorf("code %s RecommendationRule() is empty", c)
		}
	}
}
