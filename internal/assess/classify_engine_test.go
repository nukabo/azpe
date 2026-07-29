package assess_test

import (
	"testing"

	"github.com/nukabo/azpe/internal/assess"
	"github.com/nukabo/azpe/internal/target"
)

type mockTCPObs struct {
	aggStatus assess.AggregateTCPStatus
	results   []assess.MinimalTCPResultItem
}

func (m mockTCPObs) GetAggregateStatus() assess.AggregateTCPStatus { return m.aggStatus }
func (m mockTCPObs) GetResults() []assess.MinimalTCPResultItem     { return m.results }

type mockTCPItem struct {
	addr     string
	dest     string
	port     int
	status   assess.TCPAddressStatus
	duration int64
	errCat   string
	err      string
}

func (m mockTCPItem) GetAddress() string                 { return m.addr }
func (m mockTCPItem) GetDestination() string             { return m.dest }
func (m mockTCPItem) GetPort() int                       { return m.port }
func (m mockTCPItem) GetStatus() assess.TCPAddressStatus { return m.status }
func (m mockTCPItem) GetDurationMs() int64               { return m.duration }
func (m mockTCPItem) GetErrorCategory() string           { return m.errCat }
func (m mockTCPItem) GetError() string                   { return m.err }

type mockTLSObs struct {
	aggStatus  assess.AggregateTLSStatus
	serverName string
	results    []assess.MinimalTLSResultItem
}

func (m mockTLSObs) GetAggregateStatus() assess.AggregateTLSStatus { return m.aggStatus }
func (m mockTLSObs) GetServerName() string                         { return m.serverName }
func (m mockTLSObs) GetResults() []assess.MinimalTLSResultItem     { return m.results }

type mockTLSItem struct {
	addr        string
	dest        string
	port        int
	serverName  string
	status      assess.TLSAddressStatus
	stage       string
	duration    int64
	tlsVer      string
	cipherSuite string
	errCat      string
	err         string
}

func (m mockTLSItem) GetAddress() string                 { return m.addr }
func (m mockTLSItem) GetDestination() string             { return m.dest }
func (m mockTLSItem) GetPort() int                       { return m.port }
func (m mockTLSItem) GetServerName() string              { return m.serverName }
func (m mockTLSItem) GetStatus() assess.TLSAddressStatus { return m.status }
func (m mockTLSItem) GetStage() string                   { return m.stage }
func (m mockTLSItem) GetDurationMs() int64               { return m.duration }
func (m mockTLSItem) GetTLSVersion() string              { return m.tlsVer }
func (m mockTLSItem) GetCipherSuite() string             { return m.cipherSuite }
func (m mockTLSItem) GetErrorCategory() string           { return m.errCat }
func (m mockTLSItem) GetError() string                   { return m.err }

type mockHTTPObs struct {
	aggStatus assess.AggregateHTTPStatus
	method    string
	path      string
	results   []assess.MinimalHTTPResultItem
}

func (m mockHTTPObs) GetAggregateStatus() assess.AggregateHTTPStatus { return m.aggStatus }
func (m mockHTTPObs) GetMethod() string                              { return m.method }
func (m mockHTTPObs) GetPath() string                                { return m.path }
func (m mockHTTPObs) GetResults() []assess.MinimalHTTPResultItem     { return m.results }

type mockHTTPItem struct {
	addr       string
	dest       string
	port       int
	serverName string
	host       string
	method     string
	reqURI     string
	status     assess.HTTPAddressStatus
	statusCode int
	statusText string
	category   assess.HTTPResponseCategory
	duration   int64
	redirect   bool
	errCat     string
	err        string
}

func (m mockHTTPItem) GetAddress() string                               { return m.addr }
func (m mockHTTPItem) GetDestination() string                           { return m.dest }
func (m mockHTTPItem) GetPort() int                                     { return m.port }
func (m mockHTTPItem) GetServerName() string                            { return m.serverName }
func (m mockHTTPItem) GetHost() string                                  { return m.host }
func (m mockHTTPItem) GetMethod() string                                { return m.method }
func (m mockHTTPItem) GetRequestURI() string                            { return m.reqURI }
func (m mockHTTPItem) GetStatus() assess.HTTPAddressStatus              { return m.status }
func (m mockHTTPItem) GetStatusCode() int                               { return m.statusCode }
func (m mockHTTPItem) GetStatusText() string                            { return m.statusText }
func (m mockHTTPItem) GetResponseCategory() assess.HTTPResponseCategory { return m.category }
func (m mockHTTPItem) GetDurationMs() int64                             { return m.duration }
func (m mockHTTPItem) GetRedirectFollowed() bool                        { return m.redirect }
func (m mockHTTPItem) GetErrorCategory() string                         { return m.errCat }
func (m mockHTTPItem) GetError() string                                 { return m.err }

func TestEvaluate(t *testing.T) {
	t.Run("Recognized Azure Private DNS + TCP + TLS + HTTP 403 Exit 0", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results:   []assess.MinimalTCPResultItem{mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected, duration: 8}},
		}
		tlsObs := mockTLSObs{
			aggStatus:  assess.AggregateTLSAllValid,
			serverName: "myvault.vault.azure.net",
			results:    []assess.MinimalTLSResultItem{mockTLSItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, serverName: "myvault.vault.azure.net", status: assess.TLSAddrValid, duration: 15}},
		}
		httpObs := mockHTTPObs{
			aggStatus: assess.AggregateHTTPAllResponded,
			method:    "GET",
			path:      "/",
			results: []assess.MinimalHTTPResultItem{
				mockHTTPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, serverName: "myvault.vault.azure.net", host: "myvault.vault.azure.net", method: "GET", reqURI: "/", status: assess.HTTPAddrResponded, statusCode: 403, statusText: "Forbidden", category: assess.HTTPCatAccessDenied, duration: 24},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs, tlsObs, httpObs)

		if eval.ExitCode != 0 {
			t.Errorf("exitCode = %d, want 0", eval.ExitCode)
		}
		if eval.Title != "The Azure service responded" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service responded")
		}
	})

	t.Run("Recognized Azure HTTP Timeout Exit 7", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results:   []assess.MinimalTCPResultItem{mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected, duration: 8}},
		}
		tlsObs := mockTLSObs{
			aggStatus:  assess.AggregateTLSAllValid,
			serverName: "myvault.vault.azure.net",
			results:    []assess.MinimalTLSResultItem{mockTLSItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, serverName: "myvault.vault.azure.net", status: assess.TLSAddrValid, duration: 15}},
		}
		httpObs := mockHTTPObs{
			aggStatus: assess.AggregateHTTPNoneResponded,
			method:    "GET",
			path:      "/",
			results: []assess.MinimalHTTPResultItem{
				mockHTTPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, serverName: "myvault.vault.azure.net", host: "myvault.vault.azure.net", method: "GET", reqURI: "/", status: assess.HTTPAddrTimeout, category: assess.HTTPCatNoResponse, duration: 5000, errCat: "TIMEOUT", err: "context deadline exceeded"},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs, tlsObs, httpObs)

		if eval.ExitCode != 7 {
			t.Errorf("exitCode = %d, want 7", eval.ExitCode)
		}
		if eval.Title != "The Azure service did not respond in time" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service did not respond in time")
		}
	})

	t.Run("Recognized Azure Partial HTTP Exit 8", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results:   []assess.MinimalTCPResultItem{mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443"}, mockTCPItem{addr: "10.42.3.8", dest: "10.42.3.8:443"}},
		}
		tlsObs := mockTLSObs{
			aggStatus:  assess.AggregateTLSAllValid,
			serverName: "myvault.vault.azure.net",
			results: []assess.MinimalTLSResultItem{
				mockTLSItem{addr: "10.42.3.7", dest: "10.42.3.7:443", status: assess.TLSAddrValid},
				mockTLSItem{addr: "10.42.3.8", dest: "10.42.3.8:443", status: assess.TLSAddrValid},
			},
		}
		httpObs := mockHTTPObs{
			aggStatus: assess.AggregateHTTPPartiallyResponded,
			method:    "GET",
			path:      "/",
			results: []assess.MinimalHTTPResultItem{
				mockHTTPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", status: assess.HTTPAddrResponded, statusCode: 403, statusText: "Forbidden", category: assess.HTTPCatAccessDenied},
				mockHTTPItem{addr: "10.42.3.8", dest: "10.42.3.8:443", status: assess.HTTPAddrTimeout, category: assess.HTTPCatNoResponse, errCat: "TIMEOUT"},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7", "10.42.3.8"}, []assess.AddressClassification{assess.AddrPrivate, assess.AddrPrivate}, "", "", tcpObs, tlsObs, httpObs)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "The Azure service responded on only some private addresses" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service responded on only some private addresses")
		}
	})

	t.Run("Possible Azure domain unsupported service Exit 8 (ScenarioPossibleAzure)", func(t *testing.T) {
		tgt, _ := target.Parse("custom-app.azurewebsites.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePublicOnly, []string{"20.42.64.44"}, []assess.AddressClassification{assess.AddrPublic}, "", "", nil, nil, nil)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Scenario != assess.ScenarioPossibleAzure {
			t.Errorf("scenario = %v, want %v", eval.Scenario, assess.ScenarioPossibleAzure)
		}
		if eval.Title != "This Azure service is not supported yet" {
			t.Errorf("title = %q, want %q", eval.Title, "This Azure service is not supported yet")
		}
	})
}
