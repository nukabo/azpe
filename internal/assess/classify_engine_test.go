package assess_test

import (
	"testing"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/target"
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

func TestEvaluate(t *testing.T) {
	t.Run("Recognized Azure Private DNS + TCP + TLS Valid Exit 0", func(t *testing.T) {
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
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs, tlsObs)

		if eval.ExitCode != 0 {
			t.Errorf("exitCode = %d, want 0", eval.ExitCode)
		}
		if eval.Title != "Secure private connection looks correct" {
			t.Errorf("title = %q, want %q", eval.Title, "Secure private connection looks correct")
		}
	})

	t.Run("Recognized Azure Hostname Mismatch Exit 6", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results:   []assess.MinimalTCPResultItem{mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected, duration: 8}},
		}
		tlsObs := mockTLSObs{
			aggStatus:  assess.AggregateTLSNoneValid,
			serverName: "myvault.vault.azure.net",
			results:    []assess.MinimalTLSResultItem{mockTLSItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, serverName: "myvault.vault.azure.net", status: assess.TLSAddrHostnameMismatch, duration: 20, errCat: "HOSTNAME_MISMATCH"}},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs, tlsObs)

		if eval.ExitCode != 6 {
			t.Errorf("exitCode = %d, want 6", eval.ExitCode)
		}
		if eval.Title != "The certificate does not match the Azure service name" {
			t.Errorf("title = %q, want %q", eval.Title, "The certificate does not match the Azure service name")
		}
	})

	t.Run("Recognized Azure Untrusted Certificate Exit 6", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results:   []assess.MinimalTCPResultItem{mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected, duration: 8}},
		}
		tlsObs := mockTLSObs{
			aggStatus:  assess.AggregateTLSNoneValid,
			serverName: "myvault.vault.azure.net",
			results:    []assess.MinimalTLSResultItem{mockTLSItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, serverName: "myvault.vault.azure.net", status: assess.TLSAddrUntrustedCertificate, duration: 20, errCat: "UNTRUSTED_CERTIFICATE"}},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs, tlsObs)

		if eval.ExitCode != 6 {
			t.Errorf("exitCode = %d, want 6", eval.ExitCode)
		}
		if eval.Title != "The certificate is not trusted by this workload" {
			t.Errorf("title = %q, want %q", eval.Title, "The certificate is not trusted by this workload")
		}
	})

	t.Run("Recognized Azure Partial TLS Exit 8", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results:   []assess.MinimalTCPResultItem{mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected}, mockTCPItem{addr: "10.42.3.8", dest: "10.42.3.8:443", port: 443, status: assess.TCPAddrConnected}},
		}
		tlsObs := mockTLSObs{
			aggStatus:  assess.AggregateTLSPartiallyValid,
			serverName: "myvault.vault.azure.net",
			results: []assess.MinimalTLSResultItem{
				mockTLSItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TLSAddrValid},
				mockTLSItem{addr: "10.42.3.8", dest: "10.42.3.8:443", port: 443, status: assess.TLSAddrUntrustedCertificate, errCat: "UNTRUSTED_CERTIFICATE"},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7", "10.42.3.8"}, []assess.AddressClassification{assess.AddrPrivate, assess.AddrPrivate}, "", "", tcpObs, tlsObs)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "TLS works for only some private addresses" {
			t.Errorf("title = %q, want %q", eval.Title, "TLS works for only some private addresses")
		}
	})
}
