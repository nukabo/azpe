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
	addr        string
	dest        string
	port        int
	status      assess.TCPAddressStatus
	duration    int64
	errCategory string
	err         string
}

func (m mockTCPItem) GetAddress() string                 { return m.addr }
func (m mockTCPItem) GetDestination() string             { return m.dest }
func (m mockTCPItem) GetPort() int                       { return m.port }
func (m mockTCPItem) GetStatus() assess.TCPAddressStatus { return m.status }
func (m mockTCPItem) GetDurationMs() int64               { return m.duration }
func (m mockTCPItem) GetErrorCategory() string           { return m.errCategory }
func (m mockTCPItem) GetError() string                   { return m.err }

func TestEvaluate(t *testing.T) {
	t.Run("Recognized Azure Private DNS Active Untested TCP", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", nil)

		if eval.ExitCode != 0 {
			t.Errorf("exitCode = %d, want 0", eval.ExitCode)
		}
		if eval.Title != "Private DNS looks correct" {
			t.Errorf("title = %q, want %q", eval.Title, "Private DNS looks correct")
		}
	})

	t.Run("Recognized Azure Private DNS TCP Reachable", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPAllConnected,
			results: []assess.MinimalTCPResultItem{
				mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected, duration: 8},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs)

		if eval.ExitCode != 0 {
			t.Errorf("exitCode = %d, want 0", eval.ExitCode)
		}
		if eval.Title != "Private connection is reachable" {
			t.Errorf("title = %q, want %q", eval.Title, "Private connection is reachable")
		}
	})

	t.Run("Recognized Azure Private DNS TCP Unreachable", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPNoneConnected,
			results: []assess.MinimalTCPResultItem{
				mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrTimedOut, duration: 5001, errCategory: "TIMEOUT", err: "dial tcp 10.42.3.7:443: i/o timeout"},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", tcpObs)

		if eval.ExitCode != 5 {
			t.Errorf("exitCode = %d, want 5", eval.ExitCode)
		}
		if eval.Title != "The private address cannot be reached" {
			t.Errorf("title = %q, want %q", eval.Title, "The private address cannot be reached")
		}
	})

	t.Run("Recognized Azure Private DNS Partial TCP", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		tcpObs := mockTCPObs{
			aggStatus: assess.AggregateTCPPartiallyConnected,
			results: []assess.MinimalTCPResultItem{
				mockTCPItem{addr: "10.42.3.7", dest: "10.42.3.7:443", port: 443, status: assess.TCPAddrConnected, duration: 8},
				mockTCPItem{addr: "10.42.3.8", dest: "10.42.3.8:443", port: 443, status: assess.TCPAddrTimedOut, duration: 5001, errCategory: "TIMEOUT"},
			},
		}
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7", "10.42.3.8"}, []assess.AddressClassification{assess.AddrPrivate, assess.AddrPrivate}, "", "", tcpObs)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "Some private addresses cannot be reached" {
			t.Errorf("title = %q, want %q", eval.Title, "Some private addresses cannot be reached")
		}
	})

	t.Run("Recognized Azure Private DNS Not Active", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePublicOnly, []string{"20.42.64.44"}, []assess.AddressClassification{assess.AddrPublic}, "", "", nil)

		if eval.ExitCode != 4 {
			t.Errorf("exitCode = %d, want 4", eval.ExitCode)
		}
		if eval.Title != "This workload is not using private DNS" {
			t.Errorf("title = %q, want %q", eval.Title, "This workload is not using private DNS")
		}
	})

	t.Run("Recognized Azure DNS Lookup Failed", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusNotFound, assess.AggregateNone, []string{}, []assess.AddressClassification{}, "NOT_FOUND", "no such host", nil)

		if eval.ExitCode != 3 {
			t.Errorf("exitCode = %d, want 3", eval.ExitCode)
		}
		if eval.Title != "The Azure service name cannot be resolved" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service name cannot be resolved")
		}
	})

	t.Run("Mixed Private and Public", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregateMixedPrivatePublic, []string{"10.42.3.7", "20.42.64.44"}, []assess.AddressClassification{assess.AddrPrivate, assess.AddrPublic}, "", "", nil)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "DNS is returning both private and public addresses" {
			t.Errorf("title = %q, want %q", eval.Title, "DNS is returning both private and public addresses")
		}
	})

	t.Run("IP Literal Input", func(t *testing.T) {
		tgt, _ := target.Parse("10.0.0.1")
		eval := assess.Evaluate(tgt, assess.DNSStatusNotApplicable, assess.AggregatePrivateOnly, []string{"10.0.0.1"}, []assess.AddressClassification{assess.AddrPrivate}, "", "", nil)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "The Azure service hostname is required" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service hostname is required")
		}
	})

	t.Run("Unrecognized Target microsoft.com", func(t *testing.T) {
		tgt, _ := target.Parse("microsoft.com")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePublicOnly, []string{"150.171.109.193"}, []assess.AddressClassification{assess.AddrPublic}, "", "", nil)

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "Cannot test this target" {
			t.Errorf("title = %q, want %q", eval.Title, "Cannot test this target")
		}
	})
}
