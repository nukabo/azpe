package assess_test

import (
	"testing"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/target"
)

func TestEvaluate(t *testing.T) {
	t.Run("Recognized Azure Private DNS Active", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePrivateOnly, []string{"10.42.3.7"}, []assess.AddressClassification{assess.AddrPrivate}, "", "")

		if eval.ExitCode != 0 {
			t.Errorf("exitCode = %d, want 0", eval.ExitCode)
		}
		if eval.Title != "Private DNS looks correct" {
			t.Errorf("title = %q, want %q", eval.Title, "Private DNS looks correct")
		}
	})

	t.Run("Recognized Azure Private DNS Not Active", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePublicOnly, []string{"20.42.64.44"}, []assess.AddressClassification{assess.AddrPublic}, "", "")

		if eval.ExitCode != 4 {
			t.Errorf("exitCode = %d, want 4", eval.ExitCode)
		}
		if eval.Title != "This workload is not using private DNS" {
			t.Errorf("title = %q, want %q", eval.Title, "This workload is not using private DNS")
		}
	})

	t.Run("Recognized Azure DNS Lookup Failed", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusNotFound, assess.AggregateNone, []string{}, []assess.AddressClassification{}, "NOT_FOUND", "no such host")

		if eval.ExitCode != 3 {
			t.Errorf("exitCode = %d, want 3", eval.ExitCode)
		}
		if eval.Title != "The Azure service name cannot be resolved" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service name cannot be resolved")
		}
	})

	t.Run("Mixed Private and Public", func(t *testing.T) {
		tgt, _ := target.Parse("myvault.vault.azure.net")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregateMixedPrivatePublic, []string{"10.42.3.7", "20.42.64.44"}, []assess.AddressClassification{assess.AddrPrivate, assess.AddrPublic}, "", "")

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "DNS is returning both private and public addresses" {
			t.Errorf("title = %q, want %q", eval.Title, "DNS is returning both private and public addresses")
		}
	})

	t.Run("IP Literal Input", func(t *testing.T) {
		tgt, _ := target.Parse("10.0.0.1")
		eval := assess.Evaluate(tgt, assess.DNSStatusNotApplicable, assess.AggregatePrivateOnly, []string{"10.0.0.1"}, []assess.AddressClassification{assess.AddrPrivate}, "", "")

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "The Azure service hostname is required" {
			t.Errorf("title = %q, want %q", eval.Title, "The Azure service hostname is required")
		}
	})

	t.Run("Unrecognized Target microsoft.com", func(t *testing.T) {
		tgt, _ := target.Parse("microsoft.com")
		eval := assess.Evaluate(tgt, assess.DNSStatusSuccess, assess.AggregatePublicOnly, []string{"150.171.109.193"}, []assess.AddressClassification{assess.AddrPublic}, "", "")

		if eval.ExitCode != 8 {
			t.Errorf("exitCode = %d, want 8", eval.ExitCode)
		}
		if eval.Title != "Cannot test this target" {
			t.Errorf("title = %q, want %q", eval.Title, "Cannot test this target")
		}
	})
}
