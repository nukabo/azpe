package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/output"
	"github.com/azpe/azpe/internal/target"
)

func TestRender_SimplePrivateOnly(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
		DurationMs:    10,
		Addresses: []model.IPObservation{
			{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
		},
		AggregateClassification: assess.AggregatePrivateOnly,
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregatePrivateOnly,
		Addresses:      dnsObs.Addresses,
		PrivateIPs:     []string{"10.42.3.7"},
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "✓ Private DNS looks correct") {
		t.Errorf("expected header '✓ Private DNS looks correct', got: %s", outStr)
	}
	if !strings.Contains(outStr, "myvault.vault.azure.net → 10.42.3.7 (private)") {
		t.Errorf("expected address line, got: %s", outStr)
	}
	if !strings.Contains(outStr, "The service name points to a private address from this workload.") {
		t.Errorf("expected explanation line, got: %s", outStr)
	}
	if !strings.Contains(outStr, "Connection not tested yet.") {
		t.Errorf("expected Connection not tested yet, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)
}

func TestRender_SimplePublicOnly(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
		DurationMs:    10,
		Addresses: []model.IPObservation{
			{Address: "20.42.64.44", Version: "IPv4", Classification: assess.AddrPublic},
		},
		AggregateClassification: assess.AggregatePublicOnly,
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregatePublicOnly,
		Addresses:      dnsObs.Addresses,
		PublicIPs:      []string{"20.42.64.44"},
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "✗ This workload is not using private DNS") {
		t.Errorf("expected header '✗ This workload is not using private DNS', got: %s", outStr)
	}
	if !strings.Contains(outStr, "myvault.vault.azure.net → 20.42.64.44 (public)") {
		t.Errorf("expected public address mapping, got: %s", outStr)
	}
	if !strings.Contains(outStr, "The application will attempt to use the public Azure endpoint.") {
		t.Errorf("expected public endpoint message, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)
}

func TestRender_SimpleDNSFailure(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:                  assess.DNSStatusNotFound,
		QueryHostname:           "myvault.vault.azure.net",
		DurationMs:              5,
		Addresses:               []model.IPObservation{},
		AggregateClassification: assess.AggregateNone,
		ErrorCategory:           "NOT_FOUND",
		ErrorMessage:            "no such host",
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregateNone,
		Addresses:      []model.IPObservation{},
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "✗ The Azure service name cannot be resolved") {
		t.Errorf("expected header '✗ The Azure service name cannot be resolved', got: %s", outStr)
	}
	if !strings.Contains(outStr, "myvault.vault.azure.net") {
		t.Errorf("expected hostname, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)
}

func TestRender_UnrecognizedTarget(t *testing.T) {
	tgt, _ := target.Parse("microsoft.com")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "microsoft.com",
		DurationMs:    10,
		Addresses: []model.IPObservation{
			{Address: "150.171.109.193", Version: "IPv4", Classification: assess.AddrPublic},
		},
		AggregateClassification: assess.AggregatePublicOnly,
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregatePublicOnly,
		Addresses:      dnsObs.Addresses,
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "Cannot test this target") {
		t.Errorf("expected header 'Cannot test this target', got: %s", outStr)
	}
	if !strings.Contains(outStr, "microsoft.com is not a recognized Azure Private Endpoint service hostname.") {
		t.Errorf("expected unrecognized message, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)
}

func TestRender_IPLiteralInput(t *testing.T) {
	tgt, _ := target.Parse("10.0.0.1")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusNotApplicable,
		QueryHostname: "10.0.0.1",
		DurationMs:    0,
		Addresses: []model.IPObservation{
			{Address: "10.0.0.1", Version: "IPv4", Classification: assess.AddrPrivate},
		},
		AggregateClassification: assess.AggregatePrivateOnly,
		IsIPLiteral:             true,
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregatePrivateOnly,
		Addresses:      dnsObs.Addresses,
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "The Azure service hostname is required") {
		t.Errorf("expected header 'The Azure service hostname is required', got: %s", outStr)
	}
	if !strings.Contains(outStr, "An IP address cannot test Private Endpoint DNS.") {
		t.Errorf("expected IP address cannot test Private Endpoint DNS message, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)
}

func TestRender_JSONAssertions(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
		DurationMs:    10,
		Addresses: []model.IPObservation{
			{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
		},
		AggregateClassification: assess.AggregatePrivateOnly,
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregatePrivateOnly,
		Addresses:      dnsObs.Addresses,
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{JSON: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()

	// Assert no ANSI escape codes
	if strings.Contains(outStr, "\033[") {
		t.Errorf("JSON output contained ANSI escape sequences: %s", outStr)
	}

	// Assert certValid is omitted when TLS skipped
	if strings.Contains(outStr, "\"certValid\"") {
		t.Errorf("JSON output contained certValid when TLS was skipped: %s", outStr)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if int(parsed["schemaVersion"].(float64)) != 1 {
		t.Errorf("expected schemaVersion 1, got %v", parsed["schemaVersion"])
	}

	tgtMap := parsed["target"].(map[string]interface{})
	if tgtMap["targetType"] != "RECOGNIZED_AZURE_SERVICE" {
		t.Errorf("expected targetType RECOGNIZED_AZURE_SERVICE, got %v", tgtMap["targetType"])
	}
	if tgtMap["azureServiceFamily"] != "KEY_VAULT" {
		t.Errorf("expected azureServiceFamily KEY_VAULT, got %v", tgtMap["azureServiceFamily"])
	}
}

func TestRender_HTMLAbsence(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
		DurationMs:    10,
		Addresses: []model.IPObservation{
			{Address: "20.42.64.44", Version: "IPv4", Classification: assess.AddrPublic},
		},
		AggregateClassification: assess.AggregatePublicOnly,
	}
	addrObs := model.AddrObservation{
		Classification: assess.AggregatePublicOnly,
		Addresses:      dnsObs.Addresses,
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{Details: true, NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	htmlTags := []string{"<a href=", "&lt;", "&gt;", "target=\"_blank\"", "rel=\"noopener\""}
	for _, tag := range htmlTags {
		if strings.Contains(outStr, tag) {
			t.Errorf("detailed terminal output contained HTML markup %q:\n%s", tag, outStr)
		}
	}
}

func assertNoProhibitedPhrases(t *testing.T, out string) {
	t.Helper()
	prohibited := []string{
		"UNKNOWN",
		"NOT_PRIVATE",
		"BROKEN",
		"DNS_OR_NETWORK",
		"PUBLIC_ONLY",
		"PRIVATE_ONLY",
		"MIXED_PRIVATE_PUBLIC",
		"SPECIAL_ONLY",
		"NOT_APPLICABLE",
		"RECOGNIZED_AZURE_SERVICE",
		"IP_LITERAL",
		"Public IP address detected",
		"Private DNS is active",
		"Private DNS is not active here",
		"Private Endpoint verified",
		"Private Endpoint is working",
		"Private Endpoint is broken",
		"Network connectivity is healthy",
		"Private DNS zone is linked",
		"Private Endpoint is approved",
		"<a href=",
		"&lt;",
		"&gt;",
	}

	for _, p := range prohibited {
		if strings.Contains(out, p) {
			t.Errorf("default terminal output contains prohibited phrase %q:\n%s", p, out)
		}
	}
}
