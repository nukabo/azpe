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

func TestRender_TLSValid_SimpleAndDetailed(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
		DurationMs:    4,
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
	tcpObs := model.TCPObservation{
		Status:          assess.TCPStatusSuccess,
		AggregateStatus: assess.AggregateTCPAllConnected,
		Port:            443,
		DurationMs:      8,
		Results: []model.TCPResultItem{
			{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, Status: assess.TCPAddrConnected, DurationMs: 8},
		},
	}
	bTrue := true
	tlsObs := model.TLSObservation{
		Status:          assess.TLSStatusSuccess,
		AggregateStatus: assess.AggregateTLSAllValid,
		ServerName:      "myvault.vault.azure.net",
		DurationMs:      18,
		Results: []model.TLSResultItem{
			{
				Address:            "10.42.3.7",
				Version:            "IPv4",
				Classification:     assess.AddrPrivate,
				Destination:        "10.42.3.7:443",
				Port:               443,
				ServerName:         "myvault.vault.azure.net",
				Status:             assess.TLSAddrValid,
				Stage:              "COMPLETE",
				DurationMs:         18,
				TLSVersion:         "TLS 1.3",
				CipherSuite:        "TLS_AES_256_GCM_SHA384",
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
				LeafCertificate: &model.LeafCertInfo{
					Subject:   "CN=myvault.vault.azure.net",
					Issuer:    "CN=Microsoft Azure RSA TLS Issuing CA",
					NotBefore: "2026-01-01T00:00:00Z",
					NotAfter:  "2026-12-31T23:59:59Z",
				},
			},
		},
	}

	res := model.NewResultFromDNSAndTCPAndTLS(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "✓ Secure private connection looks correct") {
		t.Errorf("expected title '✓ Secure private connection looks correct', got: %s", outStr)
	}
	if !strings.Contains(outStr, "TLS             Valid") {
		t.Errorf("expected TLS Valid status, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)

	// Test Details view
	buf.Reset()
	err = output.Render(&buf, res, output.FormatOptions{Details: true, NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	detailsStr := buf.String()
	if !strings.Contains(detailsStr, "=== TLS ===") {
		t.Errorf("expected TLS section in details, got: %s", detailsStr)
	}
	if !strings.Contains(detailsStr, "Status               Valid for all addresses") {
		t.Errorf("expected Valid for all addresses status in details, got: %s", detailsStr)
	}
	if !strings.Contains(detailsStr, "TLS version      TLS 1.3") {
		t.Errorf("expected TLS 1.3 in details, got: %s", detailsStr)
	}
}

func TestRender_TLSHostnameMismatch_SimpleAndDetailed(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:                  assess.DNSStatusSuccess,
		QueryHostname:           "myvault.vault.azure.net",
		Addresses:               []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}},
		AggregateClassification: assess.AggregatePrivateOnly,
	}
	addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, Addresses: dnsObs.Addresses, PrivateIPs: []string{"10.42.3.7"}}
	tcpObs := model.TCPObservation{
		Status:          assess.TCPStatusSuccess,
		AggregateStatus: assess.AggregateTCPAllConnected,
		Port:            443,
		Results:         []model.TCPResultItem{{Address: "10.42.3.7", Destination: "10.42.3.7:443", Port: 443, Status: assess.TCPAddrConnected}},
	}
	bFalse := false
	tlsObs := model.TLSObservation{
		Status:          assess.TLSStatusFailed,
		AggregateStatus: assess.AggregateTLSNoneValid,
		ServerName:      "myvault.vault.azure.net",
		Results: []model.TLSResultItem{
			{
				Address:       "10.42.3.7",
				Destination:   "10.42.3.7:443",
				ServerName:    "myvault.vault.azure.net",
				Status:        assess.TLSAddrHostnameMismatch,
				Stage:         "CERTIFICATE_VALIDATION",
				DurationMs:    21,
				HostnameValid: &bFalse,
				ErrorCategory: "HOSTNAME_MISMATCH",
				Error:         "x509: certificate is valid for wrong.vault.azure.net, not myvault.vault.azure.net",
			},
		},
	}

	res := model.NewResultFromDNSAndTCPAndTLS(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "✗ The certificate does not match the Azure service name") {
		t.Errorf("expected title '✗ The certificate does not match the Azure service name', got: %s", outStr)
	}
	if !strings.Contains(outStr, "TLS             Hostname mismatch") {
		t.Errorf("expected TLS Hostname mismatch status, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)
}

func TestRender_JSONAssertions_Phase4(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:                  assess.DNSStatusSuccess,
		QueryHostname:           "myvault.vault.azure.net",
		Addresses:               []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}},
		AggregateClassification: assess.AggregatePrivateOnly,
	}
	addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, Addresses: dnsObs.Addresses}
	tcpObs := model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Destination: "10.42.3.7:443", Status: assess.TCPAddrConnected}}}
	bTrue := true
	tlsObs := model.TLSObservation{
		Status:          assess.TLSStatusSuccess,
		AggregateStatus: assess.AggregateTLSAllValid,
		ServerName:      "myvault.vault.azure.net",
		DurationMs:      18,
		Results: []model.TLSResultItem{
			{
				Address:            "10.42.3.7",
				Destination:        "10.42.3.7:443",
				ServerName:         "myvault.vault.azure.net",
				Status:             assess.TLSAddrValid,
				Stage:              "COMPLETE",
				DurationMs:         18,
				TLSVersion:         "TLS 1.3",
				CipherSuite:        "TLS_AES_256_GCM_SHA384",
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
			},
		},
	}

	res := model.NewResultFromDNSAndTCPAndTLS(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{JSON: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	tlsMap := parsed["tls"].(map[string]interface{})
	if tlsMap["aggregateStatus"] != "ALL_VALID" {
		t.Errorf("expected aggregateStatus ALL_VALID, got %v", tlsMap["aggregateStatus"])
	}
	if tlsMap["serverName"] != "myvault.vault.azure.net" {
		t.Errorf("expected serverName myvault.vault.azure.net, got %v", tlsMap["serverName"])
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
		"ALL_CONNECTED",
		"NONE_CONNECTED",
		"PARTIALLY_CONNECTED",
		"ALL_VALID",
		"NONE_VALID",
		"PARTIALLY_VALID",
		"HOSTNAME_MISMATCH",
		"UNTRUSTED_CERTIFICATE",
		"SECURITY_OR_PROXY",
		"InsecureSkipVerify",
		"Public IP address detected",
		"Private DNS is active",
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
