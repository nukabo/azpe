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

func TestRender_HTTP403_SimpleAndDetailed(t *testing.T) {
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
			},
		},
	}
	httpObs := model.HTTPObservation{
		Status:          assess.HTTPStatusSuccess,
		AggregateStatus: assess.AggregateHTTPAllResponded,
		Method:          "GET",
		Path:            "/",
		DurationMs:      24,
		Results: []model.HTTPResultItem{
			{
				Address:          "10.42.3.7",
				Version:          "IPv4",
				Classification:   assess.AddrPrivate,
				Destination:      "10.42.3.7:443",
				Port:             443,
				ServerName:       "myvault.vault.azure.net",
				Host:             "myvault.vault.azure.net",
				Method:           "GET",
				RequestURI:       "/",
				Status:           assess.HTTPAddrResponded,
				StatusCode:       403,
				StatusText:       "Forbidden",
				ResponseCategory: assess.HTTPCatAccessDenied,
				DurationMs:       24,
				Headers: &model.SafeHTTPHeaders{
					ContentType: "application/json",
					RequestID:   "req-12345",
				},
			},
		},
	}

	res := model.NewResultFromDNSAndTCPAndTLSAndHTTP(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs, httpObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, "✓ The Azure service responded") {
		t.Errorf("expected title '✓ The Azure service responded', got: %s", outStr)
	}
	if !strings.Contains(outStr, "Azure service   Access denied") {
		t.Errorf("expected Azure service Access denied status, got: %s", outStr)
	}

	assertNoProhibitedPhrases(t, outStr)

	// Test Details view
	buf.Reset()
	err = output.Render(&buf, res, output.FormatOptions{Details: true, NoColor: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	detailsStr := buf.String()
	if !strings.Contains(detailsStr, "=== HTTP ===") {
		t.Errorf("expected HTTP section in details, got: %s", detailsStr)
	}
	if !strings.Contains(detailsStr, "Status               Response received from all addresses") {
		t.Errorf("expected Response received from all addresses in details, got: %s", detailsStr)
	}
}

func TestRender_JSONAssertions_Phase5(t *testing.T) {
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
		Results:         []model.TLSResultItem{{Address: "10.42.3.7", Destination: "10.42.3.7:443", Status: assess.TLSAddrValid, HostnameValid: &bTrue, CertificateTrusted: &bTrue}},
	}
	httpObs := model.HTTPObservation{
		Status:          assess.HTTPStatusSuccess,
		AggregateStatus: assess.AggregateHTTPAllResponded,
		Method:          "GET",
		Path:            "/",
		DurationMs:      24,
		Results: []model.HTTPResultItem{
			{
				Address:          "10.42.3.7",
				Destination:      "10.42.3.7:443",
				ServerName:       "myvault.vault.azure.net",
				Host:             "myvault.vault.azure.net",
				Method:           "GET",
				RequestURI:       "/",
				Status:           assess.HTTPAddrResponded,
				StatusCode:       403,
				StatusText:       "Forbidden",
				ResponseCategory: assess.HTTPCatAccessDenied,
				DurationMs:       24,
			},
		},
	}

	res := model.NewResultFromDNSAndTCPAndTLSAndHTTP(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs, httpObs)

	var buf bytes.Buffer
	err := output.Render(&buf, res, output.FormatOptions{JSON: true})
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	httpMap := parsed["http"].(map[string]interface{})
	if httpMap["aggregateStatus"] != "ALL_RESPONDED" {
		t.Errorf("expected aggregateStatus ALL_RESPONDED, got %v", httpMap["aggregateStatus"])
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
		"ALL_RESPONDED",
		"NONE_RESPONDED",
		"PARTIALLY_RESPONDED",
		"AUTHENTICATION_REQUIRED",
		"ACCESS_DENIED",
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
