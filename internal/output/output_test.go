package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/nukabo/azpe/internal/assess"
	"github.com/nukabo/azpe/internal/model"
	"github.com/nukabo/azpe/internal/output"
	"github.com/nukabo/azpe/internal/target"
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
	if !strings.Contains(detailsStr, "Resolver mode        Go built-in") {
		t.Errorf("expected Resolver mode Go built-in in details, got: %s", detailsStr)
	}
	if !strings.Contains(detailsStr, "Status               Response received from all addresses") {
		t.Errorf("expected Response received from all addresses in details, got: %s", detailsStr)
	}
}

func TestRender_JSONAssertions_Phase5(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")
	dnsObs := model.DNSObservation{
		Status:                  assess.DNSStatusSuccess,
		ResolverMode:            assess.ResolverModeGoBuiltin,
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

	dnsMap := parsed["dns"].(map[string]interface{})
	if dnsMap["resolverMode"] != "GO_BUILTIN" {
		t.Errorf("expected resolverMode GO_BUILTIN, got %v", dnsMap["resolverMode"])
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

func TestCanaryRedactionInTerminalAndJSON(t *testing.T) {
	canaries := []string{"AZPE_SECRET_1", "AZPE_SECRET_2", "AZPE_PROXY_PASSWORD"}
	rawInput := "https://user:AZPE_PROXY_PASSWORD@myvault.vault.azure.net:8443/keys?sig=AZPE_SECRET_1&mode=read#section"

	tgt, err := target.Parse(rawInput)
	if err != nil {
		t.Fatalf("unexpected Parse error: %v", err)
	}

	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
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
		Port:            8443,
		Results: []model.TCPResultItem{
			{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:8443", Port: 8443, Status: assess.TCPAddrConnected},
		},
	}
	bTrue := true
	tlsObs := model.TLSObservation{
		Status:          assess.TLSStatusSuccess,
		AggregateStatus: assess.AggregateTLSAllValid,
		ServerName:      "myvault.vault.azure.net",
		Results: []model.TLSResultItem{
			{
				Address:            "10.42.3.7",
				Version:            "IPv4",
				Classification:     assess.AddrPrivate,
				Destination:        "10.42.3.7:8443",
				Port:               8443,
				ServerName:         "myvault.vault.azure.net",
				Status:             assess.TLSAddrValid,
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
			},
		},
	}
	httpObs := model.HTTPObservation{
		Status:          assess.HTTPStatusSuccess,
		AggregateStatus: assess.AggregateHTTPAllResponded,
		Method:          "GET",
		Path:            tgt.RequestPath,
		Results: []model.HTTPResultItem{
			{
				Address:          "10.42.3.7",
				Version:          "IPv4",
				Classification:   assess.AddrPrivate,
				Destination:      "10.42.3.7:8443",
				Port:             8443,
				ServerName:       "myvault.vault.azure.net",
				Host:             "myvault.vault.azure.net:8443",
				Method:           "GET",
				RequestURI:       tgt.RequestPath,
				Status:           assess.HTTPAddrResponded,
				StatusCode:       403,
				StatusText:       "Forbidden",
				ResponseCategory: assess.HTTPCatAccessDenied,
				Headers: &model.SafeHTTPHeaders{
					Location: target.SanitizeLocation("https://user:AZPE_PROXY_PASSWORD@redirect.target/path?token=AZPE_SECRET_2#section"),
				},
				Error: target.SanitizeErrorString(`Get "https://user:AZPE_PROXY_PASSWORD@myvault.vault.azure.net/keys?sig=AZPE_SECRET_1": dial tcp: connection refused`),
			},
		},
	}

	res := model.NewResultFromDNSAndTCPAndTLSAndHTTP(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs, httpObs)

	t.Run("simple terminal rendering", func(t *testing.T) {
		var buf bytes.Buffer
		err := output.Render(&buf, res, output.FormatOptions{NoColor: true})
		if err != nil {
			t.Fatalf("unexpected render error: %v", err)
		}
		outStr := buf.String()
		for _, canary := range canaries {
			if strings.Contains(outStr, canary) {
				t.Errorf("canary %q leaked in simple terminal output:\n%s", canary, outStr)
			}
		}
	})

	t.Run("detailed terminal rendering", func(t *testing.T) {
		var buf bytes.Buffer
		err := output.Render(&buf, res, output.FormatOptions{Details: true, NoColor: true})
		if err != nil {
			t.Fatalf("unexpected render error: %v", err)
		}
		outStr := buf.String()
		for _, canary := range canaries {
			if strings.Contains(outStr, canary) {
				t.Errorf("canary %q leaked in detailed terminal output:\n%s", canary, outStr)
			}
		}
	})

	t.Run("JSON rendering", func(t *testing.T) {
		var buf bytes.Buffer
		err := output.Render(&buf, res, output.FormatOptions{JSON: true})
		if err != nil {
			t.Fatalf("unexpected JSON render error: %v", err)
		}
		outStr := buf.String()
		for _, canary := range canaries {
			if strings.Contains(outStr, canary) {
				t.Errorf("canary %q leaked in JSON output:\n%s", canary, outStr)
			}
		}
	})
}

func TestSingleTypedResult_RefactorInvariants(t *testing.T) {
	tgt, _ := target.Parse("myvault.vault.azure.net")

	t.Run("result after DNS failure", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:                  assess.DNSStatusNotFound,
			QueryHostname:           "myvault.vault.azure.net",
			ErrorCategory:           "NOT_FOUND",
			ErrorMessage:            "no such host",
			AggregateClassification: assess.AggregateNone,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregateNone}
		res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

		if res.Assessment.Scenario != assess.ScenarioDNSLookupFailed {
			t.Errorf("expected ScenarioDNSLookupFailed, got %v", res.Assessment.Scenario)
		}
		if res.Assessment.State != assess.AssessmentBroken {
			t.Errorf("expected AssessmentBroken, got %v", res.Assessment.State)
		}

		var bufJSON, bufTerm bytes.Buffer
		_ = output.Render(&bufJSON, res, output.FormatOptions{JSON: true})
		_ = output.Render(&bufTerm, res, output.FormatOptions{NoColor: true})

		if !strings.Contains(bufJSON.String(), "DNS_LOOKUP_FAILED") {
			t.Errorf("JSON output missing scenario DNS_LOOKUP_FAILED")
		}
		if !strings.Contains(bufTerm.String(), res.Assessment.Title) {
			t.Errorf("terminal output missing assessment title")
		}
	})

	t.Run("result after TCP failure", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:        assess.DNSStatusSuccess,
			QueryHostname: "myvault.vault.azure.net",
			Addresses: []model.IPObservation{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
			},
			AggregateClassification: assess.AggregatePrivateOnly,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}}
		tcpObs := model.TCPObservation{
			Status:          assess.TCPStatusFailed,
			AggregateStatus: assess.AggregateTCPNoneConnected,
			Port:            443,
			Results: []model.TCPResultItem{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, Status: assess.TCPAddrTimedOut, ErrorCategory: "TIMEOUT"},
			},
		}
		res := model.NewResultFromDNSAndTCP(tgt, time.Now(), dnsObs, addrObs, tcpObs)

		if res.Assessment.Scenario != assess.ScenarioPrivateTCPUnreachable {
			t.Errorf("expected ScenarioPrivateTCPUnreachable, got %v", res.Assessment.Scenario)
		}
	})

	t.Run("result after TLS failure", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:        assess.DNSStatusSuccess,
			QueryHostname: "myvault.vault.azure.net",
			Addresses: []model.IPObservation{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
			},
			AggregateClassification: assess.AggregatePrivateOnly,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}}
		tcpObs := model.TCPObservation{
			Status:          assess.TCPStatusSuccess,
			AggregateStatus: assess.AggregateTCPAllConnected,
			Port:            443,
			Results: []model.TCPResultItem{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, Status: assess.TCPAddrConnected},
			},
		}
		tlsObs := model.TLSObservation{
			Status:          assess.TLSStatusFailed,
			AggregateStatus: assess.AggregateTLSNoneValid,
			ServerName:      "myvault.vault.azure.net",
			Results: []model.TLSResultItem{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, ServerName: "myvault.vault.azure.net", Status: assess.TLSAddrUntrustedCertificate, ErrorCategory: "UNTRUSTED_CERTIFICATE"},
			},
		}
		res := model.NewResultFromDNSAndTCPAndTLS(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs)

		if res.Assessment.Scenario != assess.ScenarioPrivateTLSUntrusted && res.Assessment.Scenario != assess.ScenarioPrivateTLSFailed {
			t.Errorf("expected TLS failure scenario, got %v", res.Assessment.Scenario)
		}
	})

	t.Run("result after HTTP response", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:        assess.DNSStatusSuccess,
			QueryHostname: "myvault.vault.azure.net",
			Addresses: []model.IPObservation{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
			},
			AggregateClassification: assess.AggregatePrivateOnly,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}}
		tcpObs := model.TCPObservation{
			Status:          assess.TCPStatusSuccess,
			AggregateStatus: assess.AggregateTCPAllConnected,
			Port:            443,
			Results:         []model.TCPResultItem{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, Status: assess.TCPAddrConnected}},
		}
		bTrue := true
		tlsObs := model.TLSObservation{
			Status:          assess.TLSStatusSuccess,
			AggregateStatus: assess.AggregateTLSAllValid,
			ServerName:      "myvault.vault.azure.net",
			Results:         []model.TLSResultItem{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, ServerName: "myvault.vault.azure.net", Status: assess.TLSAddrValid, HostnameValid: &bTrue, CertificateTrusted: &bTrue}},
		}
		httpObs := model.HTTPObservation{
			Status:          assess.HTTPStatusSuccess,
			AggregateStatus: assess.AggregateHTTPAllResponded,
			Method:          "GET",
			Path:            "/",
			Results:         []model.HTTPResultItem{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, ServerName: "myvault.vault.azure.net", Host: "myvault.vault.azure.net", Method: "GET", RequestURI: "/", Status: assess.HTTPAddrResponded, StatusCode: 403, StatusText: "Forbidden", ResponseCategory: assess.HTTPCatAccessDenied}},
		}

		res := model.NewResultFromDNSAndTCPAndTLSAndHTTP(tgt, time.Now(), dnsObs, addrObs, tcpObs, tlsObs, httpObs)

		if res.Assessment.Scenario != assess.ScenarioPrivateHTTPAccessDenied {
			t.Errorf("expected ScenarioPrivateHTTPAccessDenied, got %v", res.Assessment.Scenario)
		}
	})

	t.Run("partial multiple-address result", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:        assess.DNSStatusSuccess,
			QueryHostname: "myvault.vault.azure.net",
			Addresses: []model.IPObservation{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
				{Address: "10.42.3.8", Version: "IPv4", Classification: assess.AddrPrivate},
			},
			AggregateClassification: assess.AggregatePrivateOnly,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7", "10.42.3.8"}}
		tcpObs := model.TCPObservation{
			Status:          assess.TCPStatusPartial,
			AggregateStatus: assess.AggregateTCPPartiallyConnected,
			Port:            443,
			Results: []model.TCPResultItem{
				{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.7:443", Port: 443, Status: assess.TCPAddrConnected},
				{Address: "10.42.3.8", Version: "IPv4", Classification: assess.AddrPrivate, Destination: "10.42.3.8:443", Port: 443, Status: assess.TCPAddrTimedOut, ErrorCategory: "TIMEOUT"},
			},
		}

		res := model.NewResultFromDNSAndTCP(tgt, time.Now(), dnsObs, addrObs, tcpObs)

		if res.Assessment.Scenario != assess.ScenarioPrivateTCPPartial {
			t.Errorf("expected ScenarioPrivateTCPPartial, got %v", res.Assessment.Scenario)
		}
		if len(res.TCP.Results) != 2 {
			t.Errorf("expected 2 TCP results preserved, got %d", len(res.TCP.Results))
		}
	})

	t.Run("terminal and JSON use the same assessment", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:                  assess.DNSStatusNotFound,
			QueryHostname:           "myvault.vault.azure.net",
			ErrorCategory:           "NOT_FOUND",
			ErrorMessage:            "no such host",
			AggregateClassification: assess.AggregateNone,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregateNone}
		res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

		var bufJSON, bufTerm bytes.Buffer
		_ = output.Render(&bufJSON, res, output.FormatOptions{JSON: true})
		_ = output.Render(&bufTerm, res, output.FormatOptions{NoColor: true})

		if !strings.Contains(bufJSON.String(), string(res.Assessment.Scenario)) {
			t.Errorf("JSON output missing scenario %s", res.Assessment.Scenario)
		}
		if !strings.Contains(bufTerm.String(), res.Assessment.Title) {
			t.Errorf("terminal output missing title %s", res.Assessment.Title)
		}
	})

	t.Run("unknown values do not become false", func(t *testing.T) {
		tlsRes := model.TLSResultItem{
			Address:            "10.42.3.7",
			Version:            "IPv4",
			Classification:     assess.AddrPrivate,
			Destination:        "10.42.3.7:443",
			Port:               443,
			ServerName:         "myvault.vault.azure.net",
			Status:             assess.TLSAddrHandshakeFailed,
			HostnameValid:      nil, // unknown/not evaluated
			CertificateTrusted: nil, // unknown/not evaluated
		}

		b, err := json.Marshal(tlsRes)
		if err != nil {
			t.Fatalf("json marshal error: %v", err)
		}
		jsonStr := string(b)
		if strings.Contains(jsonStr, `"hostnameValid":false`) {
			t.Errorf("nil HostnameValid serialized to false!")
		}
		if strings.Contains(jsonStr, `"certificateTrusted":false`) {
			t.Errorf("nil CertificateTrusted serialized to false!")
		}
	})

	t.Run("sanitized target only", func(t *testing.T) {
		rawInput := "https://user:AZPE_PROXY_PASSWORD@myvault.vault.azure.net:8443/keys?sig=AZPE_SECRET_1#section"
		sTgt, err := target.Parse(rawInput)
		if err != nil {
			t.Fatalf("target parse error: %v", err)
		}
		if strings.Contains(sTgt.OriginalInput, "AZPE_PROXY_PASSWORD") || strings.Contains(sTgt.OriginalInput, "AZPE_SECRET_1") {
			t.Errorf("secrets exposed in target.OriginalInput!")
		}
	})

	t.Run("deterministic rendering order", func(t *testing.T) {
		dnsObs := model.DNSObservation{
			Status:        assess.DNSStatusSuccess,
			QueryHostname: "myvault.vault.azure.net",
			Addresses: []model.IPObservation{
				{Address: "10.42.3.1", Version: "IPv4", Classification: assess.AddrPrivate},
				{Address: "10.42.3.2", Version: "IPv4", Classification: assess.AddrPrivate},
			},
			AggregateClassification: assess.AggregatePrivateOnly,
		}
		addrObs := model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.1", "10.42.3.2"}}
		res1 := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)
		res2 := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)

		var buf1, buf2 bytes.Buffer
		_ = output.Render(&buf1, res1, output.FormatOptions{Details: true, NoColor: true})
		_ = output.Render(&buf2, res2, output.FormatOptions{Details: true, NoColor: true})

		if buf1.String() != buf2.String() {
			t.Errorf("nondeterministic rendering order detected!")
		}
	})
}

func TestJSONSchema_AutomatedValidation(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiledSchema, err := compiler.Compile("../../docs/azpe-output-v1.schema.json")
	if err != nil {
		t.Fatalf("failed to compile JSON Schema: %v", err)
	}

	canaries := []string{"AZPE_SECRET_1", "AZPE_PROXY_PASSWORD"}
	rawInput := "https://user:AZPE_PROXY_PASSWORD@myvault.vault.azure.net:8443/keys?sig=AZPE_SECRET_1#section"
	tgtSecret, _ := target.Parse(rawInput)
	tgtPlain, _ := target.Parse("myvault.vault.azure.net")

	bTrue := true

	variants := []struct {
		name string
		res  *model.Result
	}{
		{
			name: "successful HTTP response",
			res: model.NewResultFromDNSAndTCPAndTLSAndHTTP(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}},
				model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected}}},
				model.TLSObservation{Status: assess.TLSStatusSuccess, AggregateStatus: assess.AggregateTLSAllValid, ServerName: "myvault.vault.azure.net", Results: []model.TLSResultItem{{Address: "10.42.3.7", Port: 443, ServerName: "myvault.vault.azure.net", Status: assess.TLSAddrValid, HostnameValid: &bTrue, CertificateTrusted: &bTrue}}},
				model.HTTPObservation{Status: assess.HTTPStatusSuccess, AggregateStatus: assess.AggregateHTTPAllResponded, Method: "GET", Path: "/", Results: []model.HTTPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.HTTPAddrResponded, StatusCode: 200, StatusText: "OK", ResponseCategory: assess.HTTPCatSuccess}}},
			),
		},
		{
			name: "DNS failure",
			res: model.NewResultFromDNS(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusFailure, QueryHostname: "myvault.vault.azure.net", ErrorCategory: "NXDOMAIN", ErrorMessage: "no such host"},
				model.AddrObservation{Classification: assess.AggregatePublicOnly},
			),
		},
		{
			name: "TCP failure",
			res: model.NewResultFromDNSAndTCP(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}},
				model.TCPObservation{Status: assess.TCPStatusFailed, AggregateStatus: assess.AggregateTCPNoneConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrTimedOut}}},
			),
		},
		{
			name: "TLS failure",
			res: model.NewResultFromDNSAndTCPAndTLS(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}},
				model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected}}},
				model.TLSObservation{Status: assess.TLSStatusFailed, AggregateStatus: assess.AggregateTLSNoneValid, ServerName: "myvault.vault.azure.net", Results: []model.TLSResultItem{{Address: "10.42.3.7", Port: 443, ServerName: "myvault.vault.azure.net", Status: assess.TLSAddrUntrustedCertificate}}},
			),
		},
		{
			name: "HTTP 403",
			res: model.NewResultFromDNSAndTCPAndTLSAndHTTP(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}},
				model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected}}},
				model.TLSObservation{Status: assess.TLSStatusSuccess, AggregateStatus: assess.AggregateTLSAllValid, ServerName: "myvault.vault.azure.net", Results: []model.TLSResultItem{{Address: "10.42.3.7", Port: 443, ServerName: "myvault.vault.azure.net", Status: assess.TLSAddrValid, HostnameValid: &bTrue, CertificateTrusted: &bTrue}}},
				model.HTTPObservation{Status: assess.HTTPStatusSuccess, AggregateStatus: assess.AggregateHTTPAllResponded, Method: "GET", Path: "/", Results: []model.HTTPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.HTTPAddrResponded, StatusCode: 403, StatusText: "Forbidden", ResponseCategory: assess.HTTPCatAccessDenied}}},
			),
		},
		{
			name: "redirect",
			res: model.NewResultFromDNSAndTCPAndTLSAndHTTP(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}},
				model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected}}},
				model.TLSObservation{Status: assess.TLSStatusSuccess, AggregateStatus: assess.AggregateTLSAllValid, ServerName: "myvault.vault.azure.net", Results: []model.TLSResultItem{{Address: "10.42.3.7", Port: 443, ServerName: "myvault.vault.azure.net", Status: assess.TLSAddrValid, HostnameValid: &bTrue, CertificateTrusted: &bTrue}}},
				model.HTTPObservation{Status: assess.HTTPStatusSuccess, AggregateStatus: assess.AggregateHTTPAllResponded, Method: "GET", Path: "/", Results: []model.HTTPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.HTTPAddrResponded, StatusCode: 301, StatusText: "Moved Permanently", ResponseCategory: assess.HTTPCatRedirection}}},
			),
		},
		{
			name: "multiple addresses",
			res: model.NewResultFromDNSAndTCPAndTLSAndHTTP(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}, {Address: "10.42.3.8", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7", "10.42.3.8"}},
				model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected}, {Address: "10.42.3.8", Port: 443, Status: assess.TCPAddrConnected}}},
				model.TLSObservation{Status: assess.TLSStatusSuccess, AggregateStatus: assess.AggregateTLSAllValid, ServerName: "myvault.vault.azure.net", Results: []model.TLSResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TLSAddrValid}, {Address: "10.42.3.8", Port: 443, Status: assess.TLSAddrValid}}},
				model.HTTPObservation{Status: assess.HTTPStatusSuccess, AggregateStatus: assess.AggregateHTTPAllResponded, Method: "GET", Path: "/", Results: []model.HTTPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.HTTPAddrResponded, StatusCode: 200}, {Address: "10.42.3.8", Port: 443, Status: assess.HTTPAddrResponded, StatusCode: 200}}},
			),
		},
		{
			name: "partial success",
			res: model.NewResultFromDNSAndTCP(
				tgtPlain, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}, {Address: "10.42.3.8", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7", "10.42.3.8"}},
				model.TCPObservation{Status: assess.TCPStatusPartial, AggregateStatus: assess.AggregateTCPPartiallyConnected, Port: 443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected}, {Address: "10.42.3.8", Port: 443, Status: assess.TCPAddrTimedOut}}},
			),
		},
		{
			name: "target with redacted query values",
			res: model.NewResultFromDNSAndTCPAndTLSAndHTTP(
				tgtSecret, time.Now(),
				model.DNSObservation{Status: assess.DNSStatusSuccess, QueryHostname: "myvault.vault.azure.net", Addresses: []model.IPObservation{{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate}}, AggregateClassification: assess.AggregatePrivateOnly},
				model.AddrObservation{Classification: assess.AggregatePrivateOnly, PrivateIPs: []string{"10.42.3.7"}},
				model.TCPObservation{Status: assess.TCPStatusSuccess, AggregateStatus: assess.AggregateTCPAllConnected, Port: 8443, Results: []model.TCPResultItem{{Address: "10.42.3.7", Port: 8443, Status: assess.TCPAddrConnected}}},
				model.TLSObservation{Status: assess.TLSStatusSuccess, AggregateStatus: assess.AggregateTLSAllValid, ServerName: "myvault.vault.azure.net", Results: []model.TLSResultItem{{Address: "10.42.3.7", Port: 8443, Status: assess.TLSAddrValid}}},
				model.HTTPObservation{Status: assess.HTTPStatusSuccess, AggregateStatus: assess.AggregateHTTPAllResponded, Method: "GET", Path: tgtSecret.RequestPath, Results: []model.HTTPResultItem{{Address: "10.42.3.7", Port: 8443, Status: assess.HTTPAddrResponded, StatusCode: 403, StatusText: "Forbidden"}}},
			),
		},
	}

	for _, tt := range variants {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := output.Render(&buf, tt.res, output.FormatOptions{JSON: true})
			if err != nil {
				t.Fatalf("unexpected render error: %v", err)
			}

			jsonStr := buf.String()

			// 1. Unmarshal JSON into interface{}
			var unmarshaled interface{}
			if err := json.Unmarshal([]byte(jsonStr), &unmarshaled); err != nil {
				t.Fatalf("rendered output is not valid JSON: %v", err)
			}

			// 2. Validate against JSON Schema
			if err := compiledSchema.Validate(unmarshaled); err != nil {
				t.Errorf("JSON Schema validation failed for variant %q: %v\nJSON:\n%s", tt.name, err, jsonStr)
			}

			// 3. Assert schemaVersion == 1
			parsedMap, ok := unmarshaled.(map[string]interface{})
			if !ok {
				t.Fatalf("expected map[string]interface{} for top-level JSON")
			}
			if ver, ok := parsedMap["schemaVersion"].(float64); !ok || ver != 1 {
				t.Errorf("expected schemaVersion 1, got %v", parsedMap["schemaVersion"])
			}

			// 4. Assert no secret canary appears
			for _, canary := range canaries {
				if strings.Contains(jsonStr, canary) {
					t.Errorf("secret canary %q leaked in JSON output for variant %q", canary, tt.name)
				}
			}
		})
	}
}
