package cli_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/cli"
	"github.com/azpe/azpe/internal/http"
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/tcp"
	"github.com/azpe/azpe/internal/tls"
)

type FakeResolver struct {
	Addrs map[string][]netip.Addr
	Err   map[string]error
}

func (f *FakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err, ok := f.Err[host]; ok && err != nil {
		return nil, err
	}
	if addrs, ok := f.Addrs[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestCLIRoutingWithFakeResolverAndProbers(t *testing.T) {
	fakeResolver := &FakeResolver{
		Addrs: map[string][]netip.Addr{
			"private.vault.azure.net":  {netip.MustParseAddr("10.0.0.1")},
			"multi.vault.azure.net":    {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
			"failed.vault.azure.net":   {netip.MustParseAddr("10.0.0.3")},
			"tlsfail.vault.azure.net":  {netip.MustParseAddr("10.0.0.4")},
			"httpfail.vault.azure.net": {netip.MustParseAddr("10.0.0.5")},
			"public.vault.azure.net":   {netip.MustParseAddr("20.42.64.44")},
			"mixed.vault.azure.net":    {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("20.42.64.44")},
			"microsoft.com":            {netip.MustParseAddr("150.171.109.193")},
		},
		Err: map[string]error{
			"nonexistent.vault.azure.net": &net.DNSError{Err: "no such host", Name: "nonexistent.vault.azure.net", IsNotFound: true},
		},
	}

	fakeProber := &tcp.FakeProber{
		Responses: map[string]model.TCPResultItem{
			"10.0.0.1": {Address: "10.0.0.1", Destination: "10.0.0.1:443", Status: assess.TCPAddrConnected, DurationMs: 8},
			"10.0.0.2": {Address: "10.0.0.2", Destination: "10.0.0.2:443", Status: assess.TCPAddrConnected, DurationMs: 12},
			"10.0.0.3": {Address: "10.0.0.3", Destination: "10.0.0.3:443", Status: assess.TCPAddrTimedOut, DurationMs: 5001, ErrorCategory: "TIMEOUT"},
			"10.0.0.4": {Address: "10.0.0.4", Destination: "10.0.0.4:443", Status: assess.TCPAddrConnected, DurationMs: 6},
			"10.0.0.5": {Address: "10.0.0.5", Destination: "10.0.0.5:443", Status: assess.TCPAddrConnected, DurationMs: 6},
		},
	}

	bTrue := true
	fakeTLSProber := &tls.FakeProber{
		Responses: map[string]model.TLSResultItem{
			"10.0.0.1": {
				Address:            "10.0.0.1",
				Destination:        "10.0.0.1:443",
				Status:             assess.TLSAddrValid,
				DurationMs:         15,
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
			},
			"10.0.0.2": {
				Address:            "10.0.0.2",
				Destination:        "10.0.0.2:443",
				Status:             assess.TLSAddrValid,
				DurationMs:         18,
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
			},
			"10.0.0.4": {
				Address:       "10.0.0.4",
				Destination:   "10.0.0.4:443",
				Status:        assess.TLSAddrHostnameMismatch,
				DurationMs:    22,
				ErrorCategory: "HOSTNAME_MISMATCH",
				Error:         "x509: certificate is valid for wrong.vault.azure.net, not tlsfail.vault.azure.net",
			},
			"10.0.0.5": {
				Address:            "10.0.0.5",
				Destination:        "10.0.0.5:443",
				Status:             assess.TLSAddrValid,
				DurationMs:         15,
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
			},
		},
	}

	fakeHTTPProber := &http.FakeProber{
		Responses: map[string]model.HTTPResultItem{
			"10.0.0.1": {
				Address:          "10.0.0.1",
				Destination:      "10.0.0.1:443",
				Status:           assess.HTTPAddrResponded,
				StatusCode:       403,
				StatusText:       "Forbidden",
				ResponseCategory: assess.HTTPCatAccessDenied,
				DurationMs:       24,
			},
			"10.0.0.2": {
				Address:          "10.0.0.2",
				Destination:      "10.0.0.2:443",
				Status:           assess.HTTPAddrResponded,
				StatusCode:       403,
				StatusText:       "Forbidden",
				ResponseCategory: assess.HTTPCatAccessDenied,
				DurationMs:       28,
			},
			"10.0.0.5": {
				Address:          "10.0.0.5",
				Destination:      "10.0.0.5:443",
				Status:           assess.HTTPAddrTimeout,
				ResponseCategory: assess.HTTPCatNoResponse,
				DurationMs:       5000,
				FailureStage:     "RESPONSE",
				ErrorCategory:    "TIMEOUT",
				Error:            "context deadline exceeded",
			},
		},
	}

	tests := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no args shows help",
			args:       []string{},
			wantExit:   cli.ExitSuccess,
			wantStdout: "AZPE - Azure Private Endpoint Connectivity Diagnostic Utility",
		},
		{
			name:       "flag --version",
			args:       []string{"--version"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "AZPE version",
		},
		{
			name:       "recognized Azure private target HTTP 403 exit 0",
			args:       []string{"probe", "private.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "✓ The Azure service responded",
		},
		{
			name:       "recognized Azure private target --no-http exit 0",
			args:       []string{"probe", "private.vault.azure.net", "--no-http", "--no-color"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "✓ Secure private connection looks correct",
		},
		{
			name:       "recognized Azure private target TCP failure exit 5",
			args:       []string{"probe", "failed.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitTCPFailure,
			wantStdout: "✗ The private address cannot be reached",
		},
		{
			name:       "recognized Azure private target TLS failure exit 6 (ExitTLSFailure)",
			args:       []string{"probe", "tlsfail.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitTLSFailure,
			wantStdout: "✗ The certificate does not match the Azure service name",
		},
		{
			name:       "recognized Azure private target HTTP timeout exit 7 (ExitHTTPFailure)",
			args:       []string{"probe", "httpfail.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitHTTPFailure,
			wantStdout: "✗ The Azure service did not respond in time",
		},
		{
			name:       "recognized Azure public target exit 4 (ExitNotPrivate)",
			args:       []string{"probe", "public.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitNotPrivate,
			wantStdout: "✗ This workload is not using private DNS",
		},
		{
			name:       "recognized Azure DNS failure exit 3 (ExitDNSFailure)",
			args:       []string{"probe", "nonexistent.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitDNSFailure,
			wantStdout: "✗ The Azure service name cannot be resolved",
		},
		{
			name:       "mixed private/public target exit 8 (ExitInconclusive)",
			args:       []string{"probe", "mixed.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitInconclusive,
			wantStdout: "⚠ DNS is returning both private and public addresses",
		},
		{
			name:       "probe JSON output",
			args:       []string{"probe", "private.vault.azure.net", "--json"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "\"schemaVersion\": 1",
		},
		{
			name:       "probe details output",
			args:       []string{"probe", "private.vault.azure.net", "--details", "--no-color"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "=== HTTP ===",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := cli.RunWithResolverProberTLSProberAndHTTPProber(tt.args, &stdout, &stderr, fakeResolver, fakeProber, fakeTLSProber, fakeHTTPProber)

			if exitCode != tt.wantExit {
				t.Errorf("cli.Run(%v) exit code = %d, want %d. Stderr: %s", tt.args, exitCode, tt.wantExit, stderr.String())
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, expected substring %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, expected substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestCLI_NoCustomTrustStoreOrBypassFlags(t *testing.T) {
	bannedFlags := []string{
		"--ca-cert",
		"--ca-file",
		"--custom-ca",
		"--root-ca",
		"--trust-store",
		"--insecure",
		"--skip-verify",
		"--tls-skip-verify",
	}

	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"--help"}, &stdout, &stderr)
	if exitCode != cli.ExitSuccess {
		t.Fatalf("help command failed with exit %d", exitCode)
	}

	helpOutput := stdout.String()
	for _, flag := range bannedFlags {
		if strings.Contains(helpOutput, flag) {
			t.Errorf("SECURITY/DESIGN VIOLATION: CLI help text exposes custom trust store or bypass flag %s", flag)
		}
	}
}
