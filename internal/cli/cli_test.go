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
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/tcp"
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

func TestCLIRoutingWithFakeResolverAndProber(t *testing.T) {
	fakeResolver := &FakeResolver{
		Addrs: map[string][]netip.Addr{
			"private.vault.azure.net": {netip.MustParseAddr("10.0.0.1")},
			"multi.vault.azure.net":   {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
			"failed.vault.azure.net":  {netip.MustParseAddr("10.0.0.3")},
			"partial.vault.azure.net": {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.3")},
			"public.vault.azure.net":  {netip.MustParseAddr("20.42.64.44")},
			"mixed.vault.azure.net":   {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("20.42.64.44")},
			"microsoft.com":           {netip.MustParseAddr("150.171.109.193")},
		},
		Err: map[string]error{
			"nonexistent.vault.azure.net": &net.DNSError{Err: "no such host", Name: "nonexistent.vault.azure.net", IsNotFound: true},
		},
	}

	fakeProber := &tcp.FakeProber{
		Responses: map[string]model.TCPResultItem{
			"10.0.0.1": {
				Address:     "10.0.0.1",
				Destination: "10.0.0.1:443",
				Status:      assess.TCPAddrConnected,
				DurationMs:  8,
			},
			"10.0.0.2": {
				Address:     "10.0.0.2",
				Destination: "10.0.0.2:443",
				Status:      assess.TCPAddrConnected,
				DurationMs:  12,
			},
			"10.0.0.3": {
				Address:       "10.0.0.3",
				Destination:   "10.0.0.3:443",
				Status:        assess.TCPAddrTimedOut,
				DurationMs:    5001,
				ErrorCategory: "TIMEOUT",
				Error:         "dial tcp 10.0.0.3:443: i/o timeout",
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
			name:       "probe missing target",
			args:       []string{"probe"},
			wantExit:   cli.ExitUsageOrTargetError,
			wantStderr: "missing target for probe command",
		},
		{
			name:       "probe invalid target",
			args:       []string{"probe", "invalid://scheme"},
			wantExit:   cli.ExitUsageOrTargetError,
			wantStderr: "unsupported scheme \"invalid\"",
		},
		{
			name:       "recognized Azure private target single IP success exit 0",
			args:       []string{"probe", "private.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "✓ Private connection is reachable",
		},
		{
			name:       "recognized Azure private target multi IP success exit 0",
			args:       []string{"probe", "multi.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "✓ Private connections are reachable",
		},
		{
			name:       "recognized Azure private target TCP failure exit 5",
			args:       []string{"probe", "failed.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitTCPFailure,
			wantStdout: "✗ The private address cannot be reached",
		},
		{
			name:       "recognized Azure private target partial TCP exit 8",
			args:       []string{"probe", "partial.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitInconclusive,
			wantStdout: "⚠ Some private addresses cannot be reached",
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
			name:       "IPv4 literal exit 8 (ExitInconclusive)",
			args:       []string{"probe", "10.0.0.1", "--no-color"},
			wantExit:   cli.ExitInconclusive,
			wantStdout: "The Azure service hostname is required",
		},
		{
			name:       "generic microsoft.com hostname exit 8 (ExitInconclusive)",
			args:       []string{"probe", "microsoft.com", "--no-color"},
			wantExit:   cli.ExitInconclusive,
			wantStdout: "Cannot test this target",
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
			wantStdout: "=== Connection ===",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := cli.RunWithResolverAndProber(tt.args, &stdout, &stderr, fakeResolver, fakeProber)

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

func TestCLI_UnknownFlag(t *testing.T) {
	fakeResolver := &FakeResolver{}
	fakeProber := &tcp.FakeProber{}
	var stdout, stderr bytes.Buffer
	exitCode := cli.RunWithResolverAndProber([]string{"probe", "private.vault.azure.net", "--unknown-flag"}, &stdout, &stderr, fakeResolver, fakeProber)

	if exitCode != cli.ExitUsageOrTargetError {
		t.Errorf("expected exit code %d for unknown flag, got %d", cli.ExitUsageOrTargetError, exitCode)
	}
}
