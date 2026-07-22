package cli_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/azpe/azpe/internal/cli"
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

func TestCLIRoutingWithFakeResolver(t *testing.T) {
	fake := &FakeResolver{
		Addrs: map[string][]netip.Addr{
			"private.vault.azure.net": {netip.MustParseAddr("10.0.0.1")},
			"public.vault.azure.net":  {netip.MustParseAddr("20.42.64.44")},
			"mixed.vault.azure.net":   {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("20.42.64.44")},
			"microsoft.com":           {netip.MustParseAddr("150.171.109.193")},
		},
		Err: map[string]error{
			"nonexistent.vault.azure.net": &net.DNSError{Err: "no such host", Name: "nonexistent.vault.azure.net", IsNotFound: true},
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
			name:       "recognized Azure private target exit 0",
			args:       []string{"probe", "private.vault.azure.net", "--no-color"},
			wantExit:   cli.ExitSuccess,
			wantStdout: "✓ Private DNS looks correct",
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
			name:       "IPv6 literal exit 8 (ExitInconclusive)",
			args:       []string{"probe", "[fd00::1]", "--no-color"},
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
			wantStdout: "=== Target ===",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := cli.RunWithResolver(tt.args, &stdout, &stderr, fake)

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
	fake := &FakeResolver{}
	var stdout, stderr bytes.Buffer
	exitCode := cli.RunWithResolver([]string{"probe", "private.vault.azure.net", "--unknown-flag"}, &stdout, &stderr, fake)

	if exitCode != cli.ExitUsageOrTargetError {
		t.Errorf("expected exit code %d for unknown flag, got %d", cli.ExitUsageOrTargetError, exitCode)
	}
}
