package target_test

import (
	"testing"

	"github.com/azpe/azpe/internal/target"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantScheme string
		wantHost   string
		wantPort   int
		wantPath   string
	}{
		{
			name:       "plain hostname",
			input:      "myvault.vault.azure.net",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/",
		},
		{
			name:       "hostname with port",
			input:      "myvault.vault.azure.net:443",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/",
		},
		{
			name:       "hostname with non-standard port",
			input:      "myvault.vault.azure.net:8443",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   8443,
			wantPath:   "/",
		},
		{
			name:       "HTTPS URL",
			input:      "https://myvault.vault.azure.net",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/",
		},
		{
			name:       "HTTP URL",
			input:      "http://myvault.vault.azure.net",
			wantErr:    false,
			wantScheme: "http",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   80,
			wantPath:   "/",
		},
		{
			name:       "URL with path",
			input:      "https://myvault.vault.azure.net/some/path",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/some/path",
		},
		{
			name:       "URL with query string",
			input:      "https://myvault.vault.azure.net/api?version=2023-01-01",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/api?version=2023-01-01",
		},
		{
			name:       "IPv4 literal",
			input:      "10.0.0.4",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "10.0.0.4",
			wantPort:   443,
			wantPath:   "/",
		},
		{
			name:       "IPv4 literal with port",
			input:      "10.0.0.4:8443",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "10.0.0.4",
			wantPort:   8443,
			wantPath:   "/",
		},
		{
			name:       "IPv6 literal bare",
			input:      "fd00::1",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "fd00::1",
			wantPort:   443,
			wantPath:   "/",
		},
		{
			name:       "IPv6 literal bracketed with port",
			input:      "[fd00::1]:8443",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "fd00::1",
			wantPort:   8443,
			wantPath:   "/",
		},
		{
			name:    "empty target",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only target",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "unsupported scheme ftp",
			input:   "ftp://myvault.vault.azure.net",
			wantErr: true,
		},
		{
			name:    "unsupported scheme ssh",
			input:   "ssh://myvault.vault.azure.net",
			wantErr: true,
		},
		{
			name:    "embedded credentials with username",
			input:   "https://admin@myvault.vault.azure.net",
			wantErr: true,
		},
		{
			name:    "embedded credentials username and password",
			input:   "https://admin:secret@myvault.vault.azure.net",
			wantErr: true,
		},
		{
			name:    "invalid port 0",
			input:   "myvault.vault.azure.net:0",
			wantErr: true,
		},
		{
			name:    "invalid port 70000",
			input:   "myvault.vault.azure.net:70000",
			wantErr: true,
		},
		{
			name:    "non numeric port",
			input:   "myvault.vault.azure.net:abc",
			wantErr: true,
		},
		{
			name:    "malformed hostname invalid char",
			input:   "my_vault!.vault.azure.net",
			wantErr: true,
		},
		{
			name:    "malformed hostname leading hyphen label",
			input:   "-myvault.vault.azure.net",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := target.Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if res.OriginalInput != tt.input {
				t.Errorf("OriginalInput = %q, want %q", res.OriginalInput, tt.input)
			}
			if res.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", res.Scheme, tt.wantScheme)
			}
			if res.Hostname != tt.wantHost {
				t.Errorf("Hostname = %q, want %q", res.Hostname, tt.wantHost)
			}
			if res.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", res.Port, tt.wantPort)
			}
			if res.RequestPath != tt.wantPath {
				t.Errorf("RequestPath = %q, want %q", res.RequestPath, tt.wantPath)
			}
		})
	}
}
