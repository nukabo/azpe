package target_test

import (
	"strings"
	"testing"

	"github.com/nukabo/azpe/internal/target"
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
			wantPath:   "/api?version=REDACTED",
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
			name:       "embedded credentials with username",
			input:      "https://admin@myvault.vault.azure.net",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/",
		},
		{
			name:       "embedded credentials username and password",
			input:      "https://admin:secret@myvault.vault.azure.net",
			wantErr:    false,
			wantScheme: "https",
			wantHost:   "myvault.vault.azure.net",
			wantPort:   443,
			wantPath:   "/",
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

func TestRedactionAndSanitization(t *testing.T) {
	canaries := []string{"AZPE_SECRET_1", "AZPE_SECRET_2", "AZPE_PROXY_PASSWORD"}

	tests := []struct {
		name                 string
		input                string
		wantSanitizedDisplay string
		wantRedactedPath     string
		wantRawPath          string
	}{
		{
			name:                 "no query",
			input:                "https://myvault.vault.azure.net/path",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path",
			wantRedactedPath:     "/path",
			wantRawPath:          "/path",
		},
		{
			name:                 "one query parameter",
			input:                "https://myvault.vault.azure.net/path?sig=AZPE_SECRET_1",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1",
		},
		{
			name:                 "multiple parameters",
			input:                "https://myvault.vault.azure.net/path?sig=AZPE_SECRET_1&mode=read",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED&mode=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED&mode=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1&mode=read",
		},
		{
			name:                 "empty parameter value",
			input:                "https://myvault.vault.azure.net/path?sig=",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=",
		},
		{
			name:                 "duplicate parameter names",
			input:                "https://myvault.vault.azure.net/path?sig=AZPE_SECRET_1&sig=AZPE_SECRET_2",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED&sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED&sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1&sig=AZPE_SECRET_2",
		},
		{
			name:                 "percent-encoded value",
			input:                "https://myvault.vault.azure.net/path?sig=AZPE%20SECRET%201",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE%20SECRET%201",
		},
		{
			name:                 "nested URL as value",
			input:                "https://myvault.vault.azure.net/path?redirect=https%3A%2F%2Fprivate.example%2F%3Ftoken%3DAZPE_SECRET_1",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?redirect=REDACTED",
			wantRedactedPath:     "/path?redirect=REDACTED",
			wantRawPath:          "/path?redirect=https%3A%2F%2Fprivate.example%2F%3Ftoken%3DAZPE_SECRET_1",
		},
		{
			name:                 "URL user and password",
			input:                "https://user:AZPE_PROXY_PASSWORD@myvault.vault.azure.net/path?sig=AZPE_SECRET_1",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1",
		},
		{
			name:                 "fragment",
			input:                "https://myvault.vault.azure.net/path?sig=AZPE_SECRET_1#section",
			wantSanitizedDisplay: "https://myvault.vault.azure.net/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1",
		},
		{
			name:                 "IPv4 host",
			input:                "http://10.0.0.4:8080/path?sig=AZPE_SECRET_1",
			wantSanitizedDisplay: "http://10.0.0.4:8080/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1",
		},
		{
			name:                 "bracketed IPv6 host",
			input:                "https://[fd00::1]:8443/path?sig=AZPE_SECRET_1",
			wantSanitizedDisplay: "https://[fd00::1]:8443/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1",
		},
		{
			name:                 "explicit port",
			input:                "https://myvault.vault.azure.net:8443/path?sig=AZPE_SECRET_1",
			wantSanitizedDisplay: "https://myvault.vault.azure.net:8443/path?sig=REDACTED",
			wantRedactedPath:     "/path?sig=REDACTED",
			wantRawPath:          "/path?sig=AZPE_SECRET_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt, err := target.Parse(tt.input)
			if err != nil {
				t.Fatalf("unexpected Parse error: %v", err)
			}

			if tgt.OriginalInput != tt.wantSanitizedDisplay {
				t.Errorf("OriginalInput = %q, want %q", tgt.OriginalInput, tt.wantSanitizedDisplay)
			}
			if tgt.RequestPath != tt.wantRedactedPath {
				t.Errorf("RequestPath = %q, want %q", tgt.RequestPath, tt.wantRedactedPath)
			}
			if tgt.RawRequestPath() != tt.wantRawPath {
				t.Errorf("RawRequestPath() = %q, want %q", tgt.RawRequestPath(), tt.wantRawPath)
			}

			for _, canary := range canaries {
				if strings.Contains(tgt.OriginalInput, canary) {
					t.Errorf("canary %q leaked in OriginalInput: %q", canary, tgt.OriginalInput)
				}
				if strings.Contains(tgt.RequestPath, canary) {
					t.Errorf("canary %q leaked in RequestPath: %q", canary, tgt.RequestPath)
				}
			}
		})
	}
}

func TestSanitizeErrorAndRedirect(t *testing.T) {
	canaries := []string{"AZPE_SECRET_1", "AZPE_SECRET_2", "AZPE_PROXY_PASSWORD"}

	t.Run("sanitized error", func(t *testing.T) {
		errStr := `Get "https://user:AZPE_PROXY_PASSWORD@myvault.vault.azure.net/path?sig=AZPE_SECRET_1": dial tcp: connection refused`
		sanitized := target.SanitizeErrorString(errStr)
		for _, canary := range canaries {
			if strings.Contains(sanitized, canary) {
				t.Errorf("canary %q leaked in sanitized error: %q", canary, sanitized)
			}
		}
	})

	t.Run("sanitized redirect location", func(t *testing.T) {
		locHeader := "https://user:AZPE_PROXY_PASSWORD@redirect.target/path?token=AZPE_SECRET_2#section"
		sanitized := target.SanitizeLocation(locHeader)
		for _, canary := range canaries {
			if strings.Contains(sanitized, canary) {
				t.Errorf("canary %q leaked in sanitized location header: %q", canary, sanitized)
			}
		}
	})

	t.Run("malformed URL sanitization", func(t *testing.T) {
		malformed := "https://%invalid-url%/path?sig=AZPE_SECRET_1"
		sanitized := target.SanitizeTargetString(malformed)
		for _, canary := range canaries {
			if strings.Contains(sanitized, canary) {
				t.Errorf("canary %q leaked in malformed URL sanitization: %q", canary, sanitized)
			}
		}
	})
}

func TestPart5_ExactCanaries(t *testing.T) {
	exactCanaries := []string{
		"AZPE_VERIFY_QUERY_SECRET",
		"AZPE_VERIFY_PASSWORD_SECRET",
		"AZPE_VERIFY_NESTED_SECRET",
		"AZPE_VERIFY_REDIRECT_SECRET",
	}

	inputs := []string{
		"https://example.test/path?sig=AZPE_VERIFY_QUERY_SECRET",
		"https://user:AZPE_VERIFY_PASSWORD_SECRET@example.test/path",
		"https://example.test/path?redirect=https%3A%2F%2Fprivate.example%2F%3Ftoken%3DAZPE_VERIFY_NESTED_SECRET",
		"https://example.test/start?next=https%3A%2F%2Fother.example%2F%3Fsig%3DAZPE_VERIFY_REDIRECT_SECRET",
	}

	for _, input := range inputs {
		tgt, err := target.Parse(input)
		if err != nil {
			t.Fatalf("unexpected parse error for %q: %v", input, err)
		}

		for _, canary := range exactCanaries {
			if strings.Contains(tgt.OriginalInput, canary) {
				t.Errorf("canary %q leaked in OriginalInput: %q", canary, tgt.OriginalInput)
			}
			if strings.Contains(tgt.RequestPath, canary) {
				t.Errorf("canary %q leaked in RequestPath: %q", canary, tgt.RequestPath)
			}
		}
	}
}
