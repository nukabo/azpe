package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/target"
)

func TestSanitizeLocationAndQueryValues(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "/path",
			expected: "/path",
		},
		{
			input:    "/path?sig=secret&api-version=2024-01-01",
			expected: "/path?sig=REDACTED&api-version=REDACTED",
		},
		{
			input:    "https://user:password@example.com/path?token=secret#frag",
			expected: "https://example.com/path?token=REDACTED#frag",
		},
		{
			input:    "https://admin:pass123@vault.azure.net:443/keys?api-version=7.0",
			expected: "https://vault.azure.net:443/keys?api-version=REDACTED",
		},
	}

	for _, tt := range tests {
		got := target.SanitizeLocation(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeLocation(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCategorizeStatusCode(t *testing.T) {
	tests := []struct {
		code     int
		expected assess.HTTPResponseCategory
	}{
		{200, assess.HTTPCatSuccess},
		{204, assess.HTTPCatSuccess},
		{301, assess.HTTPCatRedirection},
		{302, assess.HTTPCatRedirection},
		{303, assess.HTTPCatRedirection},
		{307, assess.HTTPCatRedirection},
		{308, assess.HTTPCatRedirection},
		{400, assess.HTTPCatClientError},
		{401, assess.HTTPCatAuthenticationRequired},
		{403, assess.HTTPCatAccessDenied},
		{404, assess.HTTPCatNotFound},
		{405, assess.HTTPCatMethodNotAllowed},
		{409, assess.HTTPCatConflict},
		{429, assess.HTTPCatThrottled},
		{500, assess.HTTPCatServerError},
		{503, assess.HTTPCatServerError},
	}

	for _, tt := range tests {
		got := CategorizeStatusCode(tt.code)
		if got != tt.expected {
			t.Errorf("CategorizeStatusCode(%d) = %v, want %v", tt.code, got, tt.expected)
		}
	}
}

func TestProductionCode_SecuritySearchInvariants(t *testing.T) {
	files, err := filepath.Glob("../../*/*.go")
	if err != nil {
		t.Fatalf("failed to glob go files: %v", err)
	}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		contentBytes, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(contentBytes)

		if strings.Contains(content, "InsecureSkipVerify: true") {
			t.Errorf("SECURITY VIOLATION: File %s contains InsecureSkipVerify: true", f)
		}
		if strings.Contains(content, "ProxyFromEnvironment") {
			t.Errorf("SECURITY VIOLATION: File %s uses ProxyFromEnvironment", f)
		}
		if strings.Contains(content, "http.DefaultClient") {
			t.Errorf("DESIGN VIOLATION: File %s uses global http.DefaultClient", f)
		}
		if strings.Contains(content, "http.Get(") {
			t.Errorf("DESIGN VIOLATION: File %s uses unconfigured http.Get", f)
		}
	}
}

func generateTestCAAndCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AZPE Test HTTP Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyBytes, _ := x509.MarshalECPrivateKey(serverPrivKey)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})

	tlsCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse X509 key pair: %v", err)
	}

	return tlsCert, rootPool
}

func TestLocalHTTPSServer_Integration_RedirectsAndProxyBypass(t *testing.T) {
	serverName := "test.vault.azure.net"
	tlsCert, rootPool := generateTestCAAndCert(t, serverName)

	var origServerReqs int64
	var proxyReqs int64

	// Spin up fake proxy server
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}
	defer proxyListener.Close()

	proxyServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&proxyReqs, 1)
			w.WriteHeader(http.StatusBadGateway)
		}),
	}
	go func() { _ = proxyServer.Serve(proxyListener) }()
	defer proxyServer.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/301", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&origServerReqs, 1)
		verifyHTTPRequest(t, r, serverName)
		w.Header().Set("Location", "https://user:password@redirect-target.example/path?key=secret")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	mux.HandleFunc("/302", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&origServerReqs, 1)
		verifyHTTPRequest(t, r, serverName)
		w.Header().Set("Location", "https://redirect-target.example/path?key=secret")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/307", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&origServerReqs, 1)
		verifyHTTPRequest(t, r, serverName)
		w.Header().Set("Location", "https://redirect-target.example/path?key=secret")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/308", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&origServerReqs, 1)
		verifyHTTPRequest(t, r, serverName)
		w.Header().Set("Location", "https://redirect-target.example/path?key=secret")
		w.WriteHeader(http.StatusPermanentRedirect)
	})

	server := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = server.ServeTLS(listener, "", "")
	}()
	defer server.Close()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Set ALL proxy env vars to fake proxy address to prove complete proxy bypass!
	proxyAddr := "http://" + proxyListener.Addr().String()
	os.Setenv("HTTP_PROXY", proxyAddr)
	os.Setenv("HTTPS_PROXY", proxyAddr)
	os.Setenv("ALL_PROXY", proxyAddr)
	os.Setenv("http_proxy", proxyAddr)
	os.Setenv("https_proxy", proxyAddr)
	os.Setenv("all_proxy", proxyAddr)
	defer func() {
		os.Unsetenv("HTTP_PROXY")
		os.Unsetenv("HTTPS_PROXY")
		os.Unsetenv("ALL_PROXY")
		os.Unsetenv("http_proxy")
		os.Unsetenv("https_proxy")
		os.Unsetenv("all_proxy")
	}()

	prober := &OSHTTPProber{RootCAs: rootPool}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	redirectPaths := []string{"/301", "/302", "/307", "/308"}
	for _, p := range redirectPaths {
		atomic.StoreInt64(&origServerReqs, 0)
		res := prober.ProbeHTTP(ctx, host, port, serverName, p, "https")

		if res.Status != assess.HTTPAddrResponded {
			t.Errorf("path %s: expected HTTPAddrResponded, got %v", p, res.Status)
		}
		if res.RedirectFollowed {
			t.Errorf("path %s: expected RedirectFollowed = false", p)
		}
		if atomic.LoadInt64(&origServerReqs) != 1 {
			t.Errorf("path %s: expected exactly 1 request to original server, got %d", p, atomic.LoadInt64(&origServerReqs))
		}
		if res.Headers == nil || !strings.Contains(res.Headers.Location, "REDACTED") || strings.Contains(res.Headers.Location, "password") {
			t.Errorf("path %s: expected sanitized Location header, got %v", p, res.Headers)
		}
	}

	if atomic.LoadInt64(&proxyReqs) != 0 {
		t.Errorf("PROXY BYPASS FAILURE: fake proxy received %d requests, want 0", atomic.LoadInt64(&proxyReqs))
	}
}

func verifyHTTPRequest(t *testing.T, r *http.Request, expectedHost string) {
	t.Helper()
	if r.Method != "GET" {
		t.Errorf("expected GET method, got %s", r.Method)
	}
	if !strings.HasPrefix(r.Host, expectedHost) {
		t.Errorf("expected Host header starting with %s, got %s", expectedHost, r.Host)
	}
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "azpe/") {
		t.Errorf("expected User-Agent starting with azpe/, got %s", r.Header.Get("User-Agent"))
	}
	if r.Header.Get("Accept-Encoding") != "identity" {
		t.Errorf("expected Accept-Encoding: identity, got %s", r.Header.Get("Accept-Encoding"))
	}
	if r.Header.Get("Authorization") != "" {
		t.Errorf("SECURITY VIOLATION: Request contains Authorization header")
	}
	if r.Header.Get("Cookie") != "" {
		t.Errorf("SECURITY VIOLATION: Request contains Cookie header")
	}
}
