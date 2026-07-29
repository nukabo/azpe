package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nukabo/azpe/internal/assess"
	"github.com/nukabo/azpe/internal/model"
)

func TestFakeProber_TLSValidAndFailed(t *testing.T) {
	bTrue := true
	bFalse := false
	fake := &FakeProber{
		Responses: map[string]model.TLSResultItem{
			"10.42.3.7": {
				Address:            "10.42.3.7",
				Status:             assess.TLSAddrValid,
				DurationMs:         15,
				HostnameValid:      &bTrue,
				CertificateTrusted: &bTrue,
			},
			"10.42.3.8": {
				Address:            "10.42.3.8",
				Status:             assess.TLSAddrUntrustedCertificate,
				DurationMs:         20,
				HostnameValid:      &bTrue,
				CertificateTrusted: &bFalse,
				ErrorCategory:      "UNTRUSTED_CERTIFICATE",
				Error:              "x509: certificate signed by unknown authority",
			},
		},
	}

	tcpObs := model.TCPObservation{
		Status:          assess.TCPStatusSuccess,
		AggregateStatus: assess.AggregateTCPAllConnected,
		Port:            443,
		Results: []model.TCPResultItem{
			{Address: "10.42.3.7", Port: 443, Status: assess.TCPAddrConnected},
			{Address: "10.42.3.8", Port: 443, Status: assess.TCPAddrConnected},
		},
	}

	ctx := context.Background()
	obs := ProbeAll(ctx, fake, tcpObs, "myvault.vault.azure.net")

	if obs.Status != assess.TLSStatusPartial {
		t.Errorf("expected TLSStatusPartial, got %v", obs.Status)
	}
	if obs.AggregateStatus != assess.AggregateTLSPartiallyValid {
		t.Errorf("expected AggregateTLSPartiallyValid, got %v", obs.AggregateStatus)
	}
	if len(obs.Results) != 2 {
		t.Fatalf("expected 2 TLS results, got %d", len(obs.Results))
	}
}

func TestCategorizeTLSError(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		expectedStatus   assess.TLSAddressStatus
		expectedCategory string
	}{
		{
			name:             "hostname mismatch",
			err:              x509.HostnameError{Host: "myvault.vault.azure.net", Certificate: &x509.Certificate{Subject: pkix.Name{CommonName: "wrong.vault.azure.net"}}},
			expectedStatus:   assess.TLSAddrHostnameMismatch,
			expectedCategory: "HOSTNAME_MISMATCH",
		},
		{
			name:             "unknown authority",
			err:              x509.UnknownAuthorityError{},
			expectedStatus:   assess.TLSAddrUntrustedCertificate,
			expectedCategory: "UNTRUSTED_CERTIFICATE",
		},
		{
			name:             "expired certificate",
			err:              x509.CertificateInvalidError{Reason: x509.Expired},
			expectedStatus:   assess.TLSAddrExpiredCertificate,
			expectedCategory: "EXPIRED_CERTIFICATE",
		},
		{
			name:             "not yet valid string",
			err:              errors.New("x509: current time is before notBefore"),
			expectedStatus:   assess.TLSAddrNotYetValid,
			expectedCategory: "NOT_YET_VALID",
		},
		{
			name:             "connection closed string",
			err:              errors.New("read: connection reset by peer"),
			expectedStatus:   assess.TLSAddrConnectionClosed,
			expectedCategory: "CONNECTION_CLOSED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, cat, _ := CategorizeTLSError(context.Background(), tt.err)
			if status != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, status)
			}
			if cat != tt.expectedCategory {
				t.Errorf("expected category %s, got %s", tt.expectedCategory, cat)
			}
		})
	}
}

func TestProductionCode_NoInsecureSkipVerifyRegression(t *testing.T) {
	files, err := filepath.Glob("../../*/*.go")
	if err != nil {
		t.Fatalf("failed to glob go files: %v", err)
	}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(string(content), "InsecureSkipVerify: true") {
			t.Errorf("SECURITY VIOLATION: File %s contains InsecureSkipVerify: true", f)
		}
	}
}

// Local Ephemeral TLS Server Integration Test Helper
func generateTestCAAndCert(t *testing.T, dnsName string, expired bool, notYetValid bool) ([]byte, tls.Certificate, *x509.CertPool) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AZPE Test Root CA"},
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

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)
	if expired {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour)
	} else if notYetValid {
		notBefore = time.Now().Add(24 * time.Hour)
		notAfter = time.Now().Add(48 * time.Hour)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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

	return caCertBytes, tlsCert, rootPool
}

func TestLocalTLSServer_Integration_Valid(t *testing.T) {
	serverName := "test.vault.azure.net"
	_, tlsCert, rootPool := generateTestCAAndCert(t, serverName, false, false)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	prober := &OSTLSProber{RootCAs: rootPool}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := prober.ProbeTLS(ctx, host, port, serverName)
	if res.Status != assess.TLSAddrValid {
		t.Errorf("expected TLSAddrValid for local TLS server, got %v (err: %s)", res.Status, res.Error)
	}
	if res.TLSVersion == "" {
		t.Errorf("expected TLSVersion to be populated, got empty")
	}
	if res.LeafCertificate == nil || res.LeafCertificate.CommonName != serverName {
		t.Errorf("expected leaf cert common name %s", serverName)
	}
}

func TestLocalTLSServer_Integration_HostnameMismatch(t *testing.T) {
	serverName := "test.vault.azure.net"
	_, tlsCert, rootPool := generateTestCAAndCert(t, serverName, false, false)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	prober := &OSTLSProber{RootCAs: rootPool}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := prober.ProbeTLS(ctx, host, port, "wrong.vault.azure.net")
	if res.Status != assess.TLSAddrHostnameMismatch {
		t.Errorf("expected TLSAddrHostnameMismatch, got %v (err: %s)", res.Status, res.Error)
	}
}

func TestLocalTLSServer_Integration_UntrustedCertificate(t *testing.T) {
	serverName := "test.vault.azure.net"
	_, tlsCert, _ := generateTestCAAndCert(t, serverName, false, false)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	prober := &OSTLSProber{RootCAs: x509.NewCertPool()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := prober.ProbeTLS(ctx, host, port, serverName)
	if res.Status != assess.TLSAddrUntrustedCertificate {
		t.Errorf("expected TLSAddrUntrustedCertificate, got %v (err: %s)", res.Status, res.Error)
	}
}
