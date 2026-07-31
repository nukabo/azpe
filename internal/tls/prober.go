package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nukabo/azpe/internal/assess"
	"github.com/nukabo/azpe/internal/model"
)

// Prober abstracts TLS handshake and certificate validation for testability.
type Prober interface {
	ProbeTLS(ctx context.Context, ipStr string, port int, serverName string) model.TLSResultItem
}

// OSTLSProber uses Go's standard crypto/tls to establish a TLS connection and validate certificates.
type OSTLSProber struct {
	// RootCAs is optional and only used for test injection when non-nil.
	// In production, RootCAs is nil so Go uses the operating system trust store.
	RootCAs *x509.CertPool
}

// ProbeTLS connects directly to target IP and port and validates the certificate for serverName.
func (p *OSTLSProber) ProbeTLS(ctx context.Context, ipStr string, port int, serverName string) model.TLSResultItem {
	dest := net.JoinHostPort(ipStr, strconv.Itoa(port))

	ipVer := "IPv4"
	cls := assess.AddrPrivate
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		if addr.Is6() {
			ipVer = "IPv6"
		}
		cls = assess.ClassifyIP(addr)
	}

	dialer := net.Dialer{}
	startTime := time.Now()

	rawConn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		duration := time.Since(startTime).Milliseconds()
		status, stage, cat, sanErr := CategorizeTLSError(ctx, err)
		return model.TLSResultItem{
			Address:        ipStr,
			Version:        ipVer,
			Classification: cls,
			Destination:    dest,
			Port:           port,
			ServerName:     serverName,
			Status:         status,
			Stage:          stage,
			DurationMs:     duration,
			ErrorCategory:  cat,
			Error:          sanErr,
		}
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName: serverName,
		RootCAs:    p.RootCAs,
		// InsecureSkipVerify is FALSE by default in Go tls.Config and MUST NOT be set to true.
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.HandshakeContext(ctx)
	duration := time.Since(startTime).Milliseconds()

	state := tlsConn.ConnectionState()

	if err != nil {
		status, stage, cat, sanErr := CategorizeTLSError(ctx, err)
		resItem := model.TLSResultItem{
			Address:        ipStr,
			Version:        ipVer,
			Classification: cls,
			Destination:    dest,
			Port:           port,
			ServerName:     serverName,
			Status:         status,
			Stage:          stage,
			DurationMs:     duration,
			TLSVersion:     formatTLSVersion(state.Version),
			CipherSuite:    formatCipherSuite(state.CipherSuite),
			ErrorCategory:  cat,
			Error:          sanErr,
		}

		if status == assess.TLSAddrHostnameMismatch {
			bFalse := false
			resItem.HostnameValid = &bFalse
		}
		if status == assess.TLSAddrUntrustedCertificate || status == assess.TLSAddrExpiredCertificate || status == assess.TLSAddrNotYetValid {
			bFalse := false
			resItem.CertificateTrusted = &bFalse
		}

		if len(state.PeerCertificates) > 0 {
			resItem.PeerCertificateCount = len(state.PeerCertificates)
			resItem.LeafCertificate = buildLeafCertInfo(state.PeerCertificates[0])
		}

		return resItem
	}

	bTrue := true
	leafInfo := buildLeafCertInfo(state.PeerCertificates[0])

	return model.TLSResultItem{
		Address:              ipStr,
		Version:              ipVer,
		Classification:       cls,
		Destination:          dest,
		Port:                 port,
		ServerName:           serverName,
		Status:               assess.TLSAddrValid,
		Stage:                "COMPLETE",
		DurationMs:           duration,
		TLSVersion:           formatTLSVersion(state.Version),
		CipherSuite:          formatCipherSuite(state.CipherSuite),
		HostnameValid:        &bTrue,
		CertificateTrusted:   &bTrue,
		PeerCertificateCount: len(state.PeerCertificates),
		VerifiedChainCount:   len(state.VerifiedChains),
		LeafCertificate:      leafInfo,
	}
}

// CategorizeTLSError maps TLS handshake and verification errors into stable statuses and categories.
func CategorizeTLSError(ctx context.Context, err error) (assess.TLSAddressStatus, string, string, string) {
	if err == nil {
		return assess.TLSAddrValid, "COMPLETE", "", ""
	}

	var sanitizedErr string
	if err != nil {
		sanitizedErr = strings.TrimSpace(err.Error())
	}

	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return assess.TLSAddrHandshakeTimeout, "HANDSHAKE", "HANDSHAKE_TIMEOUT", sanitizedErr
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return assess.TLSAddrCanceled, "HANDSHAKE", "CANCELED", sanitizedErr
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return assess.TLSAddrHostnameMismatch, "CERTIFICATE_VALIDATION", "HOSTNAME_MISMATCH", sanitizedErr
	}

	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return assess.TLSAddrUntrustedCertificate, "CERTIFICATE_VALIDATION", "UNTRUSTED_CERTIFICATE", sanitizedErr
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		if certInvalidErr.Reason == x509.Expired {
			return assess.TLSAddrExpiredCertificate, "CERTIFICATE_VALIDATION", "EXPIRED_CERTIFICATE", sanitizedErr
		}
		if certInvalidErr.Reason == x509.IncompatibleUsage || certInvalidErr.Reason == x509.CANotAuthorizedForExtKeyUsage {
			return assess.TLSAddrUntrustedCertificate, "CERTIFICATE_VALIDATION", "UNTRUSTED_CERTIFICATE", sanitizedErr
		}
		return assess.TLSAddrExpiredCertificate, "CERTIFICATE_VALIDATION", "EXPIRED_CERTIFICATE", sanitizedErr
	}

	errStr := strings.ToLower(sanitizedErr)

	if strings.Contains(errStr, "cannot be used for name") || (strings.Contains(errStr, "valid for") && strings.Contains(errStr, "not")) {
		return assess.TLSAddrHostnameMismatch, "CERTIFICATE_VALIDATION", "HOSTNAME_MISMATCH", sanitizedErr
	}
	if strings.Contains(errStr, "certificate is expired") || strings.Contains(errStr, "has expired") {
		return assess.TLSAddrExpiredCertificate, "CERTIFICATE_VALIDATION", "EXPIRED_CERTIFICATE", sanitizedErr
	}
	if strings.Contains(errStr, "not valid yet") || strings.Contains(errStr, "current time is before") {
		return assess.TLSAddrNotYetValid, "CERTIFICATE_VALIDATION", "NOT_YET_VALID", sanitizedErr
	}
	if strings.Contains(errStr, "unknown authority") || strings.Contains(errStr, "certificate signed by unknown authority") {
		return assess.TLSAddrUntrustedCertificate, "CERTIFICATE_VALIDATION", "UNTRUSTED_CERTIFICATE", sanitizedErr
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "deadline exceeded") {
		return assess.TLSAddrHandshakeTimeout, "HANDSHAKE", "HANDSHAKE_TIMEOUT", sanitizedErr
	}
	if strings.Contains(errStr, "eof") || strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "closed") {
		return assess.TLSAddrConnectionClosed, "HANDSHAKE", "CONNECTION_CLOSED", sanitizedErr
	}

	return assess.TLSAddrHandshakeFailed, "HANDSHAKE", "HANDSHAKE_FAILED", sanitizedErr
}

func buildLeafCertInfo(cert *x509.Certificate) *model.LeafCertInfo {
	if cert == nil {
		return nil
	}
	dnsNames := cert.DNSNames
	if dnsNames == nil {
		dnsNames = []string{}
	}

	return &model.LeafCertInfo{
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		DNSNames:     dnsNames,
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
	}
}

func formatTLSVersion(ver uint16) string {
	switch ver {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		if ver == 0 {
			return ""
		}
		return fmt.Sprintf("0x%04x", ver)
	}
}

func formatCipherSuite(suite uint16) string {
	if suite == 0 {
		return ""
	}
	return tls.CipherSuiteName(suite)
}

// FakeProber specifies pre-configured TLS results per IP address for deterministic testing.
type FakeProber struct {
	Responses map[string]model.TLSResultItem
	Calls     []string
}

// ProbeTLS returns the pre-configured TLSResultItem or defaults to VALID.
func (f *FakeProber) ProbeTLS(ctx context.Context, ipStr string, port int, serverName string) model.TLSResultItem {
	f.Calls = append(f.Calls, fmt.Sprintf("%s:%d (%s)", ipStr, port, serverName))
	if res, found := f.Responses[ipStr]; found {
		if res.Destination == "" {
			res.Destination = net.JoinHostPort(ipStr, strconv.Itoa(port))
		}
		if res.Port == 0 {
			res.Port = port
		}
		if res.Address == "" {
			res.Address = ipStr
		}
		if res.ServerName == "" {
			res.ServerName = serverName
		}
		return res
	}

	bTrue := true
	dest := net.JoinHostPort(ipStr, strconv.Itoa(port))
	ipVer := "IPv4"
	if strings.Contains(ipStr, ":") {
		ipVer = "IPv6"
	}

	return model.TLSResultItem{
		Address:              ipStr,
		Version:              ipVer,
		Classification:       assess.AddrPrivate,
		Destination:          dest,
		Port:                 port,
		ServerName:           serverName,
		Status:               assess.TLSAddrValid,
		Stage:                "COMPLETE",
		DurationMs:           12,
		TLSVersion:           "TLS 1.3",
		CipherSuite:          "TLS_AES_256_GCM_SHA384",
		HostnameValid:        &bTrue,
		CertificateTrusted:   &bTrue,
		PeerCertificateCount: 2,
		VerifiedChainCount:   1,
		LeafCertificate: &model.LeafCertInfo{
			Subject:      "CN=" + serverName,
			CommonName:   serverName,
			DNSNames:     []string{serverName},
			Issuer:       "CN=Microsoft Azure RSA TLS Issuing CA",
			SerialNumber: "1234567890",
			NotBefore:    time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		},
	}
}

// ProbeAll sequentially probes every TCP-connected IP address using the provided prober.
func ProbeAll(ctx context.Context, prober Prober, tcpObs model.TCPObservation, serverName string) model.TLSObservation {
	var eligible []model.TCPResultItem
	for _, res := range tcpObs.Results {
		if res.Status == assess.TCPAddrConnected {
			eligible = append(eligible, res)
		}
	}

	if len(eligible) == 0 {
		return model.TLSObservation{
			Status:          assess.TLSStatusSkipped,
			AggregateStatus: assess.AggregateTLSNotAttempted,
			ServerName:      serverName,
			DurationMs:      0,
			Results:         []model.TLSResultItem{},
			Note:            "TLS was not attempted because no TCP connection succeeded.",
		}
	}

	if prober == nil {
		prober = &OSTLSProber{}
	}

	startTime := time.Now()
	var results []model.TLSResultItem
	validCount := 0
	failedCount := 0

	for _, tcpRes := range eligible {
		if ctx != nil && ctx.Err() != nil {
			dest := net.JoinHostPort(tcpRes.Address, strconv.Itoa(tcpRes.Port))
			status := assess.TLSAddrCanceled
			errCat := "CANCELED"
			errMsg := "Context canceled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				status = assess.TLSAddrHandshakeTimeout
				errCat = "HANDSHAKE_TIMEOUT"
				errMsg = "Context deadline exceeded"
			}
			results = append(results, model.TLSResultItem{
				Address:        tcpRes.Address,
				Version:        tcpRes.Version,
				Classification: tcpRes.Classification,
				Destination:    dest,
				Port:           tcpRes.Port,
				ServerName:     serverName,
				Status:         status,
				Stage:          "HANDSHAKE",
				DurationMs:     0,
				ErrorCategory:  errCat,
				Error:          errMsg,
			})
			failedCount++
			continue
		}

		res := prober.ProbeTLS(ctx, tcpRes.Address, tcpRes.Port, serverName)
		if res.Version == "" {
			res.Version = tcpRes.Version
		}
		if res.Classification == "" {
			res.Classification = tcpRes.Classification
		}
		results = append(results, res)

		if res.Status == assess.TLSAddrValid {
			validCount++
		} else {
			failedCount++
		}
	}

	totalDuration := time.Since(startTime).Milliseconds()

	var aggStatus assess.AggregateTLSStatus
	var tlsStatus assess.TLSStatus

	if validCount == len(eligible) {
		aggStatus = assess.AggregateTLSAllValid
		tlsStatus = assess.TLSStatusSuccess
	} else if validCount > 0 && failedCount > 0 {
		aggStatus = assess.AggregateTLSPartiallyValid
		tlsStatus = assess.TLSStatusPartial
	} else if failedCount == len(eligible) {
		aggStatus = assess.AggregateTLSNoneValid
		tlsStatus = assess.TLSStatusFailed
	} else if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		aggStatus = assess.AggregateTLSCanceled
		tlsStatus = assess.TLSStatusFailed
	} else {
		aggStatus = assess.AggregateTLSUnknown
		tlsStatus = assess.TLSStatusUnknown
	}

	sortResults(results)

	return model.TLSObservation{
		Status:          tlsStatus,
		AggregateStatus: aggStatus,
		ServerName:      serverName,
		DurationMs:      totalDuration,
		Results:         results,
	}
}

func sortResults(results []model.TLSResultItem) {
	sort.Slice(results, func(i, j int) bool {
		addrI, errI := netip.ParseAddr(results[i].Address)
		addrJ, errJ := netip.ParseAddr(results[j].Address)
		if errI == nil && errJ == nil {
			return addrI.Compare(addrJ) < 0
		}
		return results[i].Address < results[j].Address
	})
}
