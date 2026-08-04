package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nukabo/azpe/internal/assess"
	"github.com/nukabo/azpe/internal/model"
	"github.com/nukabo/azpe/internal/target"
	"github.com/nukabo/azpe/internal/version"
)

// Prober abstracts HTTP health requests for testability.
type Prober interface {
	ProbeHTTP(ctx context.Context, ipStr string, port int, serverName string, requestPath string, scheme string) model.HTTPResultItem
}

// OSHTTPProber uses Go's standard net/http to send an unauthenticated HTTPS GET request directly to captured IP.
type OSHTTPProber struct {
	// RootCAs is optional and used for test injection when non-nil.
	// In production, RootCAs is nil so Go uses the operating system trust store.
	RootCAs *x509.CertPool
	// Transport is optional and used for test injection when non-nil.
	Transport http.RoundTripper
}

// MaxResponseBodyReadBytes is the maximum number of response body bytes read for health evaluation.
const MaxResponseBodyReadBytes = 4096

// ProbeHTTP executes a single unauthenticated HTTPS GET request directly to target IP and port.
func (p *OSHTTPProber) ProbeHTTP(ctx context.Context, ipStr string, port int, serverName string, requestPath string, scheme string) model.HTTPResultItem {
	if scheme == "" {
		scheme = "https"
	}

	dest := net.JoinHostPort(ipStr, strconv.Itoa(port))
	ipVer := "IPv4"
	cls := assess.AddrPrivate
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		if addr.Is6() {
			ipVer = "IPv6"
		}
		cls = assess.ClassifyIP(addr)
	}

	hostHeader := serverName
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		hostHeader = net.JoinHostPort(serverName, strconv.Itoa(port))
	}

	sanitizedURI := target.RedactQueryValues(requestPath)

	tr := &http.Transport{
		Proxy: nil, // explicitly disable environment proxies!
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(dialCtx, "tcp", dest)
		},
		TLSClientConfig: &tls.Config{
			ServerName: serverName,
			RootCAs:    p.RootCAs,
			// InsecureSkipVerify is FALSE by default and MUST NOT be set to true.
		},
		DisableKeepAlives:  true,
		DisableCompression: true, // Prevent compressed body expansion
	}
	defer tr.CloseIdleConnections()

	var clientTransport http.RoundTripper = tr
	if p.Transport != nil {
		clientTransport = p.Transport
	}

	client := &http.Client{
		Transport: clientTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: nil, // explicitly no cookie jar
	}

	reqURL := fmt.Sprintf("%s://%s%s", scheme, dest, requestPath)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return model.HTTPResultItem{
			Address:          ipStr,
			Version:          ipVer,
			Classification:   cls,
			Destination:      dest,
			Port:             port,
			ServerName:       serverName,
			Host:             hostHeader,
			Method:           "GET",
			RequestURI:       sanitizedURI,
			Status:           assess.HTTPAddrError,
			ResponseCategory: assess.HTTPCatNoResponse,
			DurationMs:       0,
			FailureStage:     "REQUEST_CREATION",
			ErrorCategory:    "ERROR",
			Error:            target.SanitizeErrorString(err.Error()),
		}
	}

	req.Host = hostHeader
	req.Header.Set("User-Agent", "azpe/"+version.Version)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")

	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		status, stage, cat, sanErr := CategorizeHTTPError(ctx, err)
		return model.HTTPResultItem{
			Address:          ipStr,
			Version:          ipVer,
			Classification:   cls,
			Destination:      dest,
			Port:             port,
			ServerName:       serverName,
			Host:             hostHeader,
			Method:           "GET",
			RequestURI:       sanitizedURI,
			Status:           status,
			ResponseCategory: assess.HTTPCatNoResponse,
			DurationMs:       duration,
			FailureStage:     stage,
			ErrorCategory:    cat,
			Error:            sanErr,
		}
	}

	// Read body up to MaxResponseBodyReadBytes limit and discard
	bodyReader := io.LimitReader(resp.Body, int64(MaxResponseBodyReadBytes+1))
	bodyBytes, _ := io.ReadAll(bodyReader)
	resp.Body.Close()

	readLen := len(bodyBytes)
	truncated := false
	if readLen > MaxResponseBodyReadBytes {
		readLen = MaxResponseBodyReadBytes
		truncated = true
	}

	statusText := http.StatusText(resp.StatusCode)
	if statusText == "" {
		statusText = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	cat := CategorizeStatusCode(resp.StatusCode)
	safeHeaders := ExtractSafeHeaders(resp.Header)

	return model.HTTPResultItem{
		Address:          ipStr,
		Version:          ipVer,
		Classification:   cls,
		Destination:      dest,
		Port:             port,
		ServerName:       serverName,
		Host:             hostHeader,
		Method:           "GET",
		RequestURI:       sanitizedURI,
		Status:           assess.HTTPAddrResponded,
		StatusCode:       resp.StatusCode,
		StatusText:       statusText,
		ResponseCategory: cat,
		DurationMs:       duration,
		RedirectFollowed: false,
		Headers:          safeHeaders,
		BodyReadBytes:    readLen,
		BodyTruncated:    truncated,
	}
}

// CategorizeStatusCode maps numeric HTTP status codes into response categories.
func CategorizeStatusCode(code int) assess.HTTPResponseCategory {
	switch {
	case code >= 100 && code <= 199:
		return assess.HTTPCatInformational
	case code >= 200 && code <= 299:
		return assess.HTTPCatSuccess
	case code >= 300 && code <= 399:
		return assess.HTTPCatRedirection
	case code == 400:
		return assess.HTTPCatClientError
	case code == 401:
		return assess.HTTPCatAuthenticationRequired
	case code == 403:
		return assess.HTTPCatAccessDenied
	case code == 404:
		return assess.HTTPCatNotFound
	case code == 405:
		return assess.HTTPCatMethodNotAllowed
	case code == 409:
		return assess.HTTPCatConflict
	case code == 429:
		return assess.HTTPCatThrottled
	case code >= 500 && code <= 599:
		return assess.HTTPCatServerError
	default:
		return assess.HTTPCatOtherResponse
	}
}

// CategorizeHTTPError maps transport and HTTP errors into stable statuses and categories.
func CategorizeHTTPError(ctx context.Context, err error) (assess.HTTPAddressStatus, string, string, string) {
	if err == nil {
		return assess.HTTPAddrResponded, "COMPLETE", "", ""
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = target.SanitizeTargetString(urlErr.URL)
	}

	sanitizedErr := target.SanitizeErrorString(strings.TrimSpace(err.Error()))

	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return assess.HTTPAddrTimeout, "RESPONSE", "TIMEOUT", sanitizedErr
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return assess.HTTPAddrCanceled, "RESPONSE", "CANCELED", sanitizedErr
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return assess.HTTPAddrTimeout, "RESPONSE", "TIMEOUT", sanitizedErr
	}

	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return assess.HTTPAddrTLSFailed, "TLS_HANDSHAKE", "TLS_FAILED", sanitizedErr
	}

	errStr := strings.ToLower(sanitizedErr)

	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "tls") || strings.Contains(errStr, "x509") {
		return assess.HTTPAddrTLSFailed, "TLS_HANDSHAKE", "TLS_FAILED", sanitizedErr
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") || strings.Contains(errStr, "i/o timeout") {
		return assess.HTTPAddrTimeout, "RESPONSE", "TIMEOUT", sanitizedErr
	}
	if strings.Contains(errStr, "malformed") || strings.Contains(errStr, "invalid http") || strings.Contains(errStr, "bad header") {
		return assess.HTTPAddrMalformedResponse, "HEADER", "MALFORMED_RESPONSE", sanitizedErr
	}
	if strings.Contains(errStr, "eof") || strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "closed") {
		return assess.HTTPAddrConnectionClosed, "RESPONSE", "CONNECTION_CLOSED", sanitizedErr
	}
	if strings.Contains(errStr, "refused") || strings.Contains(errStr, "unreachable") || strings.Contains(errStr, "dial") {
		return assess.HTTPAddrConnectionFailed, "CONNECTION", "CONNECTION_FAILED", sanitizedErr
	}

	return assess.HTTPAddrError, "RESPONSE", "ERROR", sanitizedErr
}

// ExtractSafeHeaders extracts a safe allowlist of response headers.
func ExtractSafeHeaders(h http.Header) *model.SafeHTTPHeaders {
	if len(h) == 0 {
		return nil
	}

	res := &model.SafeHTTPHeaders{}

	if cType := h.Get("Content-Type"); cType != "" {
		res.ContentType = cType
	}
	if cLenStr := h.Get("Content-Length"); cLenStr != "" {
		if cLen, err := strconv.ParseInt(cLenStr, 10, 64); err == nil {
			res.ContentLength = &cLen
		}
	}
	if dateStr := h.Get("Date"); dateStr != "" {
		res.Date = dateStr
	}
	if serverStr := h.Get("Server"); serverStr != "" {
		res.Server = serverStr
	}
	if locStr := h.Get("Location"); locStr != "" {
		res.Location = target.SanitizeLocation(locStr)
	}
	if retryStr := h.Get("Retry-After"); retryStr != "" {
		res.RetryAfter = retryStr
	}
	if authStr := h.Get("WWW-Authenticate"); authStr != "" {
		res.WWWAuthenticateScheme = extractAuthScheme(authStr)
	}
	if reqID := h.Get("x-ms-request-id"); reqID != "" {
		res.RequestID = reqID
	}
	if corrID := h.Get("x-ms-correlation-request-id"); corrID != "" {
		res.CorrelationRequestID = corrID
	}
	if clientID := h.Get("x-ms-client-request-id"); clientID != "" {
		res.ClientRequestID = clientID
	}
	if genericReqID := h.Get("request-id"); genericReqID != "" && res.RequestID == "" {
		res.RequestID = genericReqID
	}

	if res.ContentType == "" && res.ContentLength == nil && res.Date == "" && res.Server == "" &&
		res.Location == "" && res.RetryAfter == "" && res.WWWAuthenticateScheme == "" &&
		res.RequestID == "" && res.CorrelationRequestID == "" && res.ClientRequestID == "" {
		return nil
	}

	return res
}

func extractAuthScheme(hVal string) string {
	parts := strings.Fields(hVal)
	if len(parts) > 0 {
		return parts[0]
	}
	return "Authentication Required"
}

// FakeProber specifies pre-configured HTTP results per IP address for deterministic testing.
type FakeProber struct {
	Responses map[string]model.HTTPResultItem
	Calls     []string
}

// ProbeHTTP returns the pre-configured HTTPResultItem or defaults to 200 OK.
func (f *FakeProber) ProbeHTTP(ctx context.Context, ipStr string, port int, serverName string, requestPath string, scheme string) model.HTTPResultItem {
	f.Calls = append(f.Calls, fmt.Sprintf("%s:%d (%s %s)", ipStr, port, serverName, requestPath))
	sanitizedURI := target.RedactQueryValues(requestPath)

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
		if res.Host == "" {
			res.Host = serverName
		}
		if res.Method == "" {
			res.Method = "GET"
		}
		if res.RequestURI == "" {
			res.RequestURI = sanitizedURI
		}
		return res
	}

	dest := net.JoinHostPort(ipStr, strconv.Itoa(port))
	ipVer := "IPv4"
	if strings.Contains(ipStr, ":") {
		ipVer = "IPv6"
	}

	return model.HTTPResultItem{
		Address:          ipStr,
		Version:          ipVer,
		Classification:   assess.AddrPrivate,
		Destination:      dest,
		Port:             port,
		ServerName:       serverName,
		Host:             serverName,
		Method:           "GET",
		RequestURI:       sanitizedURI,
		Status:           assess.HTTPAddrResponded,
		StatusCode:       200,
		StatusText:       "OK",
		ResponseCategory: assess.HTTPCatSuccess,
		DurationMs:       14,
		RedirectFollowed: false,
		Headers: &model.SafeHTTPHeaders{
			ContentType: "application/json",
		},
		BodyReadBytes: 128,
		BodyTruncated: false,
	}
}

// ProbeAll sequentially probes every TLS-valid IP address using the provided prober.
func ProbeAll(ctx context.Context, prober Prober, tlsObs model.TLSObservation, requestPath string, scheme string, port int, serverName string) model.HTTPObservation {
	var eligible []model.TLSResultItem
	for _, res := range tlsObs.Results {
		if res.Status == assess.TLSAddrValid {
			eligible = append(eligible, res)
		}
	}

	if len(eligible) == 0 {
		return model.HTTPObservation{
			Status:          assess.HTTPStatusSkipped,
			AggregateStatus: assess.AggregateHTTPNotAttempted,
			Method:          "GET",
			Path:            requestPath,
			DurationMs:      0,
			Results:         []model.HTTPResultItem{},
			Note:            "HTTP was not attempted because no TLS validation succeeded.",
		}
	}

	if prober == nil {
		prober = &OSHTTPProber{}
	}

	startTime := time.Now()
	var results []model.HTTPResultItem
	respondedCount := 0
	failedCount := 0

	for _, tlsRes := range eligible {
		if ctx != nil && ctx.Err() != nil {
			dest := net.JoinHostPort(tlsRes.Address, strconv.Itoa(tlsRes.Port))
			sanitizedURI := target.RedactQueryValues(requestPath)
			status := assess.HTTPAddrCanceled
			errCat := "CANCELED"
			errMsg := "Context canceled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				status = assess.HTTPAddrTimeout
				errCat = "TIMEOUT"
				errMsg = "Context deadline exceeded"
			}
			results = append(results, model.HTTPResultItem{
				Address:          tlsRes.Address,
				Version:          tlsRes.Version,
				Classification:   tlsRes.Classification,
				Destination:      dest,
				Port:             tlsRes.Port,
				ServerName:       serverName,
				Host:             serverName,
				Method:           "GET",
				RequestURI:       sanitizedURI,
				Status:           status,
				ResponseCategory: assess.HTTPCatNoResponse,
				DurationMs:       0,
				FailureStage:     "RESPONSE",
				ErrorCategory:    errCat,
				Error:            errMsg,
			})
			failedCount++
			continue
		}

		res := prober.ProbeHTTP(ctx, tlsRes.Address, port, serverName, requestPath, scheme)
		if res.Version == "" {
			res.Version = tlsRes.Version
		}
		if res.Classification == "" {
			res.Classification = tlsRes.Classification
		}
		results = append(results, res)

		if res.Status == assess.HTTPAddrResponded {
			respondedCount++
		} else {
			failedCount++
		}
	}

	totalDuration := time.Since(startTime).Milliseconds()

	var aggStatus assess.AggregateHTTPStatus
	var httpStatus assess.HTTPStatus

	if respondedCount == len(eligible) {
		aggStatus = assess.AggregateHTTPAllResponded
		httpStatus = assess.HTTPStatusSuccess
	} else if respondedCount > 0 && failedCount > 0 {
		aggStatus = assess.AggregateHTTPPartiallyResponded
		httpStatus = assess.HTTPStatusPartial
	} else if failedCount == len(eligible) {
		aggStatus = assess.AggregateHTTPNoneResponded
		httpStatus = assess.HTTPStatusFailed
	} else if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		aggStatus = assess.AggregateHTTPCanceled
		httpStatus = assess.HTTPStatusFailed
	} else {
		aggStatus = assess.AggregateHTTPUnknown
		httpStatus = assess.HTTPStatusUnknown
	}

	sortResults(results)

	return model.HTTPObservation{
		Status:          httpStatus,
		AggregateStatus: aggStatus,
		Method:          "GET",
		Path:            requestPath,
		DurationMs:      totalDuration,
		Results:         results,
	}
}

func sortResults(results []model.HTTPResultItem) {
	sort.Slice(results, func(i, j int) bool {
		addrI, errI := netip.ParseAddr(results[i].Address)
		addrJ, errJ := netip.ParseAddr(results[j].Address)
		if errI == nil && errJ == nil {
			return addrI.Compare(addrJ) < 0
		}
		return results[i].Address < results[j].Address
	})
}
