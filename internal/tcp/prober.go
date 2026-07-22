package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/model"
)

// Prober abstracts TCP connection attempts for testability.
type Prober interface {
	ProbeTCP(ctx context.Context, ipStr string, port int) model.TCPResultItem
}

// OSTCPProber uses Go's standard net.Dialer to attempt direct TCP connections.
type OSTCPProber struct{}

// ProbeTCP attempts a direct TCP connection to target IP and port without host DNS resolution.
func (p *OSTCPProber) ProbeTCP(ctx context.Context, ipStr string, port int) model.TCPResultItem {
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
	conn, err := dialer.DialContext(ctx, "tcp", dest)
	duration := time.Since(startTime).Milliseconds()

	if err == nil {
		_ = conn.Close()
		return model.TCPResultItem{
			Address:        ipStr,
			Version:        ipVer,
			Classification: cls,
			Destination:    dest,
			Port:           port,
			Status:         assess.TCPAddrConnected,
			DurationMs:     duration,
		}
	}

	status, errCat, errSan := CategorizeTCPError(ctx, err)
	return model.TCPResultItem{
		Address:        ipStr,
		Version:        ipVer,
		Classification: cls,
		Destination:    dest,
		Port:           port,
		Status:         status,
		DurationMs:     duration,
		ErrorCategory:  errCat,
		Error:          errSan,
	}
}

// CategorizeTCPError maps connection errors into stable TCPAddressStatus and ErrorCategory values.
func CategorizeTCPError(ctx context.Context, err error) (assess.TCPAddressStatus, string, string) {
	if err == nil {
		return assess.TCPAddrConnected, "", ""
	}

	sanitizedErr := sanitizeErrorString(err.Error())

	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return assess.TCPAddrTimedOut, "TIMEOUT", sanitizedErr
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return assess.TCPAddrCanceled, "CANCELED", sanitizedErr
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return assess.TCPAddrTimedOut, "TIMEOUT", sanitizedErr
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return assess.TCPAddrConnectionRefused, "REFUSED", sanitizedErr
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return assess.TCPAddrUnreachable, "UNREACHABLE", sanitizedErr
	}

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "refused") {
		return assess.TCPAddrConnectionRefused, "REFUSED", sanitizedErr
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") || strings.Contains(errStr, "i/o timeout") {
		return assess.TCPAddrTimedOut, "TIMEOUT", sanitizedErr
	}
	if strings.Contains(errStr, "unreachable") || strings.Contains(errStr, "no route to host") {
		return assess.TCPAddrUnreachable, "UNREACHABLE", sanitizedErr
	}

	return assess.TCPAddrError, "ERROR", sanitizedErr
}

func sanitizeErrorString(msg string) string {
	// Strip any potential carriage returns or control chars
	msg = strings.ReplaceAll(msg, "\r", "")
	msg = strings.TrimSpace(msg)
	return msg
}

// FakeProber specifies pre-configured TCP results per IP address for deterministic testing.
type FakeProber struct {
	Responses map[string]model.TCPResultItem
	Calls     []string
}

// ProbeTCP returns the pre-configured TCPResultItem or defaults to CONNECTED.
func (f *FakeProber) ProbeTCP(ctx context.Context, ipStr string, port int) model.TCPResultItem {
	f.Calls = append(f.Calls, fmt.Sprintf("%s:%d", ipStr, port))
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
		return res
	}

	dest := net.JoinHostPort(ipStr, strconv.Itoa(port))
	ipVer := "IPv4"
	if strings.Contains(ipStr, ":") {
		ipVer = "IPv6"
	}

	return model.TCPResultItem{
		Address:        ipStr,
		Version:        ipVer,
		Classification: assess.AddrPrivate,
		Destination:    dest,
		Port:           port,
		Status:         assess.TCPAddrConnected,
		DurationMs:     8,
	}
}

// ProbeAll sequentially probes every IP address using the provided prober.
func ProbeAll(ctx context.Context, prober Prober, ipObsList []model.IPObservation, port int) model.TCPObservation {
	if len(ipObsList) == 0 {
		return model.TCPObservation{
			Status:          assess.TCPStatusSkipped,
			AggregateStatus: assess.AggregateTCPNotAttempted,
			Port:            port,
			DurationMs:      0,
			Results:         []model.TCPResultItem{},
			Note:            "No IP addresses provided to TCP prober",
		}
	}

	if prober == nil {
		prober = &OSTCPProber{}
	}

	startTime := time.Now()
	var results []model.TCPResultItem
	connectedCount := 0
	failedCount := 0

	for _, ipObs := range ipObsList {
		if ctx != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
			// Parent context was canceled before probing this IP
			dest := net.JoinHostPort(ipObs.Address, strconv.Itoa(port))
			results = append(results, model.TCPResultItem{
				Address:        ipObs.Address,
				Version:        ipObs.Version,
				Classification: ipObs.Classification,
				Destination:    dest,
				Port:           port,
				Status:         assess.TCPAddrCanceled,
				DurationMs:     0,
				ErrorCategory:  "CANCELED",
				Error:          "Context canceled",
			})
			continue
		}

		res := prober.ProbeTCP(ctx, ipObs.Address, port)
		// Ensure IP version and classification are populated
		if res.Version == "" {
			res.Version = ipObs.Version
		}
		if res.Classification == "" {
			res.Classification = ipObs.Classification
		}
		results = append(results, res)

		if res.Status == assess.TCPAddrConnected {
			connectedCount++
		} else {
			failedCount++
		}
	}

	totalDuration := time.Since(startTime).Milliseconds()

	// Calculate AggregateTCPStatus & TCPStatus
	var aggStatus assess.AggregateTCPStatus
	var tcpStatus assess.TCPStatus

	if connectedCount == len(ipObsList) {
		aggStatus = assess.AggregateTCPAllConnected
		tcpStatus = assess.TCPStatusSuccess
	} else if connectedCount > 0 && failedCount > 0 {
		aggStatus = assess.AggregateTCPPartiallyConnected
		tcpStatus = assess.TCPStatusPartial
	} else if failedCount == len(ipObsList) {
		aggStatus = assess.AggregateTCPNoneConnected
		tcpStatus = assess.TCPStatusFailed
	} else if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		aggStatus = assess.AggregateTCPCanceled
		tcpStatus = assess.TCPStatusFailed
	} else {
		aggStatus = assess.AggregateTCPUnknown
		tcpStatus = assess.TCPStatusUnknown
	}

	sortResults(results)

	return model.TCPObservation{
		Status:          tcpStatus,
		AggregateStatus: aggStatus,
		Port:            port,
		DurationMs:      totalDuration,
		Results:         results,
	}
}

func sortResults(results []model.TCPResultItem) {
	sort.Slice(results, func(i, j int) bool {
		addrI, errI := netip.ParseAddr(results[i].Address)
		addrJ, errJ := netip.ParseAddr(results[j].Address)
		if errI == nil && errJ == nil {
			return addrI.Compare(addrJ) < 0
		}
		return results[i].Address < results[j].Address
	})
}
