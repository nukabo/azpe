package tcp

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/nukabo/azpe/internal/assess"
	"github.com/nukabo/azpe/internal/model"
)

func TestFakeProber_ConnectedAndFailed(t *testing.T) {
	fake := &FakeProber{
		Responses: map[string]model.TCPResultItem{
			"10.42.3.7": {
				Address:    "10.42.3.7",
				Status:     assess.TCPAddrConnected,
				DurationMs: 8,
			},
			"10.42.3.8": {
				Address:       "10.42.3.8",
				Status:        assess.TCPAddrTimedOut,
				DurationMs:    5001,
				ErrorCategory: "TIMEOUT",
				Error:         "dial tcp 10.42.3.8:443: i/o timeout",
			},
		},
	}

	ipObs := []model.IPObservation{
		{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
		{Address: "10.42.3.8", Version: "IPv4", Classification: assess.AddrPrivate},
	}

	ctx := context.Background()
	obs := ProbeAll(ctx, fake, ipObs, 443)

	if obs.Status != assess.TCPStatusPartial {
		t.Errorf("expected TCPStatusPartial, got %v", obs.Status)
	}
	if obs.AggregateStatus != assess.AggregateTCPPartiallyConnected {
		t.Errorf("expected AggregateTCPPartiallyConnected, got %v", obs.AggregateStatus)
	}
	if len(obs.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(obs.Results))
	}

	if obs.Results[0].Destination != "10.42.3.7:443" {
		t.Errorf("expected destination 10.42.3.7:443, got %s", obs.Results[0].Destination)
	}
	if obs.Results[1].Status != assess.TCPAddrTimedOut {
		t.Errorf("expected 10.42.3.8 status TIMEOUT, got %v", obs.Results[1].Status)
	}
}

func TestIPv6DestinationFormatting(t *testing.T) {
	fake := &FakeProber{
		Responses: map[string]model.TCPResultItem{},
	}

	ipObs := []model.IPObservation{
		{Address: "fd00::7", Version: "IPv6", Classification: assess.AddrPrivate},
	}

	ctx := context.Background()
	obs := ProbeAll(ctx, fake, ipObs, 443)

	if len(obs.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(obs.Results))
	}
	expectedDest := "[fd00::7]:443"
	if obs.Results[0].Destination != expectedDest {
		t.Errorf("expected destination %s, got %s", expectedDest, obs.Results[0].Destination)
	}
	if obs.Results[0].Version != "IPv6" {
		t.Errorf("expected version IPv6, got %s", obs.Results[0].Version)
	}
}

func TestCategorizeTCPError(t *testing.T) {
	tests := []struct {
		name             string
		ctxErr           error
		netErr           error
		expectedStatus   assess.TCPAddressStatus
		expectedCategory string
	}{
		{
			name:             "deadline exceeded context",
			ctxErr:           context.DeadlineExceeded,
			netErr:           errors.New("deadline exceeded"),
			expectedStatus:   assess.TCPAddrTimedOut,
			expectedCategory: "TIMEOUT",
		},
		{
			name:             "connection refused syscall",
			ctxErr:           nil,
			netErr:           syscall.ECONNREFUSED,
			expectedStatus:   assess.TCPAddrConnectionRefused,
			expectedCategory: "REFUSED",
		},
		{
			name:             "host unreachable syscall",
			ctxErr:           nil,
			netErr:           syscall.EHOSTUNREACH,
			expectedStatus:   assess.TCPAddrUnreachable,
			expectedCategory: "UNREACHABLE",
		},
		{
			name:             "connection canceled context",
			ctxErr:           context.Canceled,
			netErr:           context.Canceled,
			expectedStatus:   assess.TCPAddrCanceled,
			expectedCategory: "CANCELED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.ctxErr != nil {
				var cancel context.CancelFunc
				if errors.Is(tt.ctxErr, context.DeadlineExceeded) {
					ctx, cancel = context.WithTimeout(ctx, 1*time.Nanosecond)
					time.Sleep(2 * time.Millisecond)
				} else {
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
			}

			status, cat, _ := CategorizeTCPError(ctx, tt.netErr)
			if status != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, status)
			}
			if cat != tt.expectedCategory {
				t.Errorf("expected category %s, got %s", tt.expectedCategory, cat)
			}
		})
	}
}

func TestLocalTCPListener_Integration(t *testing.T) {
	// Start local TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local listener: %v", err)
	}
	defer listener.Close()

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener addr: %v", err)
	}
	port := 443
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	prober := &OSTCPProber{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := prober.ProbeTCP(ctx, host, port)
	if res.Status != assess.TCPAddrConnected {
		t.Errorf("expected CONNECTED for local listener, got %v (err: %s)", res.Status, res.Error)
	}
	if res.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", res.DurationMs)
	}
}

func TestNoSecondDNSLookup_Regression(t *testing.T) {
	fake := &FakeProber{}

	ipObs := []model.IPObservation{
		{Address: "10.42.3.7", Version: "IPv4", Classification: assess.AddrPrivate},
		{Address: "10.42.3.8", Version: "IPv4", Classification: assess.AddrPrivate},
	}

	ctx := context.Background()
	_ = ProbeAll(ctx, fake, ipObs, 443)

	if len(fake.Calls) != 2 {
		t.Fatalf("expected 2 calls to TCP prober, got %d", len(fake.Calls))
	}
	if fake.Calls[0] != "10.42.3.7:443" {
		t.Errorf("expected call 10.42.3.7:443, got %s", fake.Calls[0])
	}
	if fake.Calls[1] != "10.42.3.8:443" {
		t.Errorf("expected call 10.42.3.8:443, got %s", fake.Calls[1])
	}
}
