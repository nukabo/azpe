package dns_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/dns"
	"github.com/azpe/azpe/internal/target"
)

type FakeResolver struct {
	Addrs map[string][]netip.Addr
	Err   map[string]error
}

func (f *FakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if err, ok := f.Err[host]; ok && err != nil {
		return nil, err
	}
	if addrs, ok := f.Addrs[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestResolve_FakeResolver(t *testing.T) {
	fake := &FakeResolver{
		Addrs: map[string][]netip.Addr{
			"private.test": {
				netip.MustParseAddr("10.0.0.1"),
			},
			"public.test": {
				netip.MustParseAddr("8.8.8.8"),
			},
			"multiprivate.test": {
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.1"),
			},
			"mixed.test": {
				netip.MustParseAddr("8.8.8.8"),
				netip.MustParseAddr("10.0.0.1"),
			},
			"dualstack.test": {
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("fd00::1"),
			},
			"duplicates.test": {
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
			},
			"unordered.test": {
				netip.MustParseAddr("192.168.1.50"),
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("172.16.0.1"),
			},
		},
		Err: map[string]error{
			"notfound.test": &net.DNSError{Err: "no such host", Name: "notfound.test", IsNotFound: true},
			"timeout.test":  &net.DNSError{Err: "i/o timeout", Name: "timeout.test", IsTimeout: true},
			"temp.test":     &net.DNSError{Err: "server failure", Name: "temp.test", IsTemporary: true},
			"generic.test":  fmt.Errorf("generic resolver failure"),
		},
	}

	ctx := context.Background()

	t.Run("one private address", func(t *testing.T) {
		tgt, _ := target.Parse("private.test")
		dnsObs, addrObs := dns.Resolve(ctx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusSuccess {
			t.Fatalf("expected DNSStatusSuccess, got %s", dnsObs.Status)
		}
		if addrObs.Classification != assess.AggregatePrivateOnly {
			t.Fatalf("expected AggregatePrivateOnly, got %s", addrObs.Classification)
		}
		if len(dnsObs.Addresses) != 1 || dnsObs.Addresses[0].Address != "10.0.0.1" {
			t.Fatalf("unexpected addresses: %v", dnsObs.Addresses)
		}
	})

	t.Run("one public address", func(t *testing.T) {
		tgt, _ := target.Parse("public.test")
		dnsObs, addrObs := dns.Resolve(ctx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusSuccess {
			t.Fatalf("expected DNSStatusSuccess, got %s", dnsObs.Status)
		}
		if addrObs.Classification != assess.AggregatePublicOnly {
			t.Fatalf("expected AggregatePublicOnly, got %s", addrObs.Classification)
		}
	})

	t.Run("multiple private addresses", func(t *testing.T) {
		tgt, _ := target.Parse("multiprivate.test")
		dnsObs, addrObs := dns.Resolve(ctx, fake, tgt)

		if addrObs.Classification != assess.AggregatePrivateOnly {
			t.Fatalf("expected AggregatePrivateOnly, got %s", addrObs.Classification)
		}
		if len(dnsObs.Addresses) != 2 {
			t.Fatalf("expected 2 addresses, got %d", len(dnsObs.Addresses))
		}
		// Verify deterministic sorting: 10.0.0.1 before 10.0.0.2
		if dnsObs.Addresses[0].Address != "10.0.0.1" || dnsObs.Addresses[1].Address != "10.0.0.2" {
			t.Fatalf("expected sorted [10.0.0.1, 10.0.0.2], got %v", dnsObs.Addresses)
		}
	})

	t.Run("mixed private and public addresses", func(t *testing.T) {
		tgt, _ := target.Parse("mixed.test")
		_, addrObs := dns.Resolve(ctx, fake, tgt)

		if addrObs.Classification != assess.AggregateMixedPrivatePublic {
			t.Fatalf("expected AggregateMixedPrivatePublic, got %s", addrObs.Classification)
		}
	})

	t.Run("IPv4 and IPv6", func(t *testing.T) {
		tgt, _ := target.Parse("dualstack.test")
		dnsObs, addrObs := dns.Resolve(ctx, fake, tgt)

		if addrObs.Classification != assess.AggregatePrivateOnly {
			t.Fatalf("expected AggregatePrivateOnly, got %s", addrObs.Classification)
		}
		if len(dnsObs.Addresses) != 2 {
			t.Fatalf("expected 2 addresses, got %d", len(dnsObs.Addresses))
		}
	})

	t.Run("duplicate addresses deduplicated", func(t *testing.T) {
		tgt, _ := target.Parse("duplicates.test")
		dnsObs, _ := dns.Resolve(ctx, fake, tgt)

		if len(dnsObs.Addresses) != 2 {
			t.Fatalf("expected 2 deduplicated addresses, got %d", len(dnsObs.Addresses))
		}
	})

	t.Run("addresses returned in nondeterministic order sorted", func(t *testing.T) {
		tgt, _ := target.Parse("unordered.test")
		dnsObs, _ := dns.Resolve(ctx, fake, tgt)

		if len(dnsObs.Addresses) != 3 {
			t.Fatalf("expected 3 addresses, got %d", len(dnsObs.Addresses))
		}
		if dnsObs.Addresses[0].Address != "10.0.0.1" || dnsObs.Addresses[1].Address != "172.16.0.1" || dnsObs.Addresses[2].Address != "192.168.1.50" {
			t.Fatalf("expected sorted IPs, got %v", dnsObs.Addresses)
		}
	})

	t.Run("hostname not found", func(t *testing.T) {
		tgt, _ := target.Parse("notfound.test")
		dnsObs, _ := dns.Resolve(ctx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusNotFound {
			t.Fatalf("expected DNSStatusNotFound, got %s", dnsObs.Status)
		}
		if dnsObs.ErrorCategory != "NOT_FOUND" {
			t.Fatalf("expected NOT_FOUND error category, got %s", dnsObs.ErrorCategory)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		tgt, _ := target.Parse("timeout.test")
		dnsObs, _ := dns.Resolve(ctx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusTimeout {
			t.Fatalf("expected DNSStatusTimeout, got %s", dnsObs.Status)
		}
		if dnsObs.ErrorCategory != "TIMEOUT" {
			t.Fatalf("expected TIMEOUT error category, got %s", dnsObs.ErrorCategory)
		}
	})

	t.Run("temporary failure", func(t *testing.T) {
		tgt, _ := target.Parse("temp.test")
		dnsObs, _ := dns.Resolve(ctx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusTemporaryFailure {
			t.Fatalf("expected DNSStatusTemporaryFailure, got %s", dnsObs.Status)
		}
	})

	t.Run("generic resolver error", func(t *testing.T) {
		tgt, _ := target.Parse("generic.test")
		dnsObs, _ := dns.Resolve(ctx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusFailure {
			t.Fatalf("expected DNSStatusFailure, got %s", dnsObs.Status)
		}
		if dnsObs.ErrorCategory != "GENERIC_ERROR" {
			t.Fatalf("expected GENERIC_ERROR category, got %s", dnsObs.ErrorCategory)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		tgt, _ := target.Parse("private.test")
		dnsObs, _ := dns.Resolve(cancelCtx, fake, tgt)

		if dnsObs.Status != assess.DNSStatusTimeout {
			t.Fatalf("expected DNSStatusTimeout on cancelled context, got %s", dnsObs.Status)
		}
	})
}

func TestResolve_IPLiterals(t *testing.T) {
	ctx := context.Background()
	fake := &FakeResolver{}

	tests := []struct {
		name      string
		targetStr string
		wantHost  string
		wantClass assess.AddressClassification
		wantAgg   assess.AggregateClassification
		wantIPVer string
	}{
		{
			name:      "IPv4 literal",
			targetStr: "10.0.0.1",
			wantHost:  "10.0.0.1",
			wantClass: assess.AddrPrivate,
			wantAgg:   assess.AggregatePrivateOnly,
			wantIPVer: "IPv4",
		},
		{
			name:      "IPv4 literal with port",
			targetStr: "10.0.0.1:8443",
			wantHost:  "10.0.0.1",
			wantClass: assess.AddrPrivate,
			wantAgg:   assess.AggregatePrivateOnly,
			wantIPVer: "IPv4",
		},
		{
			name:      "bracketed IPv6 literal",
			targetStr: "[fd00::1]",
			wantHost:  "fd00::1",
			wantClass: assess.AddrPrivate,
			wantAgg:   assess.AggregatePrivateOnly,
			wantIPVer: "IPv6",
		},
		{
			name:      "bracketed IPv6 literal with port",
			targetStr: "[fd00::1]:443",
			wantHost:  "fd00::1",
			wantClass: assess.AddrPrivate,
			wantAgg:   assess.AggregatePrivateOnly,
			wantIPVer: "IPv6",
		},
		{
			name:      "public IPv4 literal",
			targetStr: "8.8.8.8",
			wantHost:  "8.8.8.8",
			wantClass: assess.AddrPublic,
			wantAgg:   assess.AggregatePublicOnly,
			wantIPVer: "IPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt, err := target.Parse(tt.targetStr)
			if err != nil {
				t.Fatalf("failed to parse target %s: %v", tt.targetStr, err)
			}

			dnsObs, addrObs := dns.Resolve(ctx, fake, tgt)

			if dnsObs.Status != assess.DNSStatusNotApplicable {
				t.Errorf("expected DNSStatusNotApplicable, got %s", dnsObs.Status)
			}
			if !dnsObs.IsIPLiteral {
				t.Errorf("expected IsIPLiteral true")
			}
			if len(dnsObs.Addresses) != 1 {
				t.Fatalf("expected 1 address, got %d", len(dnsObs.Addresses))
			}
			if dnsObs.Addresses[0].Address != tt.wantHost {
				t.Errorf("address = %s, want %s", dnsObs.Addresses[0].Address, tt.wantHost)
			}
			if dnsObs.Addresses[0].Classification != tt.wantClass {
				t.Errorf("classification = %s, want %s", dnsObs.Addresses[0].Classification, tt.wantClass)
			}
			if addrObs.Classification != tt.wantAgg {
				t.Errorf("aggregate classification = %s, want %s", addrObs.Classification, tt.wantAgg)
			}
		})
	}
}

func TestResolve_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	time.Sleep(10 * time.Millisecond)
	defer cancel()

	fake := &FakeResolver{
		Addrs: map[string][]netip.Addr{"slow.test": {netip.MustParseAddr("10.0.0.1")}},
	}

	tgt, _ := target.Parse("slow.test")
	dnsObs, _ := dns.Resolve(ctx, fake, tgt)

	if dnsObs.Status != assess.DNSStatusTimeout {
		t.Errorf("expected DNSStatusTimeout, got %s", dnsObs.Status)
	}
}
