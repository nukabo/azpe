package assess_test

import (
	"net/netip"
	"testing"

	"github.com/azpe/azpe/internal/assess"
)

func TestClassifyIP(t *testing.T) {
	tests := []struct {
		ip   string
		want assess.AddressClassification
	}{
		{"10.0.0.1", assess.AddrPrivate},
		{"172.16.0.1", assess.AddrPrivate},
		{"172.31.255.254", assess.AddrPrivate},
		{"172.32.0.1", assess.AddrPublic},
		{"192.168.0.1", assess.AddrPrivate},
		{"8.8.8.8", assess.AddrPublic},
		{"127.0.0.1", assess.AddrLoopback},
		{"169.254.0.1", assess.AddrLinkLocal},
		{"0.0.0.0", assess.AddrUnspecified},
		{"224.0.0.1", assess.AddrMulticast},
		{"192.0.2.1", assess.AddrDocumentation},
		{"198.51.100.1", assess.AddrDocumentation},
		{"203.0.113.1", assess.AddrDocumentation},
		{"198.18.0.1", assess.AddrBenchmark},
		{"::1", assess.AddrLoopback},
		{"fe80::1", assess.AddrLinkLocal},
		{"fc00::1", assess.AddrPrivate},
		{"fd00::1", assess.AddrPrivate},
		{"2001:4860:4860::8888", assess.AddrPublic},
		{"ff02::1", assess.AddrMulticast},
		{"::", assess.AddrUnspecified},
		{"2001:db8::1", assess.AddrDocumentation},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			got := assess.ClassifyIP(addr)
			if got != tt.want {
				t.Errorf("ClassifyIP(%s) = %s, want %s", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCalculateAggregateClassification(t *testing.T) {
	tests := []struct {
		name            string
		classifications []assess.AddressClassification
		want            assess.AggregateClassification
	}{
		{
			name:            "empty address collection",
			classifications: []assess.AddressClassification{},
			want:            assess.AggregateNone,
		},
		{
			name:            "private only",
			classifications: []assess.AddressClassification{assess.AddrPrivate, assess.AddrPrivate},
			want:            assess.AggregatePrivateOnly,
		},
		{
			name:            "public only",
			classifications: []assess.AddressClassification{assess.AddrPublic, assess.AddrPublic},
			want:            assess.AggregatePublicOnly,
		},
		{
			name:            "mixed private/public",
			classifications: []assess.AddressClassification{assess.AddrPrivate, assess.AddrPublic},
			want:            assess.AggregateMixedPrivatePublic,
		},
		{
			name:            "special only",
			classifications: []assess.AddressClassification{assess.AddrLoopback, assess.AddrLinkLocal},
			want:            assess.AggregateSpecialOnly,
		},
		{
			name:            "mixed special and private",
			classifications: []assess.AddressClassification{assess.AddrPrivate, assess.AddrLoopback},
			want:            assess.AggregateMixed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assess.CalculateAggregateClassification(tt.classifications)
			if got != tt.want {
				t.Errorf("CalculateAggregateClassification(%v) = %s, want %s", tt.classifications, got, tt.want)
			}
		})
	}
}
