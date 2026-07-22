package assess

import (
	"net/netip"
)

var (
	// IPv4 prefixes
	pfxIPv4Private10  = netip.MustParsePrefix("10.0.0.0/8")
	pfxIPv4Private172 = netip.MustParsePrefix("172.16.0.0/12")
	pfxIPv4Private192 = netip.MustParsePrefix("192.168.0.0/16")
	pfxIPv4LinkLocal  = netip.MustParsePrefix("169.254.0.0/16")
	pfxIPv4Doc1       = netip.MustParsePrefix("192.0.2.0/24")
	pfxIPv4Doc2       = netip.MustParsePrefix("198.51.100.0/24")
	pfxIPv4Doc3       = netip.MustParsePrefix("203.0.113.0/24")
	pfxIPv4Benchmark  = netip.MustParsePrefix("198.18.0.0/15")
	pfxIPv4Reserved1  = netip.MustParsePrefix("240.0.0.0/4")
	pfxIPv4CGNAT      = netip.MustParsePrefix("100.64.0.0/10")
	pfxIPv4IETF       = netip.MustParsePrefix("192.0.0.0/24")
	pfxIPv46to4Relay  = netip.MustParsePrefix("192.88.99.0/24")

	// IPv6 prefixes
	pfxIPv6Private   = netip.MustParsePrefix("fc00::/7")
	pfxIPv6LinkLocal = netip.MustParsePrefix("fe80::/10")
	pfxIPv6Doc       = netip.MustParsePrefix("2001:db8::/32")
)

// ClassifyIP determines the classification of an individual IP address with specific precedence.
func ClassifyIP(addr netip.Addr) AddressClassification {
	if !addr.IsValid() {
		return AddrUnknown
	}

	// 1. Unspecified (0.0.0.0, ::)
	if addr.IsUnspecified() {
		return AddrUnspecified
	}

	// 2. Loopback (127.0.0.0/8, ::1)
	if addr.IsLoopback() {
		return AddrLoopback
	}

	// 3. Multicast (224.0.0.0/4, ff00::/8)
	if addr.IsMulticast() {
		return AddrMulticast
	}

	// 4. Link-local (169.254.0.0/16, fe80::/10)
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || pfxIPv4LinkLocal.Contains(addr) || pfxIPv6LinkLocal.Contains(addr) {
		return AddrLinkLocal
	}

	// 5. Documentation
	if pfxIPv4Doc1.Contains(addr) || pfxIPv4Doc2.Contains(addr) || pfxIPv4Doc3.Contains(addr) || pfxIPv6Doc.Contains(addr) {
		return AddrDocumentation
	}

	// 6. Benchmark
	if pfxIPv4Benchmark.Contains(addr) {
		return AddrBenchmark
	}

	// 7. Reserved
	if pfxIPv4Reserved1.Contains(addr) || pfxIPv4CGNAT.Contains(addr) || pfxIPv4IETF.Contains(addr) || pfxIPv46to4Relay.Contains(addr) {
		return AddrReserved
	}

	// 8. Private (RFC 1918 / RFC 4193)
	if pfxIPv4Private10.Contains(addr) || pfxIPv4Private172.Contains(addr) || pfxIPv4Private192.Contains(addr) || pfxIPv6Private.Contains(addr) {
		return AddrPrivate
	}

	// 9. Public (Global Unicast not matching any of the above)
	if addr.IsGlobalUnicast() || addr.Is4() || addr.Is6() {
		return AddrPublic
	}

	return AddrUnknown
}

// CalculateAggregateClassification computes the aggregate classification for a set of address classifications.
func CalculateAggregateClassification(classifications []AddressClassification) AggregateClassification {
	if len(classifications) == 0 {
		return AggregateNone
	}

	hasPrivate := false
	hasPublic := false
	hasSpecial := false

	for _, c := range classifications {
		switch c {
		case AddrPrivate:
			hasPrivate = true
		case AddrPublic:
			hasPublic = true
		case AddrLoopback, AddrLinkLocal, AddrUnspecified, AddrMulticast, AddrDocumentation, AddrBenchmark, AddrReserved:
			hasSpecial = true
		case AddrUnknown:
			hasSpecial = true
		}
	}

	if hasPrivate && !hasPublic && !hasSpecial {
		return AggregatePrivateOnly
	}
	if hasPublic && !hasPrivate && !hasSpecial {
		return AggregatePublicOnly
	}
	if hasPrivate && hasPublic {
		return AggregateMixedPrivatePublic
	}
	if hasSpecial && !hasPrivate && !hasPublic {
		return AggregateSpecialOnly
	}

	return AggregateMixedPrivatePublic
}
