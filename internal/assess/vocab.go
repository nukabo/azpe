package assess

// AssessmentState represents the top-level outcome of an AZPE probe.
type AssessmentState string

const (
	AssessmentWorking    AssessmentState = "WORKING"
	AssessmentNotPrivate AssessmentState = "NOT_PRIVATE"
	AssessmentBroken     AssessmentState = "BROKEN"
	AssessmentUnknown    AssessmentState = "UNKNOWN"
)

func (a AssessmentState) String() string {
	return string(a)
}

// LikelyOwner represents the team or component likely responsible for an observed issue.
type LikelyOwner string

const (
	OwnerDNSOrNetwork          LikelyOwner = "DNS_OR_NETWORK"
	OwnerNetwork               LikelyOwner = "NETWORK"
	OwnerApplicationOrIdentity LikelyOwner = "APPLICATION_OR_IDENTITY"
	OwnerSecurityOrProxy       LikelyOwner = "SECURITY_OR_PROXY"
	OwnerUnknown               LikelyOwner = "UNKNOWN"
)

func (o LikelyOwner) String() string {
	return string(o)
}

// DNSStatus represents the status of DNS resolution.
type DNSStatus string

const (
	DNSStatusSuccess          DNSStatus = "SUCCESS"
	DNSStatusFailure          DNSStatus = "FAILURE"
	DNSStatusNotApplicable    DNSStatus = "NOT_APPLICABLE"
	DNSStatusTimeout          DNSStatus = "TIMEOUT"
	DNSStatusNotFound         DNSStatus = "NOT_FOUND"
	DNSStatusTemporaryFailure DNSStatus = "TEMPORARY_FAILURE"
	DNSStatusSkipped          DNSStatus = "SKIPPED"
	DNSStatusUnknown          DNSStatus = "UNKNOWN"
)

func (d DNSStatus) String() string {
	return string(d)
}

// AddressClassification represents an individual IP address category.
type AddressClassification string

const (
	AddrPrivate       AddressClassification = "PRIVATE"
	AddrPublic        AddressClassification = "PUBLIC"
	AddrLoopback      AddressClassification = "LOOPBACK"
	AddrLinkLocal     AddressClassification = "LINK_LOCAL"
	AddrUnspecified   AddressClassification = "UNSPECIFIED"
	AddrMulticast     AddressClassification = "MULTICAST"
	AddrDocumentation AddressClassification = "DOCUMENTATION"
	AddrBenchmark     AddressClassification = "BENCHMARK"
	AddrReserved      AddressClassification = "RESERVED"
	AddrUnknown       AddressClassification = "UNKNOWN"
)

func (a AddressClassification) String() string {
	return string(a)
}

// AggregateClassification represents the combined classification of all resolved IP addresses.
type AggregateClassification string

const (
	AggregatePrivateOnly        AggregateClassification = "PRIVATE_ONLY"
	AggregatePublicOnly         AggregateClassification = "PUBLIC_ONLY"
	AggregateMixedPrivatePublic AggregateClassification = "MIXED_PRIVATE_PUBLIC"
	AggregateSpecialOnly        AggregateClassification = "SPECIAL_ONLY"
	AggregateMixed              AggregateClassification = "MIXED"
	AggregateNone               AggregateClassification = "NONE"
	AggregateUnknown            AggregateClassification = "UNKNOWN"
)

func (a AggregateClassification) String() string {
	return string(a)
}

// TCPStatus represents the aggregate status of TCP connection tests.
type TCPStatus string

const (
	TCPStatusSuccess TCPStatus = "SUCCESS"
	TCPStatusFailed  TCPStatus = "FAILED"
	TCPStatusPartial TCPStatus = "PARTIAL"
	TCPStatusSkipped TCPStatus = "SKIPPED"
	TCPStatusUnknown TCPStatus = "UNKNOWN"
)

func (t TCPStatus) String() string {
	return string(t)
}

// TCPAddressStatus represents the TCP status of a single IP address.
type TCPAddressStatus string

const (
	TCPAddrConnected         TCPAddressStatus = "CONNECTED"
	TCPAddrConnectionRefused TCPAddressStatus = "REFUSED"
	TCPAddrTimedOut          TCPAddressStatus = "TIMEOUT"
	TCPAddrUnreachable       TCPAddressStatus = "UNREACHABLE"
	TCPAddrCanceled          TCPAddressStatus = "CANCELED"
	TCPAddrError             TCPAddressStatus = "ERROR"
	TCPAddrSkipped           TCPAddressStatus = "SKIPPED"
)

func (t TCPAddressStatus) String() string {
	return string(t)
}

// AggregateTCPStatus represents the overall aggregate status across all probed TCP addresses.
type AggregateTCPStatus string

const (
	AggregateTCPAllConnected       AggregateTCPStatus = "ALL_CONNECTED"
	AggregateTCPNoneConnected      AggregateTCPStatus = "NONE_CONNECTED"
	AggregateTCPPartiallyConnected AggregateTCPStatus = "PARTIALLY_CONNECTED"
	AggregateTCPNotAttempted       AggregateTCPStatus = "NOT_ATTEMPTED"
	AggregateTCPNotApplicable      AggregateTCPStatus = "NOT_APPLICABLE"
	AggregateTCPCanceled           AggregateTCPStatus = "CANCELED"
	AggregateTCPUnknown            AggregateTCPStatus = "UNKNOWN"
)

func (a AggregateTCPStatus) String() string {
	return string(a)
}

// TLSStatus represents the aggregate status of TLS validation.
type TLSStatus string

const (
	TLSStatusSuccess TLSStatus = "SUCCESS"
	TLSStatusFailed  TLSStatus = "FAILED"
	TLSStatusPartial TLSStatus = "PARTIAL"
	TLSStatusSkipped TLSStatus = "SKIPPED"
	TLSStatusUnknown TLSStatus = "UNKNOWN"
)

func (t TLSStatus) String() string {
	return string(t)
}

// TLSAddressStatus represents the TLS status of a single IP address.
type TLSAddressStatus string

const (
	TLSAddrValid                TLSAddressStatus = "VALID"
	TLSAddrHostnameMismatch     TLSAddressStatus = "HOSTNAME_MISMATCH"
	TLSAddrUntrustedCertificate TLSAddressStatus = "UNTRUSTED_CERTIFICATE"
	TLSAddrExpiredCertificate   TLSAddressStatus = "EXPIRED_CERTIFICATE"
	TLSAddrNotYetValid          TLSAddressStatus = "NOT_YET_VALID"
	TLSAddrHandshakeTimeout     TLSAddressStatus = "HANDSHAKE_TIMEOUT"
	TLSAddrHandshakeFailed      TLSAddressStatus = "HANDSHAKE_FAILED"
	TLSAddrConnectionClosed     TLSAddressStatus = "CONNECTION_CLOSED"
	TLSAddrCanceled             TLSAddressStatus = "CANCELED"
	TLSAddrError                TLSAddressStatus = "ERROR"
	TLSAddrSkipped              TLSAddressStatus = "SKIPPED"
)

func (t TLSAddressStatus) String() string {
	return string(t)
}

// AggregateTLSStatus represents the overall aggregate status across all TLS validation attempts.
type AggregateTLSStatus string

const (
	AggregateTLSAllValid       AggregateTLSStatus = "ALL_VALID"
	AggregateTLSNoneValid      AggregateTLSStatus = "NONE_VALID"
	AggregateTLSPartiallyValid AggregateTLSStatus = "PARTIALLY_VALID"
	AggregateTLSNotAttempted   AggregateTLSStatus = "NOT_ATTEMPTED"
	AggregateTLSNotApplicable  AggregateTLSStatus = "NOT_APPLICABLE"
	AggregateTLSCanceled       AggregateTLSStatus = "CANCELED"
	AggregateTLSUnknown        AggregateTLSStatus = "UNKNOWN"
)

func (a AggregateTLSStatus) String() string {
	return string(a)
}

// HTTPStatus represents the result of the HTTP health request.
type HTTPStatus string

const (
	HTTPStatusOK2XX          HTTPStatus = "OK_2XX"
	HTTPStatusClientError4XX HTTPStatus = "CLIENT_ERROR_4XX"
	HTTPStatusServerError5XX HTTPStatus = "SERVER_ERROR_5XX"
	HTTPStatusFailed         HTTPStatus = "FAILED"
	HTTPStatusSkipped        HTTPStatus = "SKIPPED"
	HTTPStatusUnknown        HTTPStatus = "UNKNOWN"
)

func (h HTTPStatus) String() string {
	return string(h)
}
