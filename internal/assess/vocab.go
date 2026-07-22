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

// TCPStatus represents the result of TCP connection attempts.
type TCPStatus string

const (
	TCPStatusConnected         TCPStatus = "CONNECTED"
	TCPStatusConnectionRefused TCPStatus = "CONNECTION_REFUSED"
	TCPStatusTimedOut          TCPStatus = "TIMED_OUT"
	TCPStatusUnreachable       TCPStatus = "UNREACHABLE"
	TCPStatusSkipped           TCPStatus = "SKIPPED"
	TCPStatusUnknown           TCPStatus = "UNKNOWN"
)

func (t TCPStatus) String() string {
	return string(t)
}

// TLSStatus represents the result of TLS validation.
type TLSStatus string

const (
	TLSStatusHandshakeOK  TLSStatus = "HANDSHAKE_OK"
	TLSStatusCertExpired  TLSStatus = "CERT_EXPIRED"
	TLSStatusNameMismatch TLSStatus = "NAME_MISMATCH"
	TLSStatusUntrustedCA  TLSStatus = "UNTRUSTED_CA"
	TLSStatusFailed       TLSStatus = "FAILED"
	TLSStatusSkipped      TLSStatus = "SKIPPED"
	TLSStatusUnknown      TLSStatus = "UNKNOWN"
)

func (t TLSStatus) String() string {
	return string(t)
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
