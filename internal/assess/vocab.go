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
	OwnerApplication           LikelyOwner = "APPLICATION"
	OwnerApplicationOrService  LikelyOwner = "APPLICATION_OR_SERVICE"
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
	DNSStatusNotFound         DNSStatus = "NOT_FOUND"
	DNSStatusTimeout          DNSStatus = "TIMEOUT"
	DNSStatusTemporaryFailure DNSStatus = "TEMPORARY_FAILURE"
)

func (d DNSStatus) String() string {
	return string(d)
}

// DNSResolverMode indicates the resolver implementation path used by AZPE.
type DNSResolverMode string

const (
	ResolverModeGoBuiltin DNSResolverMode = "GO_BUILTIN"
	ResolverModeOSNative  DNSResolverMode = "OS_NATIVE"
)

func (r DNSResolverMode) String() string {
	return string(r)
}

// AddressClassification represents the network classification of a single IP address.
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

// AggregateClassification represents the aggregate classification of all resolved IP addresses.
type AggregateClassification string

const (
	AggregatePrivateOnly        AggregateClassification = "PRIVATE_ONLY"
	AggregatePublicOnly         AggregateClassification = "PUBLIC_ONLY"
	AggregateMixedPrivatePublic AggregateClassification = "MIXED_PRIVATE_PUBLIC"
	AggregateSpecialOnly        AggregateClassification = "SPECIAL_ONLY"
	AggregateNone               AggregateClassification = "NONE"
)

func (a AggregateClassification) String() string {
	return string(a)
}

// TCPAddressStatus represents the TCP connection status for a single address.
type TCPAddressStatus string

const (
	TCPAddrConnected        TCPAddressStatus = "CONNECTED"
	TCPAddrTimedOut         TCPAddressStatus = "TIMED_OUT"
	TCPAddrConnectionRefused TCPAddressStatus = "CONNECTION_REFUSED"
	TCPAddrUnreachable      TCPAddressStatus = "UNREACHABLE"
	TCPAddrCanceled         TCPAddressStatus = "CANCELED"
	TCPAddrError            TCPAddressStatus = "ERROR"
)

// AggregateTCPStatus represents the aggregate TCP connectivity status across all probed addresses.
type AggregateTCPStatus string

const (
	AggregateTCPAllConnected       AggregateTCPStatus = "ALL_CONNECTED"
	AggregateTCPNoneConnected      AggregateTCPStatus = "NONE_CONNECTED"
	AggregateTCPPartiallyConnected AggregateTCPStatus = "PARTIALLY_CONNECTED"
	AggregateTCPNotAttempted       AggregateTCPStatus = "NOT_ATTEMPTED"
	AggregateTCPNotApplicable      AggregateTCPStatus = "NOT_APPLICABLE"
	AggregateTCPCanceled           AggregateTCPStatus = "CANCELED"
)

// TCPStatus represents the top-level TCP connectivity probe phase status.
type TCPStatus string

const (
	TCPStatusSuccess TCPStatus = "SUCCESS"
	TCPStatusFailed  TCPStatus = "FAILED"
	TCPStatusPartial TCPStatus = "PARTIAL"
	TCPStatusSkipped TCPStatus = "SKIPPED"
	TCPStatusUnknown TCPStatus = "UNKNOWN"
)

// TLSAddressStatus represents the TLS validation status for a single address.
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
)

// AggregateTLSStatus represents the aggregate TLS status across all probed addresses.
type AggregateTLSStatus string

const (
	AggregateTLSAllValid       AggregateTLSStatus = "ALL_VALID"
	AggregateTLSNoneValid      AggregateTLSStatus = "NONE_VALID"
	AggregateTLSPartiallyValid AggregateTLSStatus = "PARTIALLY_VALID"
	AggregateTLSNotAttempted   AggregateTLSStatus = "NOT_ATTEMPTED"
	AggregateTLSNotApplicable  AggregateTLSStatus = "NOT_APPLICABLE"
	AggregateTLSCanceled       AggregateTLSStatus = "CANCELED"
)

// TLSStatus represents the top-level TLS probe phase status.
type TLSStatus string

const (
	TLSStatusSuccess TLSStatus = "SUCCESS"
	TLSStatusFailed  TLSStatus = "FAILED"
	TLSStatusPartial TLSStatus = "PARTIAL"
	TLSStatusSkipped TLSStatus = "SKIPPED"
	TLSStatusUnknown TLSStatus = "UNKNOWN"
)

// HTTPAddressStatus represents the HTTP request/response status for a single address.
type HTTPAddressStatus string

const (
	HTTPAddrResponded         HTTPAddressStatus = "RESPONDED"
	HTTPAddrTimeout           HTTPAddressStatus = "TIMEOUT"
	HTTPAddrConnectionFailed  HTTPAddressStatus = "CONNECTION_FAILED"
	HTTPAddrTLSFailed         HTTPAddressStatus = "TLS_FAILED"
	HTTPAddrMalformedResponse HTTPAddressStatus = "MALFORMED_RESPONSE"
	HTTPAddrConnectionClosed  HTTPAddressStatus = "CONNECTION_CLOSED"
	HTTPAddrCanceled          HTTPAddressStatus = "CANCELED"
	HTTPAddrError             HTTPAddressStatus = "ERROR"
)

// HTTPResponseCategory categorizes numeric HTTP status codes into functional categories.
type HTTPResponseCategory string

const (
	HTTPCatSuccess                HTTPResponseCategory = "SUCCESS"
	HTTPCatAuthenticationRequired HTTPResponseCategory = "AUTHENTICATION_REQUIRED"
	HTTPCatAccessDenied           HTTPResponseCategory = "ACCESS_DENIED"
	HTTPCatNotFound              HTTPResponseCategory = "NOT_FOUND"
	HTTPCatMethodNotAllowed      HTTPResponseCategory = "METHOD_NOT_ALLOWED"
	HTTPCatConflict              HTTPResponseCategory = "CONFLICT"
	HTTPCatThrottled             HTTPResponseCategory = "THROTTLED"
	HTTPCatServerError           HTTPResponseCategory = "SERVER_ERROR"
	HTTPCatRedirection           HTTPResponseCategory = "REDIRECTION"
	HTTPCatClientError           HTTPResponseCategory = "CLIENT_ERROR"
	HTTPCatInformational         HTTPResponseCategory = "INFORMATIONAL"
	HTTPCatOtherResponse         HTTPResponseCategory = "OTHER_RESPONSE"
	HTTPCatNoResponse            HTTPResponseCategory = "NO_RESPONSE"
)

// AggregateHTTPStatus represents the aggregate HTTP status across all probed addresses.
type AggregateHTTPStatus string

const (
	AggregateHTTPAllResponded       AggregateHTTPStatus = "ALL_RESPONDED"
	AggregateHTTPNoneResponded      AggregateHTTPStatus = "NONE_RESPONDED"
	AggregateHTTPPartiallyResponded AggregateHTTPStatus = "PARTIALLY_RESPONDED"
	AggregateHTTPNotAttempted       AggregateHTTPStatus = "NOT_ATTEMPTED"
	AggregateHTTPNotApplicable      AggregateHTTPStatus = "NOT_APPLICABLE"
	AggregateHTTPCanceled           AggregateHTTPStatus = "CANCELED"
	AggregateHTTPUnknown            AggregateHTTPStatus = "UNKNOWN"
)

// HTTPStatus represents the top-level HTTP probe phase status.
type HTTPStatus string

const (
	HTTPStatusSuccess HTTPStatus = "SUCCESS"
	HTTPStatusFailed  HTTPStatus = "FAILED"
	HTTPStatusPartial HTTPStatus = "PARTIAL"
	HTTPStatusSkipped HTTPStatus = "SKIPPED"
	HTTPStatusUnknown HTTPStatus = "UNKNOWN"
)
