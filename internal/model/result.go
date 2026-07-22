package model

import (
	"os"
	"runtime"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/target"
	"github.com/azpe/azpe/internal/version"
)

// Result is the top-level versioned diagnostic result model.
type Result struct {
	SchemaVersion int             `json:"schemaVersion"`
	ToolVersion   string          `json:"toolVersion"`
	Timestamp     time.Time       `json:"timestamp"`
	DurationMs    int64           `json:"durationMs"`
	Target        *target.Target  `json:"target"`
	Environment   EnvironmentInfo `json:"environment"`
	DNS           DNSObservation  `json:"dns"`
	Address       AddrObservation `json:"address"`
	TCP           TCPObservation  `json:"tcp"`
	TLS           TLSObservation  `json:"tls"`
	HTTP          HTTPObservation `json:"http"`
	Assessment    AssessmentInfo  `json:"assessment"`
	Errors        []string        `json:"errors"`
	Warnings      []string        `json:"warnings"`
}

// EnvironmentInfo captures local execution context.
type EnvironmentInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
}

// IPObservation represents an individual resolved or target IP observation.
type IPObservation struct {
	Address        string                       `json:"address"`
	Version        string                       `json:"version"` // "IPv4" or "IPv6"
	Classification assess.AddressClassification `json:"classification"`
}

// DNSObservation contains DNS resolution observations.
type DNSObservation struct {
	Status                  assess.DNSStatus               `json:"status"`
	QueryHostname           string                         `json:"queryHostname,omitempty"`
	DurationMs              int64                          `json:"durationMs"`
	Addresses               []IPObservation                `json:"addresses"`
	AggregateClassification assess.AggregateClassification `json:"aggregateClassification"`
	IsIPLiteral             bool                           `json:"isIpLiteral"`
	ErrorCategory           string                         `json:"errorCategory,omitempty"`
	ErrorMessage            string                         `json:"errorMessage,omitempty"`
	Note                    string                         `json:"note,omitempty"`
}

// AddrObservation contains IP address classification details.
type AddrObservation struct {
	Classification assess.AggregateClassification `json:"classification"`
	Addresses      []IPObservation                `json:"addresses"`
	PrivateIPs     []string                       `json:"privateIps"`
	PublicIPs      []string                       `json:"publicIps"`
	Note           string                         `json:"note,omitempty"`
}

// TCPResultItem represents a single TCP connection observation for an address.
type TCPResultItem struct {
	Address        string                       `json:"address"`
	Version        string                       `json:"version"` // "IPv4" or "IPv6"
	Classification assess.AddressClassification `json:"classification"`
	Destination    string                       `json:"destination"` // "10.42.3.7:443" or "[fd00::7]:443"
	Port           int                          `json:"port"`
	Status         assess.TCPAddressStatus      `json:"status"`
	DurationMs     int64                        `json:"durationMs"`
	ErrorCategory  string                       `json:"errorCategory,omitempty"`
	Error          string                       `json:"error,omitempty"`
}

func (r TCPResultItem) GetAddress() string {
	return r.Address
}

func (r TCPResultItem) GetDestination() string {
	return r.Destination
}

func (r TCPResultItem) GetPort() int {
	return r.Port
}

func (r TCPResultItem) GetStatus() assess.TCPAddressStatus {
	return r.Status
}

func (r TCPResultItem) GetDurationMs() int64 {
	return r.DurationMs
}

func (r TCPResultItem) GetErrorCategory() string {
	return r.ErrorCategory
}

func (r TCPResultItem) GetError() string {
	return r.Error
}

// TCPObservation contains TCP connection test results.
type TCPObservation struct {
	Status          assess.TCPStatus          `json:"status"`
	AggregateStatus assess.AggregateTCPStatus `json:"aggregateStatus,omitempty"`
	Port            int                       `json:"port,omitempty"`
	DurationMs      int64                     `json:"durationMs"`
	Results         []TCPResultItem           `json:"results"`
	Note            string                    `json:"note,omitempty"`
}

func (t TCPObservation) GetAggregateStatus() assess.AggregateTCPStatus {
	return t.AggregateStatus
}

func (t TCPObservation) GetResults() []assess.MinimalTCPResultItem {
	var items []assess.MinimalTCPResultItem
	for _, r := range t.Results {
		items = append(items, r)
	}
	return items
}

// LeafCertInfo contains non-secret leaf certificate metadata for diagnostics.
type LeafCertInfo struct {
	Subject      string   `json:"subject,omitempty"`
	CommonName   string   `json:"commonName,omitempty"`
	DNSNames     []string `json:"dnsNames,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	SerialNumber string   `json:"serialNumber,omitempty"`
	NotBefore    string   `json:"notBefore,omitempty"`
	NotAfter     string   `json:"notAfter,omitempty"`
}

// TLSResultItem represents a single TLS connection/validation observation for an address.
type TLSResultItem struct {
	Address              string                       `json:"address"`
	Version              string                       `json:"version"` // "IPv4" or "IPv6"
	Classification       assess.AddressClassification `json:"classification"`
	Destination          string                       `json:"destination"` // "10.42.3.7:443" or "[fd00::7]:443"
	Port                 int                          `json:"port"`
	ServerName           string                       `json:"serverName"`
	Status               assess.TLSAddressStatus      `json:"status"`
	Stage                string                       `json:"stage,omitempty"` // "DIAL", "HANDSHAKE", "CERTIFICATE_VALIDATION", "COMPLETE"
	DurationMs           int64                        `json:"durationMs"`
	TLSVersion           string                       `json:"tlsVersion,omitempty"`
	CipherSuite          string                       `json:"cipherSuite,omitempty"`
	HostnameValid        *bool                        `json:"hostnameValid,omitempty"`
	CertificateTrusted   *bool                        `json:"certificateTrusted,omitempty"`
	PeerCertificateCount int                          `json:"peerCertificateCount,omitempty"`
	VerifiedChainCount   int                          `json:"verifiedChainCount,omitempty"`
	LeafCertificate      *LeafCertInfo                `json:"leafCertificate,omitempty"`
	ErrorCategory        string                       `json:"errorCategory,omitempty"`
	Error                string                       `json:"error,omitempty"`
}

func (r TLSResultItem) GetAddress() string {
	return r.Address
}

func (r TLSResultItem) GetDestination() string {
	return r.Destination
}

func (r TLSResultItem) GetPort() int {
	return r.Port
}

func (r TLSResultItem) GetServerName() string {
	return r.ServerName
}

func (r TLSResultItem) GetStatus() assess.TLSAddressStatus {
	return r.Status
}

func (r TLSResultItem) GetStage() string {
	return r.Stage
}

func (r TLSResultItem) GetDurationMs() int64 {
	return r.DurationMs
}

func (r TLSResultItem) GetTLSVersion() string {
	return r.TLSVersion
}

func (r TLSResultItem) GetCipherSuite() string {
	return r.CipherSuite
}

func (r TLSResultItem) GetErrorCategory() string {
	return r.ErrorCategory
}

func (r TLSResultItem) GetError() string {
	return r.Error
}

// TLSObservation contains TLS certificate and handshake observations.
type TLSObservation struct {
	Status          assess.TLSStatus          `json:"status"`
	AggregateStatus assess.AggregateTLSStatus `json:"aggregateStatus,omitempty"`
	ServerName      string                    `json:"serverName,omitempty"`
	DurationMs      int64                     `json:"durationMs"`
	Results         []TLSResultItem           `json:"results"`
	Note            string                    `json:"note,omitempty"`
}

func (t TLSObservation) GetAggregateStatus() assess.AggregateTLSStatus {
	return t.AggregateStatus
}

func (t TLSObservation) GetServerName() string {
	return t.ServerName
}

func (t TLSObservation) GetResults() []assess.MinimalTLSResultItem {
	var items []assess.MinimalTLSResultItem
	for _, r := range t.Results {
		items = append(items, r)
	}
	return items
}

// SafeHTTPHeaders contains safe response header metadata.
type SafeHTTPHeaders struct {
	ContentType           string `json:"contentType,omitempty"`
	ContentLength         *int64 `json:"contentLength,omitempty"`
	Date                  string `json:"date,omitempty"`
	Server                string `json:"server,omitempty"`
	Location              string `json:"location,omitempty"`
	RetryAfter            string `json:"retryAfter,omitempty"`
	WWWAuthenticateScheme string `json:"wwwAuthenticateScheme,omitempty"`
	RequestID             string `json:"requestId,omitempty"`
	CorrelationRequestID  string `json:"correlationRequestId,omitempty"`
	ClientRequestID       string `json:"clientRequestId,omitempty"`
}

// HTTPResultItem represents a single HTTP request/response observation for an address.
type HTTPResultItem struct {
	Address          string                       `json:"address"`
	Version          string                       `json:"version"` // "IPv4" or "IPv6"
	Classification   assess.AddressClassification `json:"classification"`
	Destination      string                       `json:"destination"` // "10.42.3.7:443" or "[fd00::7]:443"
	Port             int                          `json:"port"`
	ServerName       string                       `json:"serverName"`
	Host             string                       `json:"host"`
	Method           string                       `json:"method"` // "GET"
	RequestURI       string                       `json:"requestUri"`
	Status           assess.HTTPAddressStatus     `json:"status"`
	StatusCode       int                          `json:"statusCode,omitempty"`
	StatusText       string                       `json:"statusText,omitempty"`
	ResponseCategory assess.HTTPResponseCategory  `json:"responseCategory"`
	DurationMs       int64                        `json:"durationMs"`
	RedirectFollowed bool                         `json:"redirectFollowed"`
	Headers          *SafeHTTPHeaders             `json:"headers,omitempty"`
	BodyReadBytes    int                          `json:"bodyReadBytes"`
	BodyTruncated    bool                         `json:"bodyTruncated"`
	FailureStage     string                       `json:"failureStage,omitempty"`
	ErrorCategory    string                       `json:"errorCategory,omitempty"`
	Error            string                       `json:"error,omitempty"`
}

func (r HTTPResultItem) GetAddress() string {
	return r.Address
}

func (r HTTPResultItem) GetDestination() string {
	return r.Destination
}

func (r HTTPResultItem) GetPort() int {
	return r.Port
}

func (r HTTPResultItem) GetServerName() string {
	return r.ServerName
}

func (r HTTPResultItem) GetHost() string {
	return r.Host
}

func (r HTTPResultItem) GetMethod() string {
	return r.Method
}

func (r HTTPResultItem) GetRequestURI() string {
	return r.RequestURI
}

func (r HTTPResultItem) GetStatus() assess.HTTPAddressStatus {
	return r.Status
}

func (r HTTPResultItem) GetStatusCode() int {
	return r.StatusCode
}

func (r HTTPResultItem) GetStatusText() string {
	return r.StatusText
}

func (r HTTPResultItem) GetResponseCategory() assess.HTTPResponseCategory {
	return r.ResponseCategory
}

func (r HTTPResultItem) GetDurationMs() int64 {
	return r.DurationMs
}

func (r HTTPResultItem) GetRedirectFollowed() bool {
	return r.RedirectFollowed
}

func (r HTTPResultItem) GetErrorCategory() string {
	return r.ErrorCategory
}

func (r HTTPResultItem) GetError() string {
	return r.Error
}

// HTTPObservation contains HTTP request/response observations.
type HTTPObservation struct {
	Status          assess.HTTPStatus          `json:"status"`
	AggregateStatus assess.AggregateHTTPStatus `json:"aggregateStatus,omitempty"`
	Method          string                     `json:"method,omitempty"`
	Path            string                     `json:"path,omitempty"`
	DurationMs      int64                      `json:"durationMs"`
	Results         []HTTPResultItem           `json:"results"`
	Note            string                     `json:"note,omitempty"`
}

func (h HTTPObservation) GetAggregateStatus() assess.AggregateHTTPStatus {
	return h.AggregateStatus
}

func (h HTTPObservation) GetMethod() string {
	return h.Method
}

func (h HTTPObservation) GetPath() string {
	return h.Path
}

func (h HTTPObservation) GetResults() []assess.MinimalHTTPResultItem {
	var items []assess.MinimalHTTPResultItem
	for _, r := range h.Results {
		items = append(items, r)
	}
	return items
}

// AssessmentInfo summarizes findings, likely ownership, recommendations, and UX scenario.
type AssessmentInfo struct {
	Scenario    assess.AssessmentScenario `json:"scenario,omitempty"`
	State       assess.AssessmentState    `json:"state"`
	Title       string                    `json:"title,omitempty"`
	Explanation string                    `json:"explanation,omitempty"`
	Impact      string                    `json:"impact,omitempty"`
	Summary     string                    `json:"summary"`
	LikelyOwner assess.LikelyOwner        `json:"likelyOwner"`
	NextAction  string                    `json:"nextAction,omitempty"`
}

// NewResultFromDNSAndTCPAndTLSAndHTTP evaluates all probe observations and builds the diagnostic Result.
func NewResultFromDNSAndTCPAndTLSAndHTTP(tgt *target.Target, startTime time.Time, dnsObs DNSObservation, addrObs AddrObservation, tcpObs TCPObservation, tlsObs TLSObservation, httpObs HTTPObservation) *Result {
	hostname, _ := os.Hostname()
	duration := time.Since(startTime).Milliseconds()

	var addrsList []string
	var classList []assess.AddressClassification
	for _, ipObs := range dnsObs.Addresses {
		addrsList = append(addrsList, ipObs.Address)
		classList = append(classList, ipObs.Classification)
	}

	eval := assess.Evaluate(tgt, dnsObs.Status, addrObs.Classification, addrsList, classList, dnsObs.ErrorCategory, dnsObs.ErrorMessage, tcpObs, tlsObs, httpObs)

	errorsList := []string{}
	if dnsObs.ErrorMessage != "" && eval.Scenario == assess.ScenarioDNSLookupFailed {
		errorsList = append(errorsList, dnsObs.ErrorMessage)
	}
	for _, tcpRes := range tcpObs.Results {
		if tcpRes.Error != "" {
			errorsList = append(errorsList, tcpRes.Error)
		}
	}
	for _, tlsRes := range tlsObs.Results {
		if tlsRes.Error != "" {
			errorsList = append(errorsList, tlsRes.Error)
		}
	}
	for _, httpRes := range httpObs.Results {
		if httpRes.Error != "" {
			errorsList = append(errorsList, httpRes.Error)
		}
	}

	warningsList := []string{}
	if len(eval.Warnings) > 0 {
		warningsList = append(warningsList, eval.Warnings...)
	}

	// Ensure non-null slice fields in JSON
	if dnsObs.Addresses == nil {
		dnsObs.Addresses = []IPObservation{}
	}
	if addrObs.Addresses == nil {
		addrObs.Addresses = []IPObservation{}
	}
	if addrObs.PrivateIPs == nil {
		addrObs.PrivateIPs = []string{}
	}
	if addrObs.PublicIPs == nil {
		addrObs.PublicIPs = []string{}
	}
	if tcpObs.Results == nil {
		tcpObs.Results = []TCPResultItem{}
	}
	if tlsObs.Results == nil {
		tlsObs.Results = []TLSResultItem{}
	}
	if httpObs.Results == nil {
		httpObs.Results = []HTTPResultItem{}
	}
	for i := range tlsObs.Results {
		if tlsObs.Results[i].LeafCertificate != nil && tlsObs.Results[i].LeafCertificate.DNSNames == nil {
			tlsObs.Results[i].LeafCertificate.DNSNames = []string{}
		}
	}

	return &Result{
		SchemaVersion: version.SchemaVersion,
		ToolVersion:   version.Version,
		Timestamp:     startTime.UTC(),
		DurationMs:    duration,
		Target:        tgt,
		Environment: EnvironmentInfo{
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
			Hostname: hostname,
		},
		DNS:     dnsObs,
		Address: addrObs,
		TCP:     tcpObs,
		TLS:     tlsObs,
		HTTP:    httpObs,
		Assessment: AssessmentInfo{
			Scenario:    eval.Scenario,
			State:       eval.State,
			Title:       eval.Title,
			Explanation: eval.Explanation,
			Impact:      eval.Impact,
			Summary:     eval.Summary,
			LikelyOwner: eval.LikelyOwner,
			NextAction:  eval.NextAction,
		},
		Errors:   errorsList,
		Warnings: warningsList,
	}
}

// NewResultFromDNSAndTCPAndTLS evaluates DNS, TCP, and TLS observations without HTTP probing (helper).
func NewResultFromDNSAndTCPAndTLS(tgt *target.Target, startTime time.Time, dnsObs DNSObservation, addrObs AddrObservation, tcpObs TCPObservation, tlsObs TLSObservation) *Result {
	httpObs := HTTPObservation{
		Status:          assess.HTTPStatusSkipped,
		AggregateStatus: assess.AggregateHTTPNotAttempted,
		Method:          "GET",
		Path:            tgt.RequestPath,
		Results:         []HTTPResultItem{},
		Note:            "HTTP probe not performed",
	}
	return NewResultFromDNSAndTCPAndTLSAndHTTP(tgt, startTime, dnsObs, addrObs, tcpObs, tlsObs, httpObs)
}

// NewResultFromDNSAndTCP evaluates DNS and TCP observations without TLS/HTTP probing (helper).
func NewResultFromDNSAndTCP(tgt *target.Target, startTime time.Time, dnsObs DNSObservation, addrObs AddrObservation, tcpObs TCPObservation) *Result {
	tlsObs := TLSObservation{
		Status:          assess.TLSStatusSkipped,
		AggregateStatus: assess.AggregateTLSNotAttempted,
		ServerName:      tgt.Hostname,
		Results:         []TLSResultItem{},
		Note:            "TLS probe not performed",
	}
	return NewResultFromDNSAndTCPAndTLS(tgt, startTime, dnsObs, addrObs, tcpObs, tlsObs)
}

// NewResultFromDNS evaluates DNS observations without TCP/TLS/HTTP probing (helper).
func NewResultFromDNS(tgt *target.Target, startTime time.Time, dnsObs DNSObservation, addrObs AddrObservation) *Result {
	tcpObs := TCPObservation{
		Status:          assess.TCPStatusSkipped,
		AggregateStatus: assess.AggregateTCPNotAttempted,
		Results:         []TCPResultItem{},
		Note:            "TCP connectivity probe not performed",
	}
	return NewResultFromDNSAndTCP(tgt, startTime, dnsObs, addrObs, tcpObs)
}
