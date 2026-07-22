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

// TCPObservation contains TCP connection test results.
type TCPObservation struct {
	Status    assess.TCPStatus `json:"status"`
	Connected string           `json:"connectedAddress,omitempty"`
	Port      int              `json:"port,omitempty"`
	Note      string           `json:"note,omitempty"`
}

// TLSObservation contains TLS certificate and handshake observations.
type TLSObservation struct {
	Status      assess.TLSStatus `json:"status"`
	TLSVersion  string           `json:"tlsVersion,omitempty"`
	CipherSuite string           `json:"cipherSuite,omitempty"`
	CertValid   *bool            `json:"certValid,omitempty"`
	CertSubject string           `json:"certSubject,omitempty"`
	CertIssuer  string           `json:"certIssuer,omitempty"`
	CertExpiry  string           `json:"certExpiry,omitempty"`
	Note        string           `json:"note,omitempty"`
}

// HTTPObservation contains minimal HTTP probe observations.
type HTTPObservation struct {
	Status     assess.HTTPStatus `json:"status"`
	StatusCode int               `json:"statusCode,omitempty"`
	StatusText string            `json:"statusText,omitempty"`
	Note       string            `json:"note,omitempty"`
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

// NewResultFromDNS evaluates the DNS observations and builds the Phase 2 diagnostic Result.
func NewResultFromDNS(tgt *target.Target, startTime time.Time, dnsObs DNSObservation, addrObs AddrObservation) *Result {
	hostname, _ := os.Hostname()
	duration := time.Since(startTime).Milliseconds()

	// Extract IP list and classifications for evaluation
	var addrsList []string
	var classList []assess.AddressClassification
	for _, ipObs := range dnsObs.Addresses {
		addrsList = append(addrsList, ipObs.Address)
		classList = append(classList, ipObs.Classification)
	}

	eval := assess.Evaluate(tgt, dnsObs.Status, addrObs.Classification, addrsList, classList, dnsObs.ErrorCategory, dnsObs.ErrorMessage)

	errorsList := []string{}
	if dnsObs.ErrorMessage != "" && eval.Scenario == assess.ScenarioDNSLookupFailed {
		errorsList = append(errorsList, dnsObs.ErrorMessage)
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
		TCP: TCPObservation{
			Status: assess.TCPStatusSkipped,
			Note:   "TCP connectivity probe not implemented in Phase 2",
		},
		TLS: TLSObservation{
			Status: assess.TLSStatusSkipped,
			Note:   "TLS validation not implemented in Phase 2",
		},
		HTTP: HTTPObservation{
			Status: assess.HTTPStatusSkipped,
			Note:   "HTTP request not implemented in Phase 2",
		},
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
