package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/target"
)

// FormatOptions configures output formatting behavior.
type FormatOptions struct {
	JSON    bool
	Details bool
	NoColor bool
}

// Color constants
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// Render writes the formatted Result to the provided writer based on options.
func Render(w io.Writer, res *model.Result, opts FormatOptions) error {
	if opts.JSON {
		return renderJSON(w, res)
	}

	useColor := !opts.NoColor && os.Getenv("NO_COLOR") == ""

	if opts.Details {
		return renderDetailedTerminal(w, res, useColor)
	}

	return renderSimpleTerminal(w, res, useColor)
}

func renderJSON(w io.Writer, res *model.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(res)
}

func renderSimpleTerminal(w io.Writer, res *model.Result, useColor bool) error {
	title := res.Assessment.Title
	if title == "" {
		title = res.Assessment.Summary
	}

	symbol, colorCode := getSymbolAndColor(res.Assessment.Scenario)

	var header string
	if symbol != "" {
		if useColor && colorCode != "" {
			header = fmt.Sprintf("AZPE\n\n%s%s %s%s", colorCode, symbol, title, colorReset)
		} else {
			header = fmt.Sprintf("AZPE\n\n%s %s", symbol, title)
		}
	} else {
		if useColor {
			header = fmt.Sprintf("AZPE\n\n%s%s%s", colorBold, title, colorReset)
		} else {
			header = fmt.Sprintf("AZPE\n\n%s", title)
		}
	}

	fmt.Fprintf(w, "%s\n\n%s\n", header, res.Assessment.Summary)

	return nil
}

func renderDetailedTerminal(w io.Writer, res *model.Result, useColor bool) error {
	sectionHeader := func(title string) string {
		if useColor {
			return fmt.Sprintf("%s=== %s ===%s", colorCyan+colorBold, title, colorReset)
		}
		return fmt.Sprintf("=== %s ===", title)
	}

	fmt.Fprintln(w, sectionHeader("Target"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Original             %s\n", res.Target.OriginalInput)
	fmt.Fprintf(w, "Normalized           %s://%s:%d%s\n", res.Target.Scheme, res.Target.Hostname, res.Target.Port, target.RedactQueryValues(res.Target.RequestPath))
	fmt.Fprintf(w, "Target type          %s\n", formatTargetType(res.Target.TargetType))
	if res.Target.AzureServiceFamily != "" && res.Target.AzureServiceFamily != "NONE" {
		fmt.Fprintf(w, "Azure service        %s\n", res.Target.AzureServiceFamily.DisplayName())
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, sectionHeader("DNS"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Status               %s\n", formatDNSStatus(res.DNS.Status))
	fmt.Fprintf(w, "Query hostname       %s\n", res.DNS.QueryHostname)
	fmt.Fprintf(w, "Resolution time      %d ms\n", res.DNS.DurationMs)
	fmt.Fprintf(w, "Address result       %s\n", formatAggregateClassification(res.DNS.AggregateClassification))
	if res.DNS.IsIPLiteral {
		fmt.Fprintln(w, "Note                 Target is an IP literal. Hostname DNS resolution bypassed.")
	}
	if res.DNS.ErrorMessage != "" {
		fmt.Fprintf(w, "Error                [%s] %s\n", res.DNS.ErrorCategory, res.DNS.ErrorMessage)
	}
	fmt.Fprintln(w)

	if len(res.DNS.Addresses) > 0 {
		fmt.Fprintln(w, "Addresses:")
		for _, addr := range res.DNS.Addresses {
			fmt.Fprintf(w, "  - %s (%s, %s)\n", addr.Address, addr.Version, formatAddressClassification(addr.Classification))
		}
		fmt.Fprintln(w)
	}

	// Render TCP Connection details if performed
	if res.TCP.AggregateStatus != assess.AggregateTCPNotAttempted && res.TCP.AggregateStatus != assess.AggregateTCPNotApplicable && res.TCP.AggregateStatus != "" {
		fmt.Fprintln(w, sectionHeader("Connection"))
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Status               %s\n", formatAggregateTCPStatus(res.TCP.AggregateStatus))
		fmt.Fprintf(w, "Port                 %d\n", res.TCP.Port)
		fmt.Fprintf(w, "Total duration       %s\n", formatDuration(res.TCP.DurationMs))
		fmt.Fprintln(w)

		if len(res.TCP.Results) > 0 {
			fmt.Fprintln(w, "Results:")
			for _, r := range res.TCP.Results {
				fmt.Fprintf(w, "  - %s\n", r.Destination)
				fmt.Fprintf(w, "    Status           %s\n", formatTCPAddressStatus(r.Status))
				fmt.Fprintf(w, "    Duration         %s\n", formatDuration(r.DurationMs))
				if r.ErrorCategory != "" {
					fmt.Fprintf(w, "    Error category   %s\n", r.ErrorCategory)
				}
				if r.Error != "" {
					fmt.Fprintf(w, "    Error            %s\n", r.Error)
				}
			}
			fmt.Fprintln(w)
		}
	}

	// Render TLS details if performed
	if res.TLS.AggregateStatus != assess.AggregateTLSNotAttempted && res.TLS.AggregateStatus != assess.AggregateTLSNotApplicable && res.TLS.AggregateStatus != "" {
		fmt.Fprintln(w, sectionHeader("TLS"))
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Status               %s\n", formatAggregateTLSStatus(res.TLS.AggregateStatus))
		fmt.Fprintf(w, "Server name          %s\n", res.TLS.ServerName)
		fmt.Fprintf(w, "Total duration       %s\n", formatDuration(res.TLS.DurationMs))
		fmt.Fprintln(w)

		if len(res.TLS.Results) > 0 {
			fmt.Fprintln(w, "Results:")
			for _, r := range res.TLS.Results {
				fmt.Fprintf(w, "  - %s\n", r.Destination)
				fmt.Fprintf(w, "    Status           %s\n", formatTLSAddressStatus(r.Status))
				if r.Stage != "" && r.Stage != "COMPLETE" {
					fmt.Fprintf(w, "    Stage            %s\n", r.Stage)
				}
				fmt.Fprintf(w, "    Duration         %s\n", formatDuration(r.DurationMs))
				if r.TLSVersion != "" {
					fmt.Fprintf(w, "    TLS version      %s\n", r.TLSVersion)
				}
				if r.CipherSuite != "" {
					fmt.Fprintf(w, "    Cipher suite     %s\n", r.CipherSuite)
				}
				if r.HostnameValid != nil {
					hVal := "Matches"
					if !*r.HostnameValid {
						hVal = "Mismatch"
					}
					fmt.Fprintf(w, "    Hostname         %s\n", hVal)
				}
				if r.CertificateTrusted != nil {
					tVal := "Trusted"
					if !*r.CertificateTrusted {
						tVal = "Not trusted"
					}
					fmt.Fprintf(w, "    Certificate      %s\n", tVal)
				}
				if r.LeafCertificate != nil {
					if r.LeafCertificate.Subject != "" {
						fmt.Fprintf(w, "    Subject          %s\n", r.LeafCertificate.Subject)
					}
					if r.LeafCertificate.Issuer != "" {
						fmt.Fprintf(w, "    Issuer           %s\n", r.LeafCertificate.Issuer)
					}
					if r.LeafCertificate.NotBefore != "" {
						fmt.Fprintf(w, "    Valid from       %s\n", r.LeafCertificate.NotBefore)
					}
					if r.LeafCertificate.NotAfter != "" {
						fmt.Fprintf(w, "    Valid until      %s\n", r.LeafCertificate.NotAfter)
					}
				}
				if r.ErrorCategory != "" {
					fmt.Fprintf(w, "    Error category   %s\n", r.ErrorCategory)
				}
				if r.Error != "" {
					fmt.Fprintf(w, "    Error            %s\n", r.Error)
				}
			}
			fmt.Fprintln(w)
		}
	}

	// Render HTTP details if performed
	if res.HTTP.AggregateStatus != assess.AggregateHTTPNotAttempted && res.HTTP.AggregateStatus != assess.AggregateHTTPNotApplicable && res.HTTP.AggregateStatus != "" {
		fmt.Fprintln(w, sectionHeader("HTTP"))
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Status               %s\n", formatAggregateHTTPStatus(res.HTTP.AggregateStatus))
		methodStr := res.HTTP.Method
		if methodStr == "" {
			methodStr = "GET"
		}
		fmt.Fprintf(w, "Method               %s\n", methodStr)
		fmt.Fprintf(w, "Request path         %s\n", target.RedactQueryValues(res.HTTP.Path))
		fmt.Fprintln(w, "Redirects            Not followed")
		fmt.Fprintf(w, "Total duration       %s\n", formatDuration(res.HTTP.DurationMs))
		fmt.Fprintln(w)

		if len(res.HTTP.Results) > 0 {
			fmt.Fprintln(w, "Results:")
			for _, r := range res.HTTP.Results {
				fmt.Fprintf(w, "  - %s\n", r.Destination)
				fmt.Fprintf(w, "    Host             %s\n", r.Host)
				if r.StatusCode > 0 {
					fmt.Fprintf(w, "    Status           %d %s\n", r.StatusCode, r.StatusText)
					fmt.Fprintf(w, "    Category         %s\n", formatHTTPResponseCategory(r.ResponseCategory))
				} else {
					fmt.Fprintf(w, "    Status           %s\n", formatHTTPAddressStatus(r.Status))
				}
				fmt.Fprintf(w, "    Duration         %s\n", formatDuration(r.DurationMs))
				if r.Headers != nil {
					if r.Headers.ContentType != "" {
						fmt.Fprintf(w, "    Content type     %s\n", r.Headers.ContentType)
					}
					if r.Headers.RequestID != "" {
						fmt.Fprintf(w, "    Request ID       %s\n", r.Headers.RequestID)
					}
					if r.Headers.Location != "" {
						fmt.Fprintf(w, "    Location         %s\n", r.Headers.Location)
					}
				}
				if r.ErrorCategory != "" {
					fmt.Fprintf(w, "    Error category   %s\n", r.ErrorCategory)
				}
				if r.Error != "" {
					fmt.Fprintf(w, "    Error            %s\n", r.Error)
				}
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, sectionHeader("Tests"))
	fmt.Fprintln(w)
	dnsTestStr := "Completed"
	if res.DNS.Status == assess.DNSStatusFailure || res.DNS.Status == assess.DNSStatusNotFound || res.DNS.Status == assess.DNSStatusTimeout {
		dnsTestStr = "Failed"
	}
	fmt.Fprintf(w, "DNS                  %s\n", dnsTestStr)

	tcpTestStr := "Not performed"
	if res.TCP.AggregateStatus != assess.AggregateTCPNotAttempted && res.TCP.AggregateStatus != assess.AggregateTCPNotApplicable && res.TCP.AggregateStatus != "" {
		tcpTestStr = "Completed"
	}
	fmt.Fprintf(w, "Connection           %s\n", tcpTestStr)

	tlsTestStr := "Not performed"
	if res.TLS.AggregateStatus != assess.AggregateTLSNotAttempted && res.TLS.AggregateStatus != assess.AggregateTLSNotApplicable && res.TLS.AggregateStatus != "" {
		tlsTestStr = "Completed"
	}
	fmt.Fprintf(w, "TLS                  %s\n", tlsTestStr)

	httpTestStr := "Not performed"
	if res.HTTP.AggregateStatus != assess.AggregateHTTPNotAttempted && res.HTTP.AggregateStatus != assess.AggregateHTTPNotApplicable && res.HTTP.AggregateStatus != "" {
		httpTestStr = "Completed"
	}
	fmt.Fprintf(w, "HTTP                 %s\n", httpTestStr)
	fmt.Fprintln(w)

	if len(res.Warnings) > 0 {
		fmt.Fprintln(w, sectionHeader("Warnings"))
		fmt.Fprintln(w)
		for _, warn := range res.Warnings {
			if useColor {
				fmt.Fprintf(w, "  %s- %s%s\n", colorYellow, warn, colorReset)
			} else {
				fmt.Fprintf(w, "  - %s\n", warn)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, sectionHeader("Assessment"))
	fmt.Fprintln(w)

	title := res.Assessment.Title
	if title != "" && !strings.HasSuffix(title, ".") {
		title += "."
	}
	fmt.Fprintf(w, "%s\n", title)

	if res.Assessment.Explanation != "" {
		fmt.Fprintf(w, "\n%s", res.Assessment.Explanation)
	}
	if res.Assessment.Impact != "" {
		fmt.Fprintf(w, " %s\n", res.Assessment.Impact)
	} else {
		fmt.Fprintln(w)
	}

	if res.Assessment.NextAction != "" {
		fmt.Fprintf(w, "\nSuggested next step:\n%s\n", res.Assessment.NextAction)
	}

	return nil
}

func getSymbolAndColor(scenario assess.AssessmentScenario) (string, string) {
	switch scenario {
	case assess.ScenarioPrivateDNSActive, assess.ScenarioPrivateTCPReachable, assess.ScenarioPrivateTLSValid,
		assess.ScenarioPrivateHTTPResponded, assess.ScenarioPrivateHTTPAuthRequired, assess.ScenarioPrivateHTTPAccessDenied,
		assess.ScenarioPrivateHTTPNotFound, assess.ScenarioPrivateHTTPMethodNotAllowed, assess.ScenarioPrivateHTTPThrottled,
		assess.ScenarioPrivateHTTPServerError, assess.ScenarioPrivateHTTPRedirect:
		return "✓", colorGreen
	case assess.ScenarioPrivateDNSNotActive, assess.ScenarioDNSLookupFailed, assess.ScenarioPrivateTCPUnreachable,
		assess.ScenarioPrivateTLSFailed, assess.ScenarioPrivateTLSHostnameMismatch, assess.ScenarioPrivateTLSUntrusted,
		assess.ScenarioPrivateTLSExpired, assess.ScenarioPrivateTLSTimeout, assess.ScenarioPrivateHTTPFailed,
		assess.ScenarioPrivateHTTPTimeout, assess.ScenarioPrivateHTTPMalformed, assess.ScenarioPrivateHTTPTransportFailed:
		return "✗", colorRed
	case assess.ScenarioDNSMixed, assess.ScenarioSpecialOnly, assess.ScenarioPrivateTCPPartial, assess.ScenarioPrivateTLSPartial, assess.ScenarioPrivateHTTPPartial:
		return "⚠", colorYellow
	default:
		return "", ""
	}
}

func formatTargetType(tt target.TargetType) string {
	switch tt {
	case target.TargetTypeRecognizedAzure:
		return "Recognized Azure service"
	case target.TargetTypePossibleAzure:
		return "Possible Azure service"
	case target.TargetTypeUnrecognized:
		return "Unrecognized target"
	case target.TargetTypeIPLiteral:
		return "IP literal"
	default:
		return string(tt)
	}
}

func formatDNSStatus(status assess.DNSStatus) string {
	switch status {
	case assess.DNSStatusSuccess:
		return "Success"
	case assess.DNSStatusNotFound:
		return "Host Not Found"
	case assess.DNSStatusTimeout:
		return "Timeout"
	case assess.DNSStatusTemporaryFailure:
		return "Temporary Failure"
	case assess.DNSStatusNotApplicable:
		return "Not Applicable (IP Literal)"
	default:
		return string(status)
	}
}

func formatAggregateClassification(agg assess.AggregateClassification) string {
	switch agg {
	case assess.AggregatePrivateOnly:
		return "Private addresses only"
	case assess.AggregatePublicOnly:
		return "Public addresses only"
	case assess.AggregateMixedPrivatePublic:
		return "Mixed private and public addresses"
	case assess.AggregateSpecialOnly:
		return "Special-purpose addresses only"
	case assess.AggregateNone:
		return "None"
	default:
		return string(agg)
	}
}

func formatAddressClassification(cls assess.AddressClassification) string {
	switch cls {
	case assess.AddrPrivate:
		return "private"
	case assess.AddrPublic:
		return "public"
	case assess.AddrLoopback:
		return "loopback"
	case assess.AddrLinkLocal:
		return "link-local"
	case assess.AddrUnspecified:
		return "unspecified"
	case assess.AddrMulticast:
		return "multicast"
	case assess.AddrDocumentation:
		return "documentation"
	case assess.AddrBenchmark:
		return "benchmark"
	case assess.AddrReserved:
		return "reserved"
	default:
		return string(cls)
	}
}

func formatAggregateTCPStatus(agg assess.AggregateTCPStatus) string {
	switch agg {
	case assess.AggregateTCPAllConnected:
		return "All addresses connected"
	case assess.AggregateTCPNoneConnected:
		return "No addresses connected"
	case assess.AggregateTCPPartiallyConnected:
		return "Some addresses connected"
	case assess.AggregateTCPNotAttempted:
		return "Not attempted"
	case assess.AggregateTCPNotApplicable:
		return "Not applicable"
	case assess.AggregateTCPCanceled:
		return "Canceled"
	default:
		return string(agg)
	}
}

func formatTCPAddressStatus(status assess.TCPAddressStatus) string {
	switch status {
	case assess.TCPAddrConnected:
		return "Connected"
	case assess.TCPAddrTimedOut:
		return "Timed out"
	case assess.TCPAddrConnectionRefused:
		return "Connection refused"
	case assess.TCPAddrUnreachable:
		return "Unreachable"
	case assess.TCPAddrCanceled:
		return "Canceled"
	case assess.TCPAddrError:
		return "Error"
	default:
		return string(status)
	}
}

func formatAggregateTLSStatus(agg assess.AggregateTLSStatus) string {
	switch agg {
	case assess.AggregateTLSAllValid:
		return "Valid for all addresses"
	case assess.AggregateTLSNoneValid:
		return "No addresses passed TLS validation"
	case assess.AggregateTLSPartiallyValid:
		return "Some addresses valid"
	case assess.AggregateTLSNotAttempted:
		return "Not attempted"
	case assess.AggregateTLSNotApplicable:
		return "Not applicable"
	case assess.AggregateTLSCanceled:
		return "Canceled"
	default:
		return string(agg)
	}
}

func formatTLSAddressStatus(status assess.TLSAddressStatus) string {
	switch status {
	case assess.TLSAddrValid:
		return "Valid"
	case assess.TLSAddrHostnameMismatch:
		return "Hostname mismatch"
	case assess.TLSAddrUntrustedCertificate:
		return "Certificate not trusted"
	case assess.TLSAddrExpiredCertificate:
		return "Certificate expired"
	case assess.TLSAddrNotYetValid:
		return "Certificate not yet valid"
	case assess.TLSAddrHandshakeTimeout:
		return "Timed out"
	case assess.TLSAddrHandshakeFailed:
		return "Failed"
	case assess.TLSAddrConnectionClosed:
		return "Connection closed"
	case assess.TLSAddrCanceled:
		return "Canceled"
	case assess.TLSAddrError:
		return "Error"
	default:
		return string(status)
	}
}

func formatAggregateHTTPStatus(agg assess.AggregateHTTPStatus) string {
	switch agg {
	case assess.AggregateHTTPAllResponded:
		return "Response received from all addresses"
	case assess.AggregateHTTPNoneResponded:
		return "No addresses returned an HTTP response"
	case assess.AggregateHTTPPartiallyResponded:
		return "Some addresses returned an HTTP response"
	case assess.AggregateHTTPNotAttempted:
		return "Not attempted"
	case assess.AggregateHTTPNotApplicable:
		return "Not applicable"
	case assess.AggregateHTTPCanceled:
		return "Canceled"
	default:
		return string(agg)
	}
}

func formatHTTPAddressStatus(status assess.HTTPAddressStatus) string {
	switch status {
	case assess.HTTPAddrResponded:
		return "Responded"
	case assess.HTTPAddrTimeout:
		return "Response timed out"
	case assess.HTTPAddrConnectionFailed:
		return "Connection failed"
	case assess.HTTPAddrTLSFailed:
		return "TLS failed"
	case assess.HTTPAddrMalformedResponse:
		return "Malformed HTTP"
	case assess.HTTPAddrConnectionClosed:
		return "Connection closed"
	case assess.HTTPAddrCanceled:
		return "Canceled"
	case assess.HTTPAddrError:
		return "Error"
	default:
		return string(status)
	}
}

func formatHTTPResponseCategory(cat assess.HTTPResponseCategory) string {
	switch cat {
	case assess.HTTPCatSuccess:
		return "Success"
	case assess.HTTPCatAuthenticationRequired:
		return "Authentication required"
	case assess.HTTPCatAccessDenied:
		return "Access denied"
	case assess.HTTPCatNotFound:
		return "Not found"
	case assess.HTTPCatMethodNotAllowed:
		return "Method not allowed"
	case assess.HTTPCatConflict:
		return "Conflict"
	case assess.HTTPCatThrottled:
		return "Throttled"
	case assess.HTTPCatServerError:
		return "Server error"
	case assess.HTTPCatRedirection:
		return "Redirection"
	case assess.HTTPCatClientError:
		return "Client error"
	case assess.HTTPCatInformational:
		return "Informational"
	default:
		return string(cat)
	}
}

func formatDuration(ms int64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.3f s", float64(ms)/1000.0)
	}
	return fmt.Sprintf("%d ms", ms)
}
