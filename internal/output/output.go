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
	fmt.Fprintf(w, "Normalized           %s://%s:%d%s\n", res.Target.Scheme, res.Target.Hostname, res.Target.Port, res.Target.RequestPath)
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

	fmt.Fprintln(w, sectionHeader("Tests"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "DNS                  Completed")
	fmt.Fprintln(w, "Connection           Not performed")
	fmt.Fprintln(w, "TLS                  Not performed")
	fmt.Fprintln(w, "HTTP                 Not performed")
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
	case assess.ScenarioPrivateDNSActive:
		return "✓", colorGreen
	case assess.ScenarioPrivateDNSNotActive, assess.ScenarioDNSLookupFailed:
		return "✗", colorRed
	case assess.ScenarioDNSMixed, assess.ScenarioSpecialOnly:
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
