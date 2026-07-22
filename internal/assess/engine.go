package assess

import (
	"fmt"
	"strings"

	"github.com/azpe/azpe/internal/target"
)

// AssessmentScenario identifies the human-facing UX scenario.
type AssessmentScenario string

const (
	ScenarioPrivateDNSActive    AssessmentScenario = "PRIVATE_DNS_ACTIVE"
	ScenarioPrivateDNSNotActive AssessmentScenario = "PRIVATE_DNS_NOT_ACTIVE"
	ScenarioDNSLookupFailed     AssessmentScenario = "DNS_LOOKUP_FAILED"
	ScenarioDNSMixed            AssessmentScenario = "DNS_MIXED"
	ScenarioIPLiteral           AssessmentScenario = "IP_LITERAL"
	ScenarioUnrecognizedTarget  AssessmentScenario = "UNRECOGNIZED_TARGET"
	ScenarioPossibleAzure       AssessmentScenario = "POSSIBLE_AZURE"
	ScenarioSpecialOnly         AssessmentScenario = "SPECIAL_ONLY"
)

// Evaluation represents the structured outcome of the assessment decision engine.
type Evaluation struct {
	Scenario    AssessmentScenario
	ExitCode    int
	Title       string
	Explanation string
	Impact      string
	Summary     string
	State       AssessmentState
	LikelyOwner LikelyOwner
	NextAction  string
	Warnings    []string
}

// Evaluate determines the Assessment result and UX scenario from target and DNS observations.
func Evaluate(tgt *target.Target, dnsStatus DNSStatus, aggClass AggregateClassification, addresses []string, classifications []AddressClassification, errCat, errMsg string) Evaluation {
	// 1. IP Literal Target
	if tgt.TargetType == target.TargetTypeIPLiteral {
		ex := "An IP address was provided instead of an Azure service hostname."
		imp := "An IP address cannot test Private Endpoint DNS."
		exampleHost := "myvault.vault.azure.net"
		sum := fmt.Sprintf("You entered an IP address:\n%s\n\n%s\n\nUse the hostname configured in your application, for example:\n  %s", tgt.Hostname, imp, exampleHost)
		if strings.Contains(tgt.Hostname, ":") {
			sum = fmt.Sprintf("You entered an IP address:\n%s\n\n%s\n\nUse the Azure service hostname configured in your application.", tgt.Hostname, imp)
		}
		return Evaluation{
			Scenario:    ScenarioIPLiteral,
			ExitCode:    8,
			Title:       "The Azure service hostname is required",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerUnknown,
			NextAction:  "Use the Azure service hostname configured in your application.",
		}
	}

	// 2. Unrecognized Non-Azure Target
	if tgt.TargetType == target.TargetTypeUnrecognized {
		ex := fmt.Sprintf("%s is not a recognized Azure Private Endpoint service hostname.", tgt.Hostname)
		imp := "AZPE can only diagnose recognized Azure Private Endpoint targets."
		sum := fmt.Sprintf("%s\n\nUse the Azure service hostname configured in your application, for example:\n  myvault.vault.azure.net\n  mystorage.blob.core.windows.net\n  mysearch.search.windows.net", ex)
		return Evaluation{
			Scenario:    ScenarioUnrecognizedTarget,
			ExitCode:    8,
			Title:       "Cannot test this target",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerUnknown,
			NextAction:  "Use the Azure service hostname configured in your application.",
		}
	}

	// 3. Possible Azure Service (Not fully recognized in catalog)
	if tgt.TargetType == target.TargetTypePossibleAzure {
		ex := "AZPE's service catalogue does not recognize this specific Azure hostname pattern yet."
		imp := "No Private Endpoint conclusion was made."
		sum := fmt.Sprintf("%s\n\n%s\n\nYou can use --details to view target information.", tgt.Hostname, imp)
		return Evaluation{
			Scenario:    ScenarioPossibleAzure,
			ExitCode:    8,
			Title:       "This Azure service is not supported yet",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerUnknown,
			NextAction:  "You can use --details to view target information.",
		}
	}

	// 4. Recognized Azure Service Hostname - Evaluate DNS Results
	switch dnsStatus {
	case DNSStatusNotFound, DNSStatusTimeout, DNSStatusTemporaryFailure, DNSStatusFailure:
		ex := "The Azure service hostname could not be resolved."
		imp := "DNS resolution failed from this execution environment."
		sum := fmt.Sprintf("%s\n\nWhat to do:\nRun this check inside the affected workload. If it still fails, send this result to your network or DNS team.", tgt.Hostname)
		return Evaluation{
			Scenario:    ScenarioDNSLookupFailed,
			ExitCode:    3,
			Title:       "The Azure service name cannot be resolved",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentBroken,
			LikelyOwner: OwnerDNSOrNetwork,
			NextAction:  "Run this check inside the affected workload. If it still fails, send this result to your network or DNS team.",
		}
	}

	switch aggClass {
	case AggregatePrivateOnly:
		var lines []string
		for _, addr := range addresses {
			lines = append(lines, fmt.Sprintf("%s → %s (private)", tgt.Hostname, addr))
		}
		addrBlock := strings.Join(lines, "\n")
		ex := "The service name points to a private address from this workload."
		if len(addresses) > 1 {
			ex = "The service name points to private addresses from this workload."
		}
		imp := "Connection not tested yet."
		sum := fmt.Sprintf("%s\n\n%s\n\n%s", addrBlock, ex, imp)
		return Evaluation{
			Scenario:    ScenarioPrivateDNSActive,
			ExitCode:    0,
			Title:       "Private DNS looks correct",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerUnknown,
			NextAction:  "",
		}

	case AggregatePublicOnly:
		var lines []string
		for _, addr := range addresses {
			lines = append(lines, fmt.Sprintf("%s → %s (public)", tgt.Hostname, addr))
		}
		addrBlock := strings.Join(lines, "\n")
		ex := "The Azure service resolved to public addresses."
		imp := "The application will attempt to use the public Azure endpoint."
		if len(addresses) > 1 {
			imp = "The application will attempt to use a public Azure endpoint."
		}
		sum := fmt.Sprintf("%s\n\n%s\n\nWhat to do:\nIf you ran AZPE inside the affected workload, send this result to your network or DNS team.", addrBlock, imp)
		return Evaluation{
			Scenario:    ScenarioPrivateDNSNotActive,
			ExitCode:    4,
			Title:       "This workload is not using private DNS",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentNotPrivate,
			LikelyOwner: OwnerDNSOrNetwork,
			NextAction:  "If this test ran inside the affected workload, send this result to your network or DNS team.",
		}

	case AggregateMixedPrivatePublic:
		var lines []string
		var hasV4Priv, hasV6Pub bool
		for i, addr := range addresses {
			clsStr := "public"
			if i < len(classifications) && classifications[i] == AddrPrivate {
				clsStr = "private"
				if strings.Contains(addr, ".") {
					hasV4Priv = true
				}
			} else {
				if strings.Contains(addr, ":") {
					hasV6Pub = true
				}
			}
			lines = append(lines, fmt.Sprintf("%s → %s (%s)", tgt.Hostname, addr, clsStr))
		}

		if hasV4Priv && hasV6Pub {
			lines = nil
			for i, addr := range addresses {
				clsStr := "public"
				verStr := "IPv4"
				if strings.Contains(addr, ":") {
					verStr = "IPv6"
				}
				if i < len(classifications) && classifications[i] == AddrPrivate {
					clsStr = "private"
				}
				lines = append(lines, fmt.Sprintf("%s → %s (%s, %s)", tgt.Hostname, addr, verStr, clsStr))
			}
		}

		addrBlock := strings.Join(lines, "\n")
		ex := "DNS returned a mixture of private and public IP addresses."
		imp := "The application may use different network paths depending on which address it selects."
		sum := fmt.Sprintf("%s\n\n%s\n\nWhat to do:\nSend this result to your network or DNS team.", addrBlock, imp)
		return Evaluation{
			Scenario:    ScenarioDNSMixed,
			ExitCode:    8,
			Title:       "DNS is returning both private and public addresses",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerDNSOrNetwork,
			NextAction:  "Send this result to your network or DNS team.",
			Warnings:    []string{"DNS returned a mixture of private and public IP addresses."},
		}

	case AggregateSpecialOnly:
		title := "DNS returned an unexpected address"
		if len(addresses) > 1 {
			title = "DNS returned unexpected addresses"
		}
		var lines []string
		for i, addr := range addresses {
			label := "special"
			if i < len(classifications) {
				label = formatAddressClassificationLabel(classifications[i])
			}
			lines = append(lines, fmt.Sprintf("%s → %s (%s)", tgt.Hostname, addr, label))
		}
		addrBlock := strings.Join(lines, "\n")
		ex := "DNS returned special-purpose IP addresses."
		imp := "This result cannot be used to evaluate Azure Private Endpoint connectivity."
		sum := fmt.Sprintf("%s\n\n%s\n\nWhat to do:\nSend the detailed result to your network or DNS team.", addrBlock, imp)
		return Evaluation{
			Scenario:    ScenarioSpecialOnly,
			ExitCode:    8,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerDNSOrNetwork,
			NextAction:  "Send the detailed result to your network or DNS team.",
		}

	default:
		ex := "DNS returned an ambiguous response."
		imp := "This result cannot be used to evaluate Azure Private Endpoint connectivity."
		sum := fmt.Sprintf("%s\n\nWhat to do:\nSend this result to your network or DNS team.", tgt.Hostname)
		return Evaluation{
			Scenario:    ScenarioDNSMixed,
			ExitCode:    8,
			Title:       "DNS result is inconclusive",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentUnknown,
			LikelyOwner: OwnerDNSOrNetwork,
			NextAction:  "Send this result to your network or DNS team.",
		}
	}
}

func formatAddressClassificationLabel(cls AddressClassification) string {
	switch cls {
	case AddrPrivate:
		return "private"
	case AddrPublic:
		return "public"
	case AddrLoopback:
		return "loopback"
	case AddrLinkLocal:
		return "link-local"
	case AddrUnspecified:
		return "unspecified"
	case AddrMulticast:
		return "multicast"
	case AddrDocumentation:
		return "documentation"
	case AddrBenchmark:
		return "benchmark"
	case AddrReserved:
		return "reserved"
	default:
		return "unknown"
	}
}
