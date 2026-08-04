package assess

import (
	"fmt"
	"strings"

	"github.com/nukabo/azpe/internal/target"
)

func evaluateIPLiteral(tgt *target.Target) Evaluation {
	ex := "An IP address was provided instead of an Azure service hostname."
	imp := "An IP address cannot test Private Endpoint DNS."
	exampleHost := "myvault.vault.azure.net"
	sum := fmt.Sprintf("You entered an IP address:\n%s\n\n%s\n\nUse the hostname configured in your application, for example:\n  %s", tgt.Hostname, imp, exampleHost)
	if strings.Contains(tgt.Hostname, ":") {
		sum = fmt.Sprintf("You entered an IP address:\n%s\n\n%s\n\nUse the Azure service hostname configured in your application.", tgt.Hostname, imp)
	}
	return Evaluation{
		Code:        CodeInconclusive,
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

func evaluateUnrecognizedTarget(tgt *target.Target) Evaluation {
	ex := fmt.Sprintf("%s is not a recognized Azure Private Endpoint service hostname.", tgt.Hostname)
	imp := "AZPE can only diagnose recognized Azure Private Endpoint targets."
	sum := fmt.Sprintf("%s\n\nUse the Azure service hostname configured in your application, for example:\n  myvault.vault.azure.net\n  mystorage.blob.core.windows.net\n  mysearch.search.windows.net", ex)
	return Evaluation{
		Code:        CodeInconclusive,
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

func evaluatePossibleAzure(tgt *target.Target) Evaluation {
	ex := "AZPE's service catalogue does not recognize this specific Azure hostname pattern yet."
	imp := "No Private Endpoint conclusion was made."
	sum := fmt.Sprintf("%s\n\n%s\n\nYou can use --details to view target information.", tgt.Hostname, imp)
	return Evaluation{
		Code:        CodeInconclusive,
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

func evaluateDNSLookupFailed(tgt *target.Target, dnsStatus DNSStatus) Evaluation {
	code := CodeDNSFailure
	if dnsStatus == DNSStatusTimeout {
		code = CodeDNSTimeout
	}
	ex := "The Azure service hostname could not be resolved."
	imp := "DNS resolution failed from this execution environment."
	sum := fmt.Sprintf("%s\n\nWhat to do:\nRun this check inside the affected workload. If it still fails, send this result to your network or DNS team.", tgt.Hostname)
	return Evaluation{
		Code:        code,
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

func evaluatePublicOnly(tgt *target.Target, addresses []string) Evaluation {
	var lines []string
	for _, ip := range addresses {
		lines = append(lines, fmt.Sprintf("%s → %s (public)", tgt.Hostname, ip))
	}
	addrBlock := strings.Join(lines, "\n")

	ex := "The Azure service hostname resolved to public IP addresses."
	imp := "The application will access the Azure service over the public internet."
	sum := fmt.Sprintf("%s\n\n%s\n\nWhat to do:\nIf this workload should connect privately, check the workload's DNS configuration or contact your network/DNS team.", addrBlock, imp)

	return Evaluation{
		Code:        CodeUnexpectedPublicResolution,
		Scenario:    ScenarioPrivateDNSNotActive,
		ExitCode:    4,
		Title:       "This workload is not using private DNS",
		Explanation: ex,
		Impact:      imp,
		Summary:     sum,
		State:       AssessmentNotPrivate,
		LikelyOwner: OwnerDNSOrNetwork,
		NextAction:  "If this workload should connect privately, check the workload's DNS configuration or contact your network/DNS team.",
	}
}

func evaluateMixedDNS(tgt *target.Target, addresses []string, classifications []AddressClassification) Evaluation {
	var lines []string
	for i, ip := range addresses {
		classStr := "unknown"
		if i < len(classifications) {
			classStr = strings.ToLower(string(classifications[i]))
		}
		lines = append(lines, fmt.Sprintf("%s → %s (%s)", tgt.Hostname, ip, classStr))
	}
	addrBlock := strings.Join(lines, "\n")

	ex := "DNS resolution returned a mix of private and public IP addresses."
	imp := "Connectivity behavior is unpredictable."
	sum := fmt.Sprintf("%s\n\n%s\n\nWhat to do:\nContact your network/DNS team to fix DNS resolution for this hostname.", addrBlock, imp)

	return Evaluation{
		Code:        CodeMixedAddressResolution,
		Scenario:    ScenarioDNSMixed,
		ExitCode:    8,
		Title:       "DNS is returning both private and public addresses",
		Explanation: ex,
		Impact:      imp,
		Summary:     sum,
		State:       AssessmentUnknown,
		LikelyOwner: OwnerDNSOrNetwork,
		NextAction:  "Contact your network/DNS team to fix DNS resolution for this hostname.",
	}
}

func evaluateSpecialOnly(tgt *target.Target, addresses []string, classifications []AddressClassification) Evaluation {
	var lines []string
	for i, ip := range addresses {
		classStr := "unknown"
		if i < len(classifications) {
			classStr = strings.ToLower(string(classifications[i]))
		}
		lines = append(lines, fmt.Sprintf("%s → %s (%s)", tgt.Hostname, ip, classStr))
	}
	addrBlock := strings.Join(lines, "\n")

	ex := "DNS resolved to special-purpose IP addresses (loopback, link-local, or reserved)."
	imp := "This is not a standard Azure Private Endpoint configuration."
	sum := fmt.Sprintf("%s\n\n%s\n\nWhat to do:\nCheck your DNS settings or local hosts file.", addrBlock, imp)

	return Evaluation{
		Code:        CodeInconclusive,
		Scenario:    ScenarioSpecialOnly,
		ExitCode:    8,
		Title:       "DNS resolved to special-purpose IP addresses",
		Explanation: ex,
		Impact:      imp,
		Summary:     sum,
		State:       AssessmentUnknown,
		LikelyOwner: OwnerDNSOrNetwork,
		NextAction:  "Check your DNS settings or local hosts file.",
	}
}
