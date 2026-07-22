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

	// Phase 3 TCP Scenarios
	ScenarioPrivateTCPReachable   AssessmentScenario = "PRIVATE_TCP_REACHABLE"
	ScenarioPrivateTCPUnreachable AssessmentScenario = "PRIVATE_TCP_UNREACHABLE"
	ScenarioPrivateTCPPartial     AssessmentScenario = "PRIVATE_TCP_PARTIAL"

	// Phase 4 TLS Scenarios
	ScenarioPrivateTLSValid            AssessmentScenario = "PRIVATE_TLS_VALID"
	ScenarioPrivateTLSFailed           AssessmentScenario = "PRIVATE_TLS_FAILED"
	ScenarioPrivateTLSPartial          AssessmentScenario = "PRIVATE_TLS_PARTIAL"
	ScenarioPrivateTLSHostnameMismatch AssessmentScenario = "PRIVATE_TLS_HOSTNAME_MISMATCH"
	ScenarioPrivateTLSUntrusted        AssessmentScenario = "PRIVATE_TLS_UNTRUSTED"
	ScenarioPrivateTLSExpired          AssessmentScenario = "PRIVATE_TLS_EXPIRED"
	ScenarioPrivateTLSTimeout          AssessmentScenario = "PRIVATE_TLS_TIMEOUT"
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

// MinimalTCPObservation contains fields required for Evaluation without importing model package.
type MinimalTCPObservation interface {
	GetAggregateStatus() AggregateTCPStatus
	GetResults() []MinimalTCPResultItem
}

// MinimalTCPResultItem interface for per-address TCP result details.
type MinimalTCPResultItem interface {
	GetAddress() string
	GetDestination() string
	GetPort() int
	GetStatus() TCPAddressStatus
	GetDurationMs() int64
	GetErrorCategory() string
	GetError() string
}

// MinimalTLSObservation contains fields required for Evaluation without importing model package.
type MinimalTLSObservation interface {
	GetAggregateStatus() AggregateTLSStatus
	GetServerName() string
	GetResults() []MinimalTLSResultItem
}

// MinimalTLSResultItem interface for per-address TLS result details.
type MinimalTLSResultItem interface {
	GetAddress() string
	GetDestination() string
	GetPort() int
	GetServerName() string
	GetStatus() TLSAddressStatus
	GetStage() string
	GetDurationMs() int64
	GetTLSVersion() string
	GetCipherSuite() string
	GetErrorCategory() string
	GetError() string
}

// Evaluate determines the Assessment result and UX scenario from target, DNS, TCP, and TLS observations.
func Evaluate(tgt *target.Target, dnsStatus DNSStatus, aggClass AggregateClassification, addresses []string, classifications []AddressClassification, errCat, errMsg string, tcpObs MinimalTCPObservation, tlsObs MinimalTLSObservation) Evaluation {
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
		// Evaluate TCP and TLS Probing Results for Private-Only DNS
		if tcpObs != nil && tcpObs.GetAggregateStatus() != AggregateTCPNotAttempted && tcpObs.GetAggregateStatus() != AggregateTCPNotApplicable {
			switch tcpObs.GetAggregateStatus() {
			case AggregateTCPAllConnected:
				// Evaluate Phase 4 TLS Probing
				if tlsObs != nil && tlsObs.GetAggregateStatus() != AggregateTLSNotAttempted && tlsObs.GetAggregateStatus() != AggregateTLSNotApplicable {
					switch tlsObs.GetAggregateStatus() {
					case AggregateTLSAllValid:
						title := "Secure private connection looks correct"
						if len(tlsObs.GetResults()) > 1 {
							title = "Secure private connections look correct"
						}
						var lines []string
						for _, r := range tlsObs.GetResults() {
							if len(tlsObs.GetResults()) == 1 {
								lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
							} else {
								lines = append(lines, fmt.Sprintf("%-18s TLS valid", r.GetDestination()))
							}
						}
						destBlock := strings.Join(lines, "\n")
						connStatusStr := "Working"
						tlsStatusStr := "Valid"
						if len(tlsObs.GetResults()) > 1 {
							connStatusStr = "Working for all addresses"
							tlsStatusStr = "Valid for all addresses"
						}
						ex := "The Azure service hostname resolved privately, and this workload established a valid, trusted TLS connection to every private address."
						imp := "DNS, TCP, and TLS validation look correct. Service response and application authorization remain untested."
						sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\n\nService response and application access not tested yet.", destBlock, connStatusStr, tlsStatusStr)
						return Evaluation{
							Scenario:    ScenarioPrivateTLSValid,
							ExitCode:    0,
							Title:       title,
							Explanation: ex,
							Impact:      imp,
							Summary:     sum,
							State:       AssessmentWorking,
							LikelyOwner: OwnerUnknown,
							NextAction:  "",
						}

					case AggregateTLSNoneValid:
						domStatus := determineDominantTLSStatus(tlsObs.GetResults())
						switch domStatus {
						case TLSAddrHostnameMismatch:
							title := "The certificate does not match the Azure service name"
							var lines []string
							for _, r := range tlsObs.GetResults() {
								lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
							}
							destBlock := strings.Join(lines, "\n")
							ex := "The private address is reachable, but it presented a certificate for a different hostname."
							imp := "The application cannot establish a secure connection because certificate hostname validation failed."
							sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Hostname mismatch\n\nThe address is reachable, but it presented a certificate for a different hostname.\n\nWhat to do:\nSend the detailed result to your network security team.", destBlock)
							return Evaluation{
								Scenario:    ScenarioPrivateTLSHostnameMismatch,
								ExitCode:    6,
								Title:       title,
								Explanation: ex,
								Impact:      imp,
								Summary:     sum,
								State:       AssessmentBroken,
								LikelyOwner: OwnerSecurityOrProxy,
								NextAction:  "Send the detailed result to your network security team.",
							}

						case TLSAddrUntrustedCertificate:
							title := "The certificate is not trusted by this workload"
							var lines []string
							for _, r := range tlsObs.GetResults() {
								lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
							}
							destBlock := strings.Join(lines, "\n")
							ex := "The private address is reachable, but the certificate presented is not trusted by this workload."
							imp := "The application cannot establish a secure connection because certificate trust validation failed."
							sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Certificate not trusted\n\nWhat to do:\nSend the detailed result to your application platform or network security team.", destBlock)
							return Evaluation{
								Scenario:    ScenarioPrivateTLSUntrusted,
								ExitCode:    6,
								Title:       title,
								Explanation: ex,
								Impact:      imp,
								Summary:     sum,
								State:       AssessmentBroken,
								LikelyOwner: OwnerSecurityOrProxy,
								NextAction:  "Send the detailed result to your application platform or network security team.",
							}

						case TLSAddrExpiredCertificate:
							title := "The certificate has expired"
							var lines []string
							for _, r := range tlsObs.GetResults() {
								lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
							}
							destBlock := strings.Join(lines, "\n")
							ex := "The private address is reachable, but the presented certificate has expired."
							imp := "The application cannot establish a secure connection because the certificate is no longer valid."
							sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Certificate expired\n\nWhat to do:\nSend the detailed result to your service owner or network security team.", destBlock)
							return Evaluation{
								Scenario:    ScenarioPrivateTLSExpired,
								ExitCode:    6,
								Title:       title,
								Explanation: ex,
								Impact:      imp,
								Summary:     sum,
								State:       AssessmentBroken,
								LikelyOwner: OwnerSecurityOrProxy,
								NextAction:  "Send the detailed result to your service owner or network security team.",
							}

						case TLSAddrHandshakeTimeout:
							title := "The secure connection timed out"
							var lines []string
							for _, r := range tlsObs.GetResults() {
								lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
							}
							destBlock := strings.Join(lines, "\n")
							ex := "The TCP port is reachable, but the TLS handshake did not finish before the timeout."
							imp := "The workload could not complete TLS negotiation within the operation deadline."
							sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Timed out\n\nThe TCP port is reachable, but the TLS handshake did not finish before the timeout.\n\nWhat to do:\nSend the detailed result to your network security team.", destBlock)
							return Evaluation{
								Scenario:    ScenarioPrivateTLSTimeout,
								ExitCode:    6,
								Title:       title,
								Explanation: ex,
								Impact:      imp,
								Summary:     sum,
								State:       AssessmentBroken,
								LikelyOwner: OwnerSecurityOrProxy,
								NextAction:  "Send the detailed result to your network security team.",
							}

						default:
							title := "The secure connection could not be established"
							var lines []string
							for _, r := range tlsObs.GetResults() {
								lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
							}
							destBlock := strings.Join(lines, "\n")
							ex := "The private address is reachable, but TLS negotiation failed."
							imp := "The application cannot establish a secure TLS connection."
							sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Failed\n\nThe private address is reachable, but TLS negotiation failed.\n\nWhat to do:\nSend the detailed result to your application platform or network security team.", destBlock)
							return Evaluation{
								Scenario:    ScenarioPrivateTLSFailed,
								ExitCode:    6,
								Title:       title,
								Explanation: ex,
								Impact:      imp,
								Summary:     sum,
								State:       AssessmentBroken,
								LikelyOwner: OwnerSecurityOrProxy,
								NextAction:  "Send the detailed result to your application platform or network security team.",
							}
						}

					case AggregateTLSPartiallyValid:
						var lines []string
						for _, r := range tlsObs.GetResults() {
							if r.GetStatus() == TLSAddrValid {
								lines = append(lines, fmt.Sprintf("%-18s TLS valid", r.GetDestination()))
							} else {
								lines = append(lines, fmt.Sprintf("%-18s %s", r.GetDestination(), formatShortTLSFailure(r.GetStatus())))
							}
						}
						destBlock := strings.Join(lines, "\n")
						ex := "At least one private address validated TLS and at least one did not."
						imp := "The application may behave differently depending on which address it uses."
						sum := fmt.Sprintf("%s\n\nThe application may behave differently depending on which address it uses.\n\nWhat to do:\nSend the detailed result to your network security team.", destBlock)
						return Evaluation{
							Scenario:    ScenarioPrivateTLSPartial,
							ExitCode:    8,
							Title:       "TLS works for only some private addresses",
							Explanation: ex,
							Impact:      imp,
							Summary:     sum,
							State:       AssessmentUnknown,
							LikelyOwner: OwnerSecurityOrProxy,
							NextAction:  "Send the detailed result to your network security team.",
						}
					}
				}

				// Untested TLS (Phase 3 fallback)
				title := "Private connection is reachable"
				if len(tcpObs.GetResults()) > 1 {
					title = "Private connections are reachable"
				}
				var lines []string
				for _, r := range tcpObs.GetResults() {
					lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
				}
				destBlock := strings.Join(lines, "\n")
				connStatusStr := "Working"
				if len(tcpObs.GetResults()) > 1 {
					connStatusStr = "Working for all addresses"
				}
				ex := "The Azure service hostname resolved privately, and this workload established a TCP connection to every returned private address."
				imp := "DNS and TCP connectivity look correct. TLS and the service response remain untested."
				sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      %s\n\nSecure connection and service response not tested yet.", destBlock, connStatusStr)
				return Evaluation{
					Scenario:    ScenarioPrivateTCPReachable,
					ExitCode:    0,
					Title:       title,
					Explanation: ex,
					Impact:      imp,
					Summary:     sum,
					State:       AssessmentWorking,
					LikelyOwner: OwnerUnknown,
					NextAction:  "",
				}

			case AggregateTCPNoneConnected:
				title := "The private address cannot be reached"
				if len(tcpObs.GetResults()) > 1 {
					title = "The private addresses cannot be reached"
				}
				var lines []string
				for _, r := range tcpObs.GetResults() {
					failReason := formatTCPFailureReason(r.GetStatus(), r.GetErrorCategory())
					if len(tcpObs.GetResults()) == 1 {
						lines = append(lines, fmt.Sprintf("%s → %s\nResult: %s", tgt.Hostname, r.GetDestination(), failReason))
					} else {
						lines = append(lines, fmt.Sprintf("%-18s %s", r.GetDestination(), formatShortTCPFailure(r.GetStatus())))
					}
				}
				destBlock := strings.Join(lines, "\n")
				connStatusStr := "Failed"
				if len(tcpObs.GetResults()) > 1 {
					connStatusStr = "Failed for all addresses"
				}
				ex := "The Azure service hostname resolved privately, but this workload could not establish a TCP connection to the returned address."
				imp := "The application cannot currently connect to the Azure service on the requested port."
				sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      %s\n\nWhat to do:\nSend this result to your network team.", destBlock, connStatusStr)
				return Evaluation{
					Scenario:    ScenarioPrivateTCPUnreachable,
					ExitCode:    5,
					Title:       title,
					Explanation: ex,
					Impact:      imp,
					Summary:     sum,
					State:       AssessmentBroken,
					LikelyOwner: OwnerNetwork,
					NextAction:  "Send this result to your network team.",
				}

			case AggregateTCPPartiallyConnected:
				var lines []string
				for _, r := range tcpObs.GetResults() {
					if r.GetStatus() == TCPAddrConnected {
						lines = append(lines, fmt.Sprintf("%-18s connected in %d ms", r.GetDestination(), r.GetDurationMs()))
					} else {
						lines = append(lines, fmt.Sprintf("%-18s %s", r.GetDestination(), formatShortTCPFailure(r.GetStatus())))
					}
				}
				destBlock := strings.Join(lines, "\n")
				ex := "At least one returned private address accepted the TCP connection and at least one did not."
				imp := "The application may behave intermittently depending on which address it uses."
				sum := fmt.Sprintf("%s\n\nThe application may work intermittently depending on which address it uses.\n\nWhat to do:\nSend this result to your network team.", destBlock)
				return Evaluation{
					Scenario:    ScenarioPrivateTCPPartial,
					ExitCode:    8,
					Title:       "Some private addresses cannot be reached",
					Explanation: ex,
					Impact:      imp,
					Summary:     sum,
					State:       AssessmentUnknown,
					LikelyOwner: OwnerNetwork,
					NextAction:  "Send this result to your network team.",
				}
			}
		}

		// Phase 2 fallback or untested TCP/TLS
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

func determineDominantTLSStatus(results []MinimalTLSResultItem) TLSAddressStatus {
	if len(results) == 0 {
		return TLSAddrError
	}
	counts := make(map[TLSAddressStatus]int)
	for _, r := range results {
		counts[r.GetStatus()]++
	}

	prio := []TLSAddressStatus{
		TLSAddrHostnameMismatch,
		TLSAddrUntrustedCertificate,
		TLSAddrExpiredCertificate,
		TLSAddrNotYetValid,
		TLSAddrHandshakeTimeout,
		TLSAddrConnectionClosed,
		TLSAddrHandshakeFailed,
		TLSAddrError,
	}

	for _, s := range prio {
		if counts[s] > 0 {
			return s
		}
	}

	return results[0].GetStatus()
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

func formatTCPFailureReason(status TCPAddressStatus, errCat string) string {
	switch status {
	case TCPAddrTimedOut:
		return "connection timed out"
	case TCPAddrConnectionRefused:
		return "connection refused"
	case TCPAddrUnreachable:
		return "network or host unreachable"
	case TCPAddrCanceled:
		return "connection canceled"
	default:
		return "connection failed"
	}
}

func formatShortTCPFailure(status TCPAddressStatus) string {
	switch status {
	case TCPAddrTimedOut:
		return "timed out"
	case TCPAddrConnectionRefused:
		return "connection refused"
	case TCPAddrUnreachable:
		return "unreachable"
	case TCPAddrCanceled:
		return "canceled"
	default:
		return "failed"
	}
}

func formatShortTLSFailure(status TLSAddressStatus) string {
	switch status {
	case TLSAddrHostnameMismatch:
		return "hostname mismatch"
	case TLSAddrUntrustedCertificate:
		return "certificate not trusted"
	case TLSAddrExpiredCertificate:
		return "certificate expired"
	case TLSAddrNotYetValid:
		return "certificate not yet valid"
	case TLSAddrHandshakeTimeout:
		return "timed out"
	case TLSAddrConnectionClosed:
		return "connection closed"
	default:
		return "failed"
	}
}
