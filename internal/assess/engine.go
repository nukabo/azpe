package assess

import (
	"github.com/nukabo/azpe/internal/target"
)

// Evaluate executes the diagnostic decision tree for a target across all observation phases.
func Evaluate(tgt *target.Target, dnsStatus DNSStatus, aggClass AggregateClassification, addresses []string, classifications []AddressClassification, errCat, errMsg string, tcpObs MinimalTCPObservation, tlsObs MinimalTLSObservation, httpObs MinimalHTTPObservation) Evaluation {
	// 1. IP Literal Target
	if tgt.TargetType == target.TargetTypeIPLiteral {
		return evaluateIPLiteral(tgt)
	}

	// 2. Unrecognized Non-Azure Target
	if tgt.TargetType == target.TargetTypeUnrecognized {
		return evaluateUnrecognizedTarget(tgt)
	}

	// 3. Possible Azure Service (Not fully recognized in catalog)
	if tgt.TargetType == target.TargetTypePossibleAzure {
		return evaluatePossibleAzure(tgt)
	}

	// 4. Recognized Azure Service Hostname - Evaluate DNS Results
	switch dnsStatus {
	case DNSStatusNotFound, DNSStatusTimeout, DNSStatusTemporaryFailure, DNSStatusFailure:
		return evaluateDNSLookupFailed(tgt)
	}

	switch aggClass {
	case AggregatePrivateOnly:
		// Evaluate TCP, TLS, and HTTP Probing Results for Private-Only DNS
		if tcpObs != nil && tcpObs.GetAggregateStatus() != AggregateTCPNotAttempted && tcpObs.GetAggregateStatus() != AggregateTCPNotApplicable {
			switch tcpObs.GetAggregateStatus() {
			case AggregateTCPAllConnected:
				if tlsObs != nil && tlsObs.GetAggregateStatus() != AggregateTLSNotAttempted && tlsObs.GetAggregateStatus() != AggregateTLSNotApplicable {
					switch tlsObs.GetAggregateStatus() {
					case AggregateTLSAllValid:
						// Evaluate Phase 5 HTTP Probing
						if httpObs != nil && httpObs.GetAggregateStatus() != AggregateHTTPNotAttempted && httpObs.GetAggregateStatus() != AggregateHTTPNotApplicable {
							switch httpObs.GetAggregateStatus() {
							case AggregateHTTPAllResponded:
								domCat, domCode, domText, domRes := determineDominantHTTPResponse(httpObs.GetResults())
								return buildHTTPRespondedEvaluation(tgt, httpObs.GetResults(), domCat, domCode, domText, domRes)

							case AggregateHTTPNoneResponded:
								return evaluateHTTPNoneResponded(tgt, httpObs)

							case AggregateHTTPPartiallyResponded:
								return evaluateHTTPPartial(tgt, httpObs)
							}
						}

						// Phase 4 TLS Valid fallback (when --no-http is used)
						return evaluateTLSValid(tgt, tlsObs)

					case AggregateTLSNoneValid:
						return evaluateTLSNoneValid(tgt, tlsObs)

					case AggregateTLSPartiallyValid:
						return evaluateTLSPartial(tgt, tlsObs)
					}
				}

			case AggregateTCPNoneConnected:
				return evaluateTCPUnreachable(tgt, tcpObs)

			case AggregateTCPPartiallyConnected:
				return evaluateTCPPartial(tgt, tcpObs)
			}
		}

		// Phase 2 fallback or untested TCP/TLS
		return evaluatePrivateDNSActiveFallback(tgt, addresses)

	case AggregatePublicOnly:
		return evaluatePublicOnly(tgt, addresses)

	case AggregateMixedPrivatePublic:
		return evaluateMixedDNS(tgt, addresses, classifications)

	case AggregateSpecialOnly:
		return evaluateSpecialOnly(tgt, addresses, classifications)

	default:
		return evaluateDNSLookupFailed(tgt)
	}
}

func evaluatePrivateDNSActiveFallback(tgt *target.Target, addresses []string) Evaluation {
	var lines []string
	for _, addr := range addresses {
		lines = append(lines, addr)
	}
	ex := "The service name points to a private address from this workload."
	if len(addresses) > 1 {
		ex = "The service name points to private addresses from this workload."
	}
	imp := "Connection not tested yet."
	sum := ex
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
}
