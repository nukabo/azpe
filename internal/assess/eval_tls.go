package assess

import (
	"fmt"
	"strings"

	"github.com/nukabo/azpe/internal/target"
)

func evaluateTLSValid(tgt *target.Target, tlsObs MinimalTLSObservation) Evaluation {
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
	imp := "DNS, TCP, and TLS validation look correct."
	sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Not tested\n\nHTTP probing was disabled with --no-http.", destBlock, connStatusStr, tlsStatusStr)
	return Evaluation{
		Code:        CodeSuccess,
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
}

func evaluateTLSNoneValid(tgt *target.Target, tlsObs MinimalTLSObservation) Evaluation {
	domStatus := determineDominantTLSStatus(tlsObs.GetResults())
	var lines []string
	for _, r := range tlsObs.GetResults() {
		lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
	}
	destBlock := strings.Join(lines, "\n")

	switch domStatus {
	case TLSAddrHostnameMismatch:
		title := "The certificate does not match the Azure service name"
		ex := "The private address is reachable, but it presented a certificate for a different hostname."
		imp := "The application cannot establish a secure connection because certificate hostname validation failed."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Hostname mismatch\n\nThe address is reachable, but it presented a certificate for a different hostname.\n\nWhat to do:\nSend the detailed result to your network security team.", destBlock)
		return Evaluation{
			Code:        CodeTLSHostnameMismatch,
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
		ex := "The private address is reachable, but the certificate presented is not trusted by this workload."
		imp := "The application cannot establish a secure connection because certificate trust validation failed."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Certificate not trusted\n\nWhat to do:\nSend the detailed result to your application platform or network security team.", destBlock)
		return Evaluation{
			Code:        CodeTLSUntrusted,
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
		ex := "The private address is reachable, but the certificate presented has expired."
		imp := "The application cannot establish a secure connection because the certificate is expired."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Certificate expired\n\nWhat to do:\nSend the detailed result to your service owner or network security team.", destBlock)
		return Evaluation{
			Code:        CodeTLSExpired,
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
		ex := "The TCP port is reachable, but the TLS handshake did not finish before the timeout."
		imp := "The workload could not complete TLS negotiation within the operation deadline."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Timed out\n\nThe TCP port is reachable, but the TLS handshake did not finish before the timeout.\n\nWhat to do:\nSend the detailed result to your network security team.", destBlock)
		return Evaluation{
			Code:        CodeTLSFailure,
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
		ex := "The private address is reachable, but TLS negotiation failed."
		imp := "The application cannot establish a secure TLS connection."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Failed\n\nThe private address is reachable, but TLS negotiation failed.\n\nWhat to do:\nSend the detailed result to your application platform or network security team.", destBlock)
		return Evaluation{
			Code:        CodeTLSFailure,
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
}

func evaluateTLSPartial(tgt *target.Target, tlsObs MinimalTLSObservation) Evaluation {
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
		Code:        CodeTLSFailure,
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

func determineDominantTLSStatus(results []MinimalTLSResultItem) TLSAddressStatus {
	if len(results) == 0 {
		return TLSAddrHandshakeFailed
	}
	// Precedence order for dominant TLS failure
	prec := map[TLSAddressStatus]int{
		TLSAddrHostnameMismatch:     1,
		TLSAddrUntrustedCertificate: 2,
		TLSAddrExpiredCertificate:   3,
		TLSAddrHandshakeTimeout:     4,
		TLSAddrHandshakeFailed:      5,
	}
	dominant := results[0].GetStatus()
	bestRank := prec[dominant]
	for _, r := range results[1:] {
		st := r.GetStatus()
		if rank, ok := prec[st]; ok && (bestRank == 0 || rank < bestRank) {
			dominant = st
			bestRank = rank
		}
	}
	return dominant
}

func formatShortTLSFailure(status TLSAddressStatus) string {
	switch status {
	case TLSAddrHostnameMismatch:
		return "Hostname mismatch"
	case TLSAddrUntrustedCertificate:
		return "Untrusted certificate"
	case TLSAddrExpiredCertificate:
		return "Certificate expired"
	case TLSAddrHandshakeTimeout:
		return "Handshake timed out"
	default:
		return "TLS failed"
	}
}
