package assess

import (
	"fmt"
	"strings"

	"github.com/nukabo/azpe/internal/target"
)

func evaluateTCPUnreachable(tgt *target.Target, tcpObs MinimalTCPObservation) Evaluation {
	title := "The private address cannot be reached"
	if len(tcpObs.GetResults()) > 1 {
		title = "The private addresses cannot be reached"
	}
	var lines []string
	code := CodeTCPFailure
	domFail := determineDominantTCPFailureStatus(tcpObs.GetResults())
	switch domFail {
	case TCPAddrTimedOut:
		code = CodeTCPTimeout
	case TCPAddrConnectionRefused:
		code = CodeTCPRefused
	}

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
		Code:        code,
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
}

func evaluateTCPPartial(tgt *target.Target, tcpObs MinimalTCPObservation) Evaluation {
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
		Code:        CodeTCPFailure,
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

func formatTCPFailureReason(status TCPAddressStatus, errCat string) string {
	switch status {
	case TCPAddrTimedOut:
		return "Connection timed out"
	case TCPAddrConnectionRefused:
		return "Connection refused"
	case TCPAddrUnreachable:
		return "Host unreachable"
	default:
		if errCat != "" {
			return fmt.Sprintf("Connection failed (%s)", errCat)
		}
		return "Connection failed"
	}
}

func formatShortTCPFailure(status TCPAddressStatus) string {
	switch status {
	case TCPAddrTimedOut:
		return "Timed out"
	case TCPAddrConnectionRefused:
		return "Connection refused"
	case TCPAddrUnreachable:
		return "Unreachable"
	default:
		return "Failed"
	}
}

func determineDominantTCPFailureStatus(results []MinimalTCPResultItem) TCPAddressStatus {
	if len(results) == 0 {
		return TCPAddrError
	}
	prec := map[TCPAddressStatus]int{
		TCPAddrTimedOut:          1,
		TCPAddrConnectionRefused: 2,
		TCPAddrUnreachable:       3,
		TCPAddrError:             4,
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
