package assess

import (
	"fmt"
	"strings"

	"github.com/nukabo/azpe/internal/target"
)

func evaluateHTTPNoneResponded(tgt *target.Target, httpObs MinimalHTTPObservation) Evaluation {
	domStatus := determineDominantHTTPFailureStatus(httpObs.GetResults())
	switch domStatus {
	case HTTPAddrTimeout:
		var lines []string
		for _, r := range httpObs.GetResults() {
			lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
		}
		destBlock := strings.Join(lines, "\n")
		ex := "The secure connection works, but no HTTP response was received before the timeout."
		imp := "The HTTP request timed out waiting for headers from the Azure service."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Valid\nAzure service   Response timed out\n\nThe secure connection works, but no HTTP response was received before the timeout.\n\nWhat to do:\nSend the detailed result to the application platform or service owner team.", destBlock)
		return Evaluation{
			Code:        CodeOverallTimeout,
			Scenario:    ScenarioPrivateHTTPTimeout,
			ExitCode:    7,
			Title:       "The Azure service did not respond in time",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentBroken,
			LikelyOwner: OwnerApplicationOrService,
			NextAction:  "Send the detailed result to the application platform or service owner team.",
		}

	case HTTPAddrMalformedResponse:
		ex := "The secure connection works, but the destination returned a non-HTTP or malformed response."
		imp := "The endpoint on port 443 did not speak HTTP."
		sum := fmt.Sprintf("%s\n\nPrivate DNS     Looks correct\nConnection      Working\nTLS             Valid\nAzure service   Invalid HTTP response\n\nWhat to do:\nSend the detailed result to the application platform or service owner team.", tgt.Hostname)
		return Evaluation{
			Code:        CodeInconclusive,
			Scenario:    ScenarioPrivateHTTPMalformed,
			ExitCode:    7,
			Title:       "The destination did not return a valid HTTP response",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentBroken,
			LikelyOwner: OwnerApplicationOrService,
			NextAction:  "Send the detailed result to the application platform or service owner team.",
		}

	default:
		ex := "Earlier checks succeeded, but the final HTTPS request failed before the service returned a response."
		imp := "The HTTPS request could not be completed."
		sum := fmt.Sprintf("%s\n\nEarlier checks succeeded, but the final HTTPS request failed before the service returned a response.\n\nWhat to do:\nRun AZPE again. If the result repeats, send the detailed output to your application platform or network security team.", tgt.Hostname)
		return Evaluation{
			Code:        CodeInconclusive,
			Scenario:    ScenarioPrivateHTTPTransportFailed,
			ExitCode:    7,
			Title:       "The HTTPS request could not be completed",
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentBroken,
			LikelyOwner: OwnerSecurityOrProxy,
			NextAction:  "Run AZPE again. If the result repeats, send the detailed output to your application platform or network security team.",
		}
	}
}

func evaluateHTTPPartial(tgt *target.Target, httpObs MinimalHTTPObservation) Evaluation {
	var lines []string
	for _, r := range httpObs.GetResults() {
		if r.GetStatus() == HTTPAddrResponded {
			lines = append(lines, fmt.Sprintf("%-18s HTTP %d %s", r.GetDestination(), r.GetStatusCode(), r.GetStatusText()))
		} else {
			lines = append(lines, fmt.Sprintf("%-18s %s", r.GetDestination(), formatShortHTTPFailure(r.GetStatus())))
		}
	}
	destBlock := strings.Join(lines, "\n")
	ex := "At least one private address returned an HTTP response and at least one did not."
	imp := "The application may behave failure-prone or intermittently depending on which address it uses."
	sum := fmt.Sprintf("%s\n\nThe application may behave intermittently depending on which address it uses.\n\nWhat to do:\nSend the detailed result to your application platform or service owner team.", destBlock)
	return Evaluation{
		Code:        CodeInconclusive,
		Scenario:    ScenarioPrivateHTTPPartial,
		ExitCode:    8,
		Title:       "The Azure service responded on only some private addresses",
		Explanation: ex,
		Impact:      imp,
		Summary:     sum,
		State:       AssessmentUnknown,
		LikelyOwner: OwnerApplicationOrService,
		NextAction:  "Send the detailed result to your application platform or service owner team.",
	}
}

func buildHTTPRespondedEvaluation(tgt *target.Target, results []MinimalHTTPResultItem, domCat HTTPResponseCategory, domCode int, domText string, domRes MinimalHTTPResultItem) Evaluation {
	var lines []string
	for _, r := range results {
		if len(results) == 1 {
			lines = append(lines, fmt.Sprintf("%s → %s", tgt.Hostname, r.GetDestination()))
		} else {
			lines = append(lines, fmt.Sprintf("%-18s HTTP %d %s", r.GetDestination(), r.GetStatusCode(), r.GetStatusText()))
		}
	}
	destBlock := strings.Join(lines, "\n")

	connStatusStr := "Working"
	tlsStatusStr := "Valid"
	httpStatusStr := fmt.Sprintf("HTTP %d %s", domCode, domText)
	if len(results) > 1 {
		connStatusStr = "Working for all addresses"
		tlsStatusStr = "Valid for all addresses"
	}

	switch domCat {
	case HTTPCatAccessDenied, HTTPCatAuthenticationRequired:
		title := "The Azure service responded"
		ex := "DNS, TCP, TLS, and HTTP transport reached a responder for the hostname. Authentication or authorization is a likely next area to investigate. AZPE does not prove which backend or intermediary generated the response."
		imp := "The network path and TLS transport are functional."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Access denied\n\nDNS, TCP, TLS, and HTTP transport reached a responder for the hostname. Authentication or authorization is a likely next area to investigate. AZPE does not prove which backend or intermediary generated the response.\n\nWhat to do:\nIf the application still fails, check its identity and Azure permissions.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr)
		sc := ScenarioPrivateHTTPAccessDenied
		code := CodeHTTPAuthorizationDenied
		if domCat == HTTPCatAuthenticationRequired {
			sc = ScenarioPrivateHTTPAuthRequired
			code = CodeHTTPAuthenticationRequired
		}
		return Evaluation{
			Code:        code,
			Scenario:    sc,
			ExitCode:    0,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentWorking,
			LikelyOwner: OwnerApplicationOrIdentity,
			NextAction:  "If the application still fails, check its identity and Azure permissions.",
		}

	case HTTPCatRedirection:
		title := "The Azure service responded with a redirect"
		locStr := ""
		if domRes != nil {
			locStr = domRes.GetLocation()
		}
		locInfo := ""
		if locStr != "" {
			locInfo = fmt.Sprintf("\nRedirect location: %s", target.SanitizeLocation(locStr))
		}
		ex := fmt.Sprintf("DNS, TCP, TLS, and HTTP transport reached a responder for the hostname. The service returned HTTP %d (%s).%s AZPE did not follow the redirect.", domCode, domText, locInfo)
		imp := "End-to-end network, TLS, and HTTP transport succeeded."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Redirected (%s)%s\n\nAZPE did not follow the redirect.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr, domText, locInfo)
		return Evaluation{
			Code:        CodeHTTPRedirected,
			Scenario:    ScenarioPrivateHTTPRedirect,
			ExitCode:    0,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentWorking,
			LikelyOwner: OwnerApplicationOrService,
			NextAction:  "Verify whether the application handles redirects to the intended destination.",
		}

	case HTTPCatSuccess:
		title := "The Azure service responded"
		ex := "The private connection works and the Azure service returned a successful response."
		imp := "End-to-end network, TLS, and HTTP transport succeeded."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Responded (%s)\n\nThe private connection is working.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr, domText)
		return Evaluation{
			Code:        CodeSuccess,
			Scenario:    ScenarioPrivateHTTPResponded,
			ExitCode:    0,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentWorking,
			LikelyOwner: OwnerUnknown,
			NextAction:  "",
		}

	case HTTPCatNotFound:
		title := "The Azure service responded"
		ex := "The private connection works. The requested resource or endpoint path was not found."
		imp := "Network path works; verify the request URL or path."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Not found (HTTP 404)\n\nThe private connection is working. The endpoint path was not found.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr)
		return Evaluation{
			Code:        CodeSuccess,
			Scenario:    ScenarioPrivateHTTPNotFound,
			ExitCode:    0,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentWorking,
			LikelyOwner: OwnerApplicationOrService,
			NextAction:  "Verify the requested URL path or API route.",
		}

	case HTTPCatThrottled:
		title := "The Azure service responded"
		ex := "The private connection works, but the Azure service is throttling requests (HTTP 429)."
		imp := "Network path works; rate limits or throttling are in effect."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Throttled (HTTP 429)\n\nThe private connection is working, but the target service is rate-limiting requests.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr)
		return Evaluation{
			Code:        CodeHTTPRateLimited,
			Scenario:    ScenarioPrivateHTTPThrottled,
			ExitCode:    0,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentWorking,
			LikelyOwner: OwnerApplicationOrService,
			NextAction:  "Check application request rate and backoff settings.",
		}

	case HTTPCatServerError:
		title := "The Azure service responded with a server error"
		ex := "The private connection works, but the Azure service returned a 5xx server error."
		imp := "Network path works; the Azure service encountered an internal error."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Server error (HTTP %d)\n\nThe private connection is working, but the Azure service returned an internal error.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr, domCode)
		return Evaluation{
			Code:        CodeHTTPServiceError,
			Scenario:    ScenarioPrivateHTTPServerError,
			ExitCode:    0,
			Title:       title,
			Explanation: ex,
			Impact:      imp,
			Summary:     sum,
			State:       AssessmentWorking,
			LikelyOwner: OwnerApplicationOrService,
			NextAction:  "Send this result to the service owner or Azure support team.",
		}

	default:
		title := "The Azure service responded"
		ex := fmt.Sprintf("The private connection works (HTTP %d).", domCode)
		imp := "End-to-end network and TLS transport succeeded."
		sum := fmt.Sprintf("%s\n%s\n\nPrivate DNS     Looks correct\nConnection      %s\nTLS             %s\nAzure service   Responded\n\nThe private connection is working.", destBlock, httpStatusStr, connStatusStr, tlsStatusStr)
		return Evaluation{
			Code:        CodeSuccess,
			Scenario:    ScenarioPrivateHTTPResponded,
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
}

func determineDominantHTTPResponse(results []MinimalHTTPResultItem) (HTTPResponseCategory, int, string, MinimalHTTPResultItem) {
	if len(results) == 0 {
		return HTTPCatOtherResponse, 0, "", nil
	}
	prec := map[HTTPResponseCategory]int{
		HTTPCatAccessDenied:           1,
		HTTPCatAuthenticationRequired: 2,
		HTTPCatSuccess:                3,
		HTTPCatNotFound:               4,
		HTTPCatThrottled:              5,
		HTTPCatServerError:            6,
		HTTPCatMethodNotAllowed:       7,
		HTTPCatRedirection:            8,
		HTTPCatClientError:            9,
		HTTPCatOtherResponse:          10,
	}

	best := results[0]
	bestRank := prec[best.GetResponseCategory()]

	for _, r := range results[1:] {
		rank := prec[r.GetResponseCategory()]
		if rank > 0 && (bestRank == 0 || rank < bestRank) {
			best = r
			bestRank = rank
		}
	}

	return best.GetResponseCategory(), best.GetStatusCode(), best.GetStatusText(), best
}

func determineDominantHTTPFailureStatus(results []MinimalHTTPResultItem) HTTPAddressStatus {
	if len(results) == 0 {
		return HTTPAddrError
	}
	prec := map[HTTPAddressStatus]int{
		HTTPAddrTimeout:           1,
		HTTPAddrMalformedResponse: 2,
		HTTPAddrConnectionFailed:  3,
		HTTPAddrTLSFailed:         4,
		HTTPAddrConnectionClosed:  5,
		HTTPAddrError:             6,
	}
	best := results[0].GetStatus()
	bestRank := prec[best]
	for _, r := range results[1:] {
		st := r.GetStatus()
		if rank := prec[st]; rank > 0 && (bestRank == 0 || rank < bestRank) {
			best = st
			bestRank = rank
		}
	}
	return best
}

func formatShortHTTPFailure(status HTTPAddressStatus) string {
	switch status {
	case HTTPAddrTimeout:
		return "HTTP timed out"
	case HTTPAddrMalformedResponse:
		return "Invalid HTTP response"
	default:
		return "HTTP failed"
	}
}
