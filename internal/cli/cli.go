package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/dns"
	"github.com/azpe/azpe/internal/http"
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/output"
	"github.com/azpe/azpe/internal/target"
	"github.com/azpe/azpe/internal/tcp"
	"github.com/azpe/azpe/internal/tls"
	"github.com/azpe/azpe/internal/version"
)

// Run executes the CLI logic with the provided argument list and writers.
// Returns an exit code suitable for os.Exit.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithResolverProberTLSProberAndHTTPProber(args, stdout, stderr, &dns.OSResolver{}, &tcp.OSTCPProber{}, &tls.OSTLSProber{}, &http.OSHTTPProber{})
}

// RunWithResolver executes the CLI logic using a custom DNS resolver (useful for testing).
func RunWithResolver(args []string, stdout, stderr io.Writer, resolver dns.Resolver) int {
	return RunWithResolverProberTLSProberAndHTTPProber(args, stdout, stderr, resolver, &tcp.OSTCPProber{}, &tls.OSTLSProber{}, &http.OSHTTPProber{})
}

// RunWithResolverAndProber executes the CLI logic using custom DNS resolver and TCP prober (useful for testing).
func RunWithResolverAndProber(args []string, stdout, stderr io.Writer, resolver dns.Resolver, prober tcp.Prober) int {
	return RunWithResolverProberTLSProberAndHTTPProber(args, stdout, stderr, resolver, prober, &tls.OSTLSProber{}, &http.OSHTTPProber{})
}

// RunWithResolverProberAndTLSProber executes CLI logic with DNS, TCP, and TLS custom probers.
func RunWithResolverProberAndTLSProber(args []string, stdout, stderr io.Writer, resolver dns.Resolver, prober tcp.Prober, tlsProber tls.Prober) int {
	return RunWithResolverProberTLSProberAndHTTPProber(args, stdout, stderr, resolver, prober, tlsProber, &http.OSHTTPProber{})
}

// RunWithResolverProberTLSProberAndHTTPProber executes CLI logic with full dependency injection for testing.
func RunWithResolverProberTLSProberAndHTTPProber(args []string, stdout, stderr io.Writer, resolver dns.Resolver, prober tcp.Prober, tlsProber tls.Prober, httpProber http.Prober) int {
	if len(args) == 0 {
		printHelp(stdout)
		return ExitSuccess
	}

	subcommand := args[0]

	switch subcommand {
	case "-h", "--help", "help":
		printHelp(stdout)
		return ExitSuccess
	case "-v", "--version", "version":
		printVersion(stdout)
		return ExitSuccess
	case "probe":
		return runProbe(args[1:], stdout, stderr, resolver, prober, tlsProber, httpProber)
	default:
		if subcommand == "-h" || subcommand == "--help" {
			printHelp(stdout)
			return ExitSuccess
		}
		if subcommand == "-v" || subcommand == "--version" {
			printVersion(stdout)
			return ExitSuccess
		}
		fmt.Fprintf(stderr, "Error: unknown command %q\n\nRun 'azpe --help' for usage.\n", subcommand)
		return ExitUsageOrTargetError
	}
}

func printHelp(w io.Writer) {
	helpText := fmt.Sprintf(`AZPE - Azure Private Endpoint Connectivity Diagnostic Utility (%s)

AZPE diagnoses Azure Private Endpoint connectivity from the workload's actual execution environment.

USAGE:
  azpe <command> [target] [flags]

COMMANDS:
  probe       Diagnose connectivity to an Azure service hostname or URL
  help        Show help information
  version     Show version information

PROBE FLAGS:
  --json             Output results as JSON (schemaVersion: %d)
  --details          Show detailed multi-section terminal output
  --timeout <duration> Timeout per operation (default: 5s)
  --no-http          Skip minimal HTTP probe phase
  --no-color         Disable colorized terminal output

EXAMPLES:
  azpe probe myvault.vault.azure.net
  azpe probe mystorage.blob.core.windows.net
  azpe probe mysearch.search.windows.net
  azpe probe myaccount.openai.azure.com
  azpe probe myvault.vault.azure.net --json
  azpe probe myvault.vault.azure.net --details
  azpe probe myvault.vault.azure.net --no-http
  azpe probe myvault.vault.azure.net --timeout 10s --no-color
`, version.Version, version.SchemaVersion)

	fmt.Fprint(w, helpText)
}

func printVersion(w io.Writer) {
	fmt.Fprintln(w, version.String())
}

func runProbe(args []string, stdout, stderr io.Writer, resolver dns.Resolver, prober tcp.Prober, tlsProber tls.Prober, httpProber http.Prober) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)

	jsonFlag := fs.Bool("json", false, "Output results as JSON")
	detailsFlag := fs.Bool("details", false, "Show detailed terminal output")
	timeoutFlag := fs.Duration("timeout", 5*time.Second, "Timeout per operation")
	noHTTPFlag := fs.Bool("no-http", false, "Skip HTTP probe phase")
	noColorFlag := fs.Bool("no-color", false, "Disable color output")

	var flagArgs []string
	var targetArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "--timeout" || arg == "-timeout") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
		} else {
			targetArgs = append(targetArgs, arg)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return ExitUsageOrTargetError
	}

	if len(targetArgs) == 0 {
		fmt.Fprintln(stderr, "Error: missing target for probe command")
		fmt.Fprintln(stderr, "\nUsage: azpe probe <azure-service-hostname-or-url> [flags]")
		return ExitUsageOrTargetError
	}

	targetStr := targetArgs[0]
	startTime := time.Now()

	tgt, err := target.Parse(targetStr)
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing target %q: %v\n", targetStr, err)
		return ExitUsageOrTargetError
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	dnsObs, addrObs := dns.Resolve(ctx, resolver, tgt)

	var tcpObs model.TCPObservation
	var tlsObs model.TLSObservation
	var httpObs model.HTTPObservation

	if tgt.TargetType == target.TargetTypeRecognizedAzure && dnsObs.Status == assess.DNSStatusSuccess && addrObs.Classification == assess.AggregatePrivateOnly {
		tcpObs = tcp.ProbeAll(ctx, prober, dnsObs.Addresses, tgt.Port)
		if tcpObs.Status == assess.TCPStatusSuccess || tcpObs.Status == assess.TCPStatusPartial {
			tlsObs = tls.ProbeAll(ctx, tlsProber, tcpObs, tgt.Hostname)
			if !*noHTTPFlag && (tlsObs.Status == assess.TLSStatusSuccess || tlsObs.Status == assess.TLSStatusPartial) {
				httpObs = http.ProbeAll(ctx, httpProber, tlsObs, tgt.RequestPath, tgt.Scheme, tgt.Port, tgt.Hostname)
			} else if *noHTTPFlag {
				httpObs = model.HTTPObservation{
					Status:          assess.HTTPStatusSkipped,
					AggregateStatus: assess.AggregateHTTPNotAttempted,
					Method:          "GET",
					Path:            tgt.RequestPath,
					Results:         []model.HTTPResultItem{},
					Note:            "HTTP probing was disabled with --no-http.",
				}
			} else {
				httpObs = model.HTTPObservation{
					Status:          assess.HTTPStatusSkipped,
					AggregateStatus: assess.AggregateHTTPNotAttempted,
					Method:          "GET",
					Path:            tgt.RequestPath,
					Results:         []model.HTTPResultItem{},
					Note:            "HTTP was not attempted because no TLS validation succeeded.",
				}
			}
		} else {
			tlsObs = model.TLSObservation{
				Status:          assess.TLSStatusSkipped,
				AggregateStatus: assess.AggregateTLSNotAttempted,
				ServerName:      tgt.Hostname,
				Results:         []model.TLSResultItem{},
				Note:            "TLS was not attempted because no TCP connection succeeded.",
			}
			httpObs = model.HTTPObservation{
				Status:          assess.HTTPStatusSkipped,
				AggregateStatus: assess.AggregateHTTPNotAttempted,
				Method:          "GET",
				Path:            tgt.RequestPath,
				Results:         []model.HTTPResultItem{},
				Note:            "HTTP was not attempted because no TCP connection succeeded.",
			}
		}
	} else {
		tcpObs = model.TCPObservation{
			Status:          assess.TCPStatusSkipped,
			AggregateStatus: assess.AggregateTCPNotAttempted,
			Port:            tgt.Port,
			DurationMs:      0,
			Results:         []model.TCPResultItem{},
			Note:            "TCP connectivity probe not performed",
		}
		tlsObs = model.TLSObservation{
			Status:          assess.TLSStatusSkipped,
			AggregateStatus: assess.AggregateTLSNotAttempted,
			ServerName:      tgt.Hostname,
			Results:         []model.TLSResultItem{},
			Note:            "TLS probe not performed",
		}
		httpObs = model.HTTPObservation{
			Status:          assess.HTTPStatusSkipped,
			AggregateStatus: assess.AggregateHTTPNotAttempted,
			Method:          "GET",
			Path:            tgt.RequestPath,
			Results:         []model.HTTPResultItem{},
			Note:            "HTTP probe not performed",
		}
	}

	res := model.NewResultFromDNSAndTCPAndTLSAndHTTP(tgt, startTime, dnsObs, addrObs, tcpObs, tlsObs, httpObs)

	opts := output.FormatOptions{
		JSON:    *jsonFlag,
		Details: *detailsFlag,
		NoColor: *noColorFlag,
	}

	if err := output.Render(stdout, res, opts); err != nil {
		fmt.Fprintf(stderr, "Error rendering output: %v\n", err)
		return ExitInternalError
	}

	// Exit Code Mapping based on scenario / evaluation
	switch res.Assessment.Scenario {
	case assess.ScenarioPrivateHTTPResponded, assess.ScenarioPrivateHTTPAuthRequired, assess.ScenarioPrivateHTTPAccessDenied,
		assess.ScenarioPrivateHTTPNotFound, assess.ScenarioPrivateHTTPMethodNotAllowed, assess.ScenarioPrivateHTTPThrottled,
		assess.ScenarioPrivateHTTPServerError, assess.ScenarioPrivateHTTPRedirect, assess.ScenarioPrivateTLSValid,
		assess.ScenarioPrivateTCPReachable, assess.ScenarioPrivateDNSActive:
		return ExitSuccess // Exit code 0
	case assess.ScenarioPrivateHTTPFailed, assess.ScenarioPrivateHTTPTimeout, assess.ScenarioPrivateHTTPMalformed, assess.ScenarioPrivateHTTPTransportFailed:
		return ExitHTTPFailure // Exit code 7
	case assess.ScenarioPrivateTLSFailed, assess.ScenarioPrivateTLSHostnameMismatch, assess.ScenarioPrivateTLSUntrusted, assess.ScenarioPrivateTLSExpired, assess.ScenarioPrivateTLSTimeout:
		return ExitTLSFailure // Exit code 6
	case assess.ScenarioPrivateTCPUnreachable:
		return ExitTCPFailure // Exit code 5
	case assess.ScenarioPrivateHTTPPartial, assess.ScenarioPrivateTLSPartial, assess.ScenarioPrivateTCPPartial:
		return ExitInconclusive // Exit code 8
	case assess.ScenarioPrivateDNSNotActive:
		return ExitNotPrivate // Exit code 4
	case assess.ScenarioDNSLookupFailed:
		return ExitDNSFailure // Exit code 3
	default:
		return ExitInconclusive // Exit code 8 for mixed, special, literal, unrecognized, etc.
	}
}
