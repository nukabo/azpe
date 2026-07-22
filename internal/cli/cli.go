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
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/output"
	"github.com/azpe/azpe/internal/target"
	"github.com/azpe/azpe/internal/version"
)

// Run executes the CLI logic with the provided argument list and writers.
// Returns an exit code suitable for os.Exit.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithResolver(args, stdout, stderr, &dns.OSResolver{})
}

// RunWithResolver executes the CLI logic using a custom DNS resolver (useful for testing).
func RunWithResolver(args []string, stdout, stderr io.Writer, resolver dns.Resolver) int {
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
		return runProbe(args[1:], stdout, stderr, resolver)
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
  azpe probe myvault.vault.azure.net --timeout 10s --no-color
`, version.Version, version.SchemaVersion)

	fmt.Fprint(w, helpText)
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "AZPE version %s (JSON schema v%d)\n", version.Version, version.SchemaVersion)
}

func runProbe(args []string, stdout, stderr io.Writer, resolver dns.Resolver) int {
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

	_ = noHTTPFlag

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	dnsObs, addrObs := dns.Resolve(ctx, resolver, tgt)

	res := model.NewResultFromDNS(tgt, startTime, dnsObs, addrObs)

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
	switch tgt.TargetType {
	case target.TargetTypeIPLiteral, target.TargetTypeUnrecognized, target.TargetTypePossibleAzure:
		return ExitInconclusive // Exit code 8
	case target.TargetTypeRecognizedAzure:
		switch dnsObs.Status {
		case assess.DNSStatusNotFound, assess.DNSStatusTimeout, assess.DNSStatusTemporaryFailure, assess.DNSStatusFailure:
			return ExitDNSFailure // Exit code 3
		}

		switch addrObs.Classification {
		case assess.AggregatePrivateOnly:
			return ExitSuccess // Exit code 0
		case assess.AggregatePublicOnly:
			return ExitNotPrivate // Exit code 4
		default:
			return ExitInconclusive // Exit code 8 for mixed or special
		}
	default:
		return ExitInconclusive
	}
}
