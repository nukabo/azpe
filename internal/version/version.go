package version

import (
	"fmt"
	"strings"
)

// Build-time injected variables via Go linker flags (-ldflags).
var (
	// Version is the semantic version of AZPE (default: "v0.1.0-dev").
	Version = "v0.1.0-dev"

	// Commit is the Git commit SHA (default: "unknown").
	Commit = "unknown"

	// Date is the ISO8601 build timestamp (default: "unknown").
	Date = "unknown"
)

// SchemaVersion is the current version of the JSON result output format.
const SchemaVersion = 1

// String returns a human-readable formatted version string for CLI output.
func String() string {
	parts := []string{fmt.Sprintf("AZPE %s", Version)}

	var meta []string
	if Commit != "" && Commit != "unknown" {
		shortCommit := Commit
		if len(shortCommit) > 7 {
			shortCommit = shortCommit[:7]
		}
		meta = append(meta, fmt.Sprintf("commit %s", shortCommit))
	}
	if Date != "" && Date != "unknown" {
		shortDate := Date
		if idx := strings.Index(Date, "T"); idx != -1 {
			shortDate = Date[:idx]
		}
		meta = append(meta, fmt.Sprintf("built %s", shortDate))
	}
	meta = append(meta, fmt.Sprintf("schema %d", SchemaVersion))

	if len(meta) > 0 {
		return fmt.Sprintf("%s (%s)", parts[0], strings.Join(meta, ", "))
	}

	return parts[0]
}
