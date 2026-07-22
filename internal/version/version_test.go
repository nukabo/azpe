package version_test

import (
	"strings"
	"testing"

	"github.com/azpe/azpe/internal/version"
)

func TestVersionString_Default(t *testing.T) {
	str := version.String()
	if !strings.HasPrefix(str, "AZPE v0.1.0-dev") {
		t.Errorf("expected version.String() to start with 'AZPE v0.1.0-dev', got %q", str)
	}
	if !strings.Contains(str, "schema 1") {
		t.Errorf("expected version.String() to contain 'schema 1', got %q", str)
	}
}

func TestVersionString_Injected(t *testing.T) {
	origVer, origCommit, origDate := version.Version, version.Commit, version.Date
	defer func() {
		version.Version = origVer
		version.Commit = origCommit
		version.Date = origDate
	}()

	version.Version = "v0.1.0"
	version.Commit = "1f88fab4651626884622b3c86fe7a2ce2507905c"
	version.Date = "2026-07-22T11:20:15Z"

	str := version.String()
	expected := "AZPE v0.1.0 (commit 1f88fab, built 2026-07-22, schema 1)"
	if str != expected {
		t.Errorf("version.String() = %q, want %q", str, expected)
	}
}
