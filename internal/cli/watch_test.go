package cli_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchRetainsBaselineAcrossOfflineRuns(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	state := filepath.Join(t.TempDir(), "state.json")
	args := []string{"watch", dir, "--runs", "1", "--state", state, "--offline", "--format", "json"}
	first := runCLI(t, args...)
	second := runCLI(t, args...)
	if !strings.Contains(string(first), "sast:go/sql-injection") || strings.Contains(string(second), "sast:go/sql-injection") {
		t.Fatalf("baseline not used:\n%s\n%s", first, second)
	}
}
