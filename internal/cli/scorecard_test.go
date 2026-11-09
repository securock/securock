package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditMinScorecard(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	got := string(runCLI(t, "audit", dir, "--offline", "--no-fail", "--min-scorecard", "5"))
	if !strings.Contains(got, "scorecard-unchecked") || !strings.Contains(got, "offline") {
		t.Fatalf("an offline --min-scorecard must say it could not check:\n%s", got)
	}
	if plain := string(runCLI(t, "audit", dir, "--offline", "--no-fail")); strings.Contains(plain, "scorecard-unchecked") {
		t.Fatalf("no lookup was asked for:\n%s", plain)
	}
	for _, bad := range []string{"-1", "11"} {
		if _, err := execCLI(t, "", "audit", dir, "--offline", "--min-scorecard", bad); err == nil {
			t.Errorf("--min-scorecard %s should be rejected", bad)
		}
	}
}
