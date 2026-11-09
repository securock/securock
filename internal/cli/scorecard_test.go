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

func TestAuditScorecardFlagAppliesPolicyChecks(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(pol, []byte("version: 1\nrules:\n  health:\n    scorecard_checks:\n      Dangerous-Workflow: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The flag is what asks for the lookup; a policy alone must not start sending names.
	if got := string(runCLI(t, "audit", dir, "--offline", "--no-fail", "--policy", pol)); strings.Contains(got, "scorecard-unchecked") {
		t.Fatalf("a policy must not trigger a lookup by itself:\n%s", got)
	}
	if got := string(runCLI(t, "audit", dir, "--offline", "--no-fail", "--policy", pol, "--scorecard")); !strings.Contains(got, "scorecard-unchecked") {
		t.Fatalf("--scorecard must ask for the lookup:\n%s", got)
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nrules:\n  health:\n    scorecard_checks:\n      Dangerous-Workflows: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := execCLI(t, "", "audit", dir, "--offline", "--policy", bad); err == nil {
		t.Fatal("a misspelled check name must be rejected")
	}
}
