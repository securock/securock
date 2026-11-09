package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDependencyConfusionFromPolicy(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"@acme/ui": "1.0.0", "left-pad": "1.0.0"}},
    "node_modules/@acme/ui": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@acme/ui/-/ui-1.0.0.tgz"},
    "node_modules/left-pad": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(pol, []byte("version: 1\nrules:\n  health:\n    internal_names:\n      - \"npm:@acme/*\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	with := string(runCLI(t, "audit", dir, "--offline", "--no-fail", "--policy", pol))
	if !strings.Contains(with, "dependency-confusion") || !strings.Contains(with, "@acme/ui") {
		t.Fatalf("an internal name from a public registry must be reported:\n%s", with)
	}
	if strings.Count(with, "dependency-confusion") != 1 {
		t.Fatalf("only @acme/ui is internal:\n%s", with)
	}
	if without := string(runCLI(t, "audit", dir, "--offline", "--no-fail")); strings.Contains(without, "dependency-confusion") {
		t.Fatalf("nothing is internal without the policy entry:\n%s", without)
	}
}
