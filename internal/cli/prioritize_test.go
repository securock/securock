package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditPrioritizeOffline(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	got := string(runCLI(t, "audit", dir, "--offline", "--no-fail", "--prioritize"))
	if !strings.Contains(got, "exploit-signals-unavailable") || !strings.Contains(got, "offline") {
		t.Fatalf("an offline --prioritize must say it could not check:\n%s", got)
	}
	if plain := string(runCLI(t, "audit", dir, "--offline", "--no-fail")); strings.Contains(plain, "exploit-signals-unavailable") {
		t.Fatalf("no lookup was asked for:\n%s", plain)
	}
}
