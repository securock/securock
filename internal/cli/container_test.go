package cli_test

import (
	"github.com/securock/securock/schemas"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestContainerOfflineRequiresArchive(t *testing.T) {
	isolateHome(t)
	raw, err := execCLI(t, "", "container", "example/image", "--offline", "--no-fail")
	if err == nil || !strings.Contains(err.Error(), "allow-all") {
		t.Fatalf("%v %s", err, raw)
	}
}
func TestContainerMissingToolFailsClosed(t *testing.T) {
	isolateHome(t)
	t.Setenv("PATH", t.TempDir())
	raw, err := execCLI(t, "", "container", "image.tar", "--archive", "--offline", "--no-fail", "--format", "json")
	if err == nil || !strings.Contains(string(raw), "analysis-incomplete") {
		t.Fatalf("%v %s", err, raw)
	}
}

func TestContainerImportsScannerResults(t *testing.T) {
	isolateHome(t)
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[{"ruleId":"CVE-test","level":"error","message":{"text":"test vulnerability"}}]}]}'
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	raw := runCLI(t, "container", "image.tar", "--archive", "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("container-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "sarif:trivy/CVE-test") {
		t.Fatal(string(raw))
	}
}
