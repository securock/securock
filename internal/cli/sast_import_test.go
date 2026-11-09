package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/schemas"
)

func writeImportSARIF(t *testing.T, project string) string {
	t.Helper()
	abs, err := filepath.Abs(project)
	if err != nil {
		t.Fatal(err)
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[
	  {"ruleId":"go.crypto","level":"warning","message":{"text":"weak hash"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + filepath.ToSlash(abs) + `/main.go"},"region":{"startLine":9}}}]},
	  {"ruleId":"cfg.open","level":"note","message":{"text":"open bucket"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"infra/main.tf"}}}]}
	]}]}`
	path := filepath.Join(t.TempDir(), "semgrep.sarif")
	if err := os.WriteFile(path, []byte(sarif), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSASTImportMergesIntoOneReport(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	sarif := writeImportSARIF(t, dir)

	raw := runCLI(t, "sast", dir, "--offline", "--no-fail", "--format", "json", "--import", sarif)
	if err := schemas.Validate("sast-report.schema.json", raw); err != nil {
		t.Fatalf("a report with imported findings must match the sast schema: %v\n%s", err, raw)
	}
	var report struct {
		Tool     string `json:"tool"`
		Findings []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, f := range report.Findings {
		ids[f.ID] = f.Subject
	}
	if report.Tool != "sast" || ids["sast:go/sql-injection"] == "" || ids["sarif:semgrep/go.crypto"] != "main.go" || ids["sarif:semgrep/cfg.open"] != "infra/main.tf" {
		t.Fatalf("native and imported findings should share one report, with project-relative paths: %v\n%s", ids, raw)
	}
}

func TestSASTImportFailsAndAcceptsLikeNativeFindings(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir() // nothing for sast itself to find
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sarif := writeImportSARIF(t, dir)
	ex := filepath.Join(t.TempDir(), "exceptions.yaml")

	if _, err := execCLI(t, "", "sast", dir, "--offline", "--import", sarif, "--fail-on", "medium", "--exceptions", ex); err == nil {
		t.Fatal("an imported medium finding must fail --fail-on medium")
	}
	if _, err := execCLI(t, "", "sast", dir, "--offline", "--import", sarif, "--exceptions", ex); err != nil {
		t.Fatalf("nothing reaches the default threshold: %v", err)
	}
	runCLI(t, "accept", "sarif:semgrep/go.crypto", t.TempDir(), "--exceptions", ex,
		"--subject", "main.go", "--reason", "test fixture", "--expires", "2999-12-31")
	if out, err := execCLI(t, "", "sast", dir, "--offline", "--import", sarif, "--fail-on", "medium", "--exceptions", ex); err != nil {
		t.Fatalf("an accepted imported finding must not fail the build: %v\n%s", err, out)
	}
}

func TestSASTImportErrors(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, "package main\n\nfunc main() {}\n")
	bad := filepath.Join(t.TempDir(), "bad.sarif")
	if err := os.WriteFile(bad, []byte(`{"version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"missing": filepath.Join(t.TempDir(), "none.sarif"), "bad version": bad} {
		t.Run(name, func(t *testing.T) {
			if _, err := execCLI(t, "", "sast", dir, "--offline", "--import", file); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestSASTSchemaStillRequiresALocationForNativeFindings(t *testing.T) {
	native := `{"tool":"sast","findings":[{"id":"sast:go/x","severity":"high","title":"t"}]}`
	if err := schemas.Validate("sast-report.schema.json", []byte(native)); err == nil || !strings.Contains(err.Error(), "location") {
		t.Fatalf("a sast: finding without a location must be rejected, got %v", err)
	}
	imported := `{"tool":"sast","findings":[{"id":"sarif:t/r","severity":"high","title":"t"}]}`
	if err := schemas.Validate("sast-report.schema.json", []byte(imported)); err != nil {
		t.Fatalf("a sarif: finding may have no location: %v", err)
	}
	other := `{"tool":"sast","findings":[{"id":"audit:x","severity":"high","title":"t"}]}`
	if err := schemas.Validate("sast-report.schema.json", []byte(other)); err == nil {
		t.Fatal("other ID prefixes must still be rejected")
	}
}
