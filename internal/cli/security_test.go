package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/schemas"
)

func securityReport(t *testing.T, raw []byte) finding.Report {
	t.Helper()
	if err := schemas.Validate("security-report.schema.json", raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	var report finding.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func writeSecurityLock(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const securityLock = `{"lockfileVersion":3,"packages":{"":{},"node_modules/lib":{"version":"1.0.0","resolved":"https://registry.npmjs.org/lib/-/lib-1.0.0.tgz"}}}`

func TestSecurityCombinesDependencySourceAndImportedFindings(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	writeSecurityLock(t, dir, securityLock)
	for name, content := range map[string]string{
		"Dockerfile": "FROM node:latest\nRUN npm ci\n",
		".env":       "AWS_ACCESS_KEY_ID=AKIA" + "1234567890ABCDEF\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	external := writeImportSARIF(t, dir)
	raw := runCLI(t, "security", dir, "--offline", "--no-fail", "--format", "json", "--import", external)
	report := securityReport(t, raw)
	ids := map[string]finding.Finding{}
	for _, f := range report.Findings {
		ids[f.ID] = f
	}
	for _, id := range []string{"sast:go/sql-injection", "sast:secrets/aws-access-key", "sast:iac/docker-root-user", "vulnerability-unchecked", "malicious-unchecked", "sarif:semgrep/go.crypto"} {
		if _, ok := ids[id]; !ok {
			t.Fatalf("missing %s: %+v", id, report.Findings)
		}
	}
	if f := ids["sast:go/sql-injection"]; f.Location == nil || f.Location.File != "main.go" || len(f.Trace) < 2 {
		t.Fatalf("source trace lost: %+v", f)
	}
	if f := ids["vulnerability-unchecked"]; f.Location == nil || f.Location.File != "securock.lock" {
		t.Fatalf("dependency anchor lost: %+v", f)
	}
	for i := 1; i < len(report.Findings); i++ {
		if report.Findings[i-1].Severity.Rank() < report.Findings[i].Severity.Rank() {
			t.Fatal("findings are not ranked")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "securock.lock")); !os.IsNotExist(err) {
		t.Fatalf("security must not write a lockfile: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	again := runCLI(t, "security", rel, "--offline", "--no-fail", "--format", "json", "--import", external)
	if !bytes.Equal(raw, again) {
		t.Fatalf("absolute and relative paths must produce identical reports:\n%s\n%s", raw, again)
	}
}

func TestSecurityWithoutLockfileStillAnalyzesSource(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	raw, err := execCLI(t, "", "security", dir, "--offline", "--format", "json")
	if err == nil || !strings.Contains(err.Error(), "findings at or above high") {
		t.Fatalf("want severity failure, got %v", err)
	}
	report := securityReport(t, []byte(raw))
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %+v", report.Findings)
	}
	if report.Findings[1].ID != "security:dependencies-unchecked" {
		t.Fatalf("missing coverage warning: %+v", report)
	}
	runCLI(t, "security", dir, "--offline", "--fail-on", "critical")
	runCLI(t, "security", dir, "--offline", "--no-fail")
}

func TestSecurityAcceptsFindingsAcrossScanners(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	external := writeImportSARIF(t, dir)
	ex := filepath.Join(t.TempDir(), "exceptions.yaml")
	for id, subject := range map[string]string{
		"sast:go/sql-injection":   "main.go#h/(*sql.DB).Query",
		"sarif:semgrep/go.crypto": "main.go",
	} {
		runCLI(t, "accept", id, dir, "--exceptions", ex, "--subject", subject, "--reason", "reviewed fixture", "--expires", "2999-12-31")
	}
	report := securityReport(t, runCLI(t, "security", dir, "--offline", "--import", external, "--exceptions", ex, "--fail-on", "medium", "--format", "json"))
	if report.Suppressed() != 2 {
		t.Fatalf("suppressed = %d", report.Suppressed())
	}
}

func TestSecurityDependencyFailurePreservesSourceAndFailsDespiteNoFail(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	writeSecurityLock(t, dir, `{"lockfileVersion":`)
	output := filepath.Join(t.TempDir(), "security.json")
	_, err := execCLI(t, "", "security", dir, "--offline", "--no-fail", "--format", "json", "--output", output)
	if err == nil || !strings.Contains(err.Error(), "dependency analysis incomplete") {
		t.Fatalf("want operational failure, got %v", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	report := securityReport(t, raw)
	ids := map[string]bool{}
	for _, f := range report.Findings {
		ids[f.ID] = true
	}
	if !ids["sast:go/sql-injection"] || !ids["security:dependencies-incomplete"] {
		t.Fatalf("partial results lost: %+v", report)
	}
}

func TestSecurityOutputFormatsAndValidation(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	for _, format := range []string{"text", "json", "sarif", "junit", "markdown"} {
		t.Run(format, func(t *testing.T) {
			raw := runCLI(t, "security", dir, "--offline", "--no-fail", "--format", format)
			if !strings.Contains(string(raw), "sast:go/sql-injection") {
				t.Fatalf("source finding missing: %s", raw)
			}
		})
	}
	for _, args := range [][]string{
		{"--fail-on", "invalid"}, {"--network", "invalid"}, {"--profile", "invalid"}, {"--format", "invalid"}, {"--import", filepath.Join(dir, "missing.sarif")},
	} {
		command := append([]string{"security", dir, "--offline", "--no-fail"}, args...)
		if _, err := execCLI(t, "", command...); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}
