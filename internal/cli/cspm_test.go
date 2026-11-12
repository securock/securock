package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/schemas"
)

const cspmSnapshot = `{"configurationItems":[{"resourceType":"AWS::RDS::DBInstance","resourceId":"db-1","accountId":"123456789012","awsRegion":"ap-northeast-1","configuration":{"publiclyAccessible":true,"storageEncrypted":true,"backupRetentionPeriod":7}}]}`

func writeInventory(t *testing.T, raw string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestCSPMOfflineJSONFormatsAndExceptions(t *testing.T) {
	isolateHome(t)
	file := writeInventory(t, cspmSnapshot)
	ex := filepath.Join(t.TempDir(), "exceptions.yaml")
	raw, err := execCLI(t, "", "cspm", file, "--offline", "--format", "json", "--exceptions", ex)
	if err == nil || !strings.Contains(err.Error(), "findings at or above high") {
		t.Fatalf("expected risk failure: %v", err)
	}
	if err := schemas.Validate("cspm-report.schema.json", raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	runCLI(t, "accept", "cspm:rds-public", t.TempDir(), "--subject", "AWS::RDS::DBInstance/123456789012/ap-northeast-1/db-1", "--exceptions", ex, "--reason", "reviewed public endpoint", "--expires", "2999-12-31")
	raw = runCLI(t, "cspm", file, "--offline", "--format", "json", "--exceptions", ex)
	var report finding.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Suppressed() != 1 {
		t.Fatalf("acceptance lost: %s", raw)
	}
	for _, format := range []string{"text", "sarif", "junit", "markdown"} {
		runCLI(t, "cspm", file, "--offline", "--no-fail", "--format", format)
	}
}

func TestSecurityCSPMCombinesAndPreservesFindings(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	for _, raw := range []string{cspmSnapshot, `{"Results":["bad-json"]}`} {
		file := writeInventory(t, raw)
		output, err := execCLI(t, "", "security", dir, "--cloud-inventory", file, "--offline", "--no-fail", "--format", "json")
		if (err != nil) != (raw != cspmSnapshot) {
			t.Fatalf("unexpected result: %v", err)
		}
		report := securityReport(t, output)
		ids := map[string]bool{}
		for _, f := range report.Findings {
			ids[f.ID] = true
		}
		if !ids["sast:go/sql-injection"] {
			t.Fatal("source findings lost")
		}
		if raw == cspmSnapshot && !ids["cspm:rds-public"] {
			t.Fatal("cloud findings lost")
		}
		if raw != cspmSnapshot && !ids["cspm:analysis-incomplete"] {
			t.Fatal("incomplete coverage lost")
		}
	}
}

func TestCSPMIncompleteWritesReportAndContinuesFiles(t *testing.T) {
	isolateHome(t)
	good := writeInventory(t, cspmSnapshot)
	bad := writeInventory(t, `{`)
	output := filepath.Join(t.TempDir(), "cloud.json")
	_, err := execCLI(t, "", "cspm", bad, good, "--offline", "--no-fail", "--format", "json", "--output", output)
	if err == nil {
		t.Fatal("malformed inventory must be an operational error")
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.Validate("cspm-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "cspm:rds-public") || !strings.Contains(string(raw), "cspm:analysis-incomplete") {
		t.Fatalf("partial results lost: %s", raw)
	}
}

func fakeAWS(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake AWS CLI fixture")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	var snapshot struct {
		Items []json.RawMessage `json:"configurationItems"`
	}
	json.Unmarshal([]byte(cspmSnapshot), &snapshot)
	raw, _ := json.Marshal(map[string]any{"Results": []string{string(snapshot.Items[0])}})
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + quote(marker) + "\nprintf '%s' " + quote(string(raw)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return dir, marker
}

func TestCSPMLiveCollectionUsesOnlyReadOnlyCLI(t *testing.T) {
	isolateHome(t)
	_, marker := fakeAWS(t)
	raw := runCLI(t, "cspm", "--aws-region", "ap-northeast-1", "--aws-profile", "audit", "--network", "allow-all", "--no-fail", "--format", "json")
	if err := schemas.Validate("cspm-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(args), "configservice\nselect-resource-config\n") || !strings.Contains(string(args), "--profile\naudit\n") {
		t.Fatalf("unexpected AWS command: %s", args)
	}
	output := runCLI(t, "security", writeGo(t, "package main\n"), "--aws-region", "ap-northeast-1", "--network", "allow-all", "--no-fail", "--format", "json")
	report := securityReport(t, output)
	found := false
	for _, f := range report.Findings {
		if f.ID == "cspm:rds-public" {
			found = true
		}
	}
	if !found {
		t.Fatal("live cloud results missing from security report")
	}
}

func TestCSPMOfflineAndPublicOnlyNeverInvokeAWS(t *testing.T) {
	isolateHome(t)
	_, marker := fakeAWS(t)
	for _, base := range [][]string{{"cspm"}, {"security", t.TempDir()}} {
		for _, flags := range [][]string{{}, {"--offline"}, {"--network", "offline"}, {"--network", "allow-all", "--offline"}} {
			args := append(append([]string{}, base...), "--aws-region", "ap-northeast-1")
			args = append(args, flags...)
			if _, err := execCLI(t, "", args...); err == nil {
				t.Fatalf("expected network refusal: %v", args)
			}
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("AWS CLI was invoked: %v", err)
	}
}

func TestCSPMValidationAndCollectionFailure(t *testing.T) {
	isolateHome(t)
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{
		{"cspm"}, {"cspm", "--aws-profile", "audit"}, {"cspm", "--aws-region", "bad", "--network", "allow-all"},
		{"cspm", writeInventory(t, cspmSnapshot), "--offline", "--fail-on", "bad"},
	} {
		if _, err := execCLI(t, "", args...); err == nil {
			t.Fatalf("expected invalid option failure: %v", args)
		}
	}
	raw, err := execCLI(t, "", "cspm", "--aws-region", "us-east-1", "--network", "allow-all", "--no-fail", "--format", "json")
	if err == nil || !strings.Contains(string(raw), "cspm:analysis-incomplete") {
		t.Fatalf("missing CLI should fail with a report: %v\n%s", err, raw)
	}
}
