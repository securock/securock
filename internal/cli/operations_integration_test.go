package cli_test

import (
	"encoding/json"
	"github.com/securock/securock/internal/lifecycle"
	"github.com/securock/securock/internal/runrecord"
	"github.com/securock/securock/schemas"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordedOperationsWorkflow(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	outdir := t.TempDir()
	record := filepath.Join(outdir, "run.json")
	runCLI(t, "security", dir, "--offline", "--no-fail", "--record", record, "--scope-id", "fixture")
	raw, e := os.ReadFile(record)
	if e != nil {
		t.Fatal(e)
	}
	if e := schemas.Validate("run-record.schema.json", raw); e != nil {
		t.Fatal(e)
	}
	var run runrecord.Record
	if e := json.Unmarshal(raw, &run); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(outdir, "issues.json")
	raw = runCLI(t, "triage", record, "--state", state, "--format", "json")
	if e := schemas.Validate("lifecycle.schema.json", raw); e != nil {
		t.Fatal(e)
	}
	var registry lifecycle.Registry
	json.Unmarshal(raw, &registry)
	if len(registry.Entries) == 0 {
		t.Fatal("missing findings")
	}
	runCLI(t, "triage", record, "--state", state, "--finding", registry.Entries[0].Key, "--owner", "team", "--due", "2030-01-02", "--as-of", "2030-01-03")
	report := filepath.Join(outdir, "report.json")
	r, _ := json.Marshal(run.Report)
	os.WriteFile(report, r, 0600)
	raw = runCLI(t, "prioritize", report, "--format", "json")
	if e := schemas.Validate("priority-report.schema.json", raw); e != nil {
		t.Fatal(e)
	}
	org := filepath.Join(outdir, "org.json")
	os.WriteFile(org, []byte(`{"version":1,"services":{"api":{"owner":"team","criticality":5,"fail_on":"high","sla_days":{"high":7},"require_approver":true,"reviewers":["alice"],"max_exception_days":30}}}`), 0600)
	raw = runCLI(t, "enforce", report, "--organization", org, "--service", "api", "--as-of", "2030-01-01", "--no-fail", "--format", "json")
	if e := schemas.Validate("organization-report.schema.json", raw); e != nil {
		t.Fatal(e)
	}
}
func TestLocalIntegrationHarness(t *testing.T) {
	isolateHome(t)
	raw := runCLI(t, "integration", "--local", "--format", "json")
	if e := schemas.Validate("integration-report.schema.json", raw); e != nil {
		t.Fatalf("%v\n%s", e, raw)
	}
}
