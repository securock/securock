package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/cli"
)

type sarifResults struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, raw []byte) sarifResults {
	t.Helper()
	var log sarifResults
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("invalid sarif: %v\n%s", err, raw)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected sarif:\n%s", raw)
	}
	return log
}

func writeDenoLock(t *testing.T, dir, resolved string) {
	t.Helper()
	lock := `{"version": "5", "redirects": {"https://esm.sh/preact": "https://esm.sh/preact@` + resolved + `"}}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSARIFOnScan(t *testing.T) {
	isolateHome(t)
	dir := filepath.Join("..", "ecosystem", "npm", "testdata")

	log := parseSARIF(t, runCLI(t, "scan", dir, "--offline", "--no-fail", "--format", "sarif"))
	run := log.Runs[0]
	if run.Tool.Driver.Name != "securock scan" {
		t.Fatalf("tool: %s", run.Tool.Driver.Name)
	}
	if len(run.Results) == 0 {
		t.Fatal("offline scans leave artifacts unknown, expected results")
	}
	if run.Results[0].RuleID != "unknown-artifact" {
		t.Fatalf("rule: %s", run.Results[0].RuleID)
	}
	if got := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "../ecosystem/npm/testdata/securock.lock" {
		t.Fatalf("location should anchor on the lockfile: %s", got)
	}
}

func TestSARIFOnVerifyAndDiff(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	writeDenoLock(t, dir, "10.26.8")
	runCLI(t, "lock", dir, "--offline", "--no-fail")

	for _, cmd := range []string{"verify", "diff"} {
		log := parseSARIF(t, runCLI(t, cmd, dir, "--offline", "--no-fail", "--format", "sarif"))
		if n := len(log.Runs[0].Results); n != 0 {
			t.Fatalf("%s: expected no results without drift, got %d", cmd, n)
		}
	}

	writeDenoLock(t, dir, "10.26.9")
	for _, cmd := range []string{"verify", "diff"} {
		log := parseSARIF(t, runCLI(t, cmd, dir, "--offline", "--no-fail", "--format", "sarif"))
		run := log.Runs[0]
		if run.Tool.Driver.Name != "securock "+cmd {
			t.Fatalf("%s: tool %s", cmd, run.Tool.Driver.Name)
		}
		if len(run.Results) == 0 {
			t.Fatalf("%s: expected drift results", cmd)
		}
	}
}

func TestOutputFlagWritesFileEvenOnTrustViolation(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	writeDenoLock(t, dir, "10.26.8")
	runCLI(t, "lock", dir, "--offline", "--no-fail")
	writeDenoLock(t, dir, "10.26.9")

	out := filepath.Join(t.TempDir(), "verify.sarif")
	root := cli.NewRoot("test", "none", "unknown")
	stdout := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stdout)
	root.SetArgs([]string{"verify", dir, "--offline", "--format", "sarif", "--output", out})
	if err := root.Execute(); err == nil {
		t.Fatal("expected a trust violation")
	}
	if stdout.Len() != 0 {
		t.Fatalf("report should not go to stdout:\n%s", stdout.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if log := parseSARIF(t, raw); len(log.Runs[0].Results) == 0 {
		t.Fatalf("expected results in %s", out)
	}
}

func TestAuditAndDoctorSARIFHaveLocations(t *testing.T) {
	isolateHome(t)
	dir := filepath.Join("..", "ecosystem", "npm", "testdata")
	log := parseSARIF(t, runCLI(t, "audit", dir, "--offline", "--no-fail", "--format", "sarif"))
	for _, res := range log.Runs[0].Results {
		if len(res.Locations) == 0 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Fatalf("audit result without a physical location: %+v", res)
		}
	}
}
