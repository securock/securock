package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

const vulnerableHandler = `package main

import (
	"database/sql"
	"net/http"
)

func h(db *sql.DB, r *http.Request) {
	db.Query("SELECT * FROM t WHERE id = " + r.FormValue("id"))
}
`

func writeGo(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSASTJSONMatchesSchema(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)

	raw := runCLI(t, "sast", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("sast-report.schema.json", raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	var report struct {
		Findings []struct{ ID string } `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "sast:go/sql-injection" {
		t.Fatalf("findings = %+v", report.Findings)
	}
}

func TestSASTSARIFHasRegionAndCodeFlow(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)

	raw := runCLI(t, "sast", dir, "--offline", "--no-fail", "--format", "sarif")
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
						Region           struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				CodeFlows []struct {
					ThreadFlows []struct {
						Locations []struct{} `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	res := log.Runs[0].Results
	if len(res) != 1 || res[0].RuleID != "sast:go/sql-injection" {
		t.Fatalf("results = %+v", res)
	}
	loc := res[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "main.go" || loc.Region.StartLine != 9 {
		t.Fatalf("location = %+v", loc)
	}
	if len(res[0].CodeFlows) != 1 || len(res[0].CodeFlows[0].ThreadFlows[0].Locations) < 2 {
		t.Fatalf("codeFlows = %+v", res[0].CodeFlows)
	}
}

func TestSASTFailsOnFindingUnlessNoFail(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)

	root := cli.NewRoot("test", "none", "unknown")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"sast", dir, "--offline"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected a non-zero exit for a high finding")
	}
	clean := writeGo(t, "package main\n\nfunc main() {}\n")
	out := runCLI(t, "sast", clean, "--offline")
	if !strings.HasPrefix(string(out), "0 findings") {
		t.Fatalf("output = %s", out)
	}
}

// A file that cannot be analyzed is info-severity, below the default --fail-on high, so
// only the incomplete-analysis check keeps an unfinished scan from reading as a pass.
func TestAnalysisIncompleteFailsClosed(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, "package main\n\nfunc broken( {\n")
	for _, cmd := range []string{"sast", "security"} {
		t.Run(cmd, func(t *testing.T) {
			out, err := runCLIErr(t, cmd, dir, "--offline", "--format", "json")
			if err == nil || !strings.Contains(err.Error(), "source analysis incomplete") {
				t.Fatalf("incomplete analysis must fail: err=%v\n%s", err, out)
			}
			if !strings.Contains(out, "sast:analysis-incomplete") {
				t.Fatalf("report must still list the unanalyzed file:\n%s", out)
			}
			if _, err := runCLIErr(t, cmd, dir, "--offline", "--no-fail", "--format", "json"); err == nil {
				t.Fatal("--no-fail must not hide an unfinished analysis")
			}
		})
	}
	runCLI(t, "accept", "sast:analysis-incomplete", dir, "--reason", "generated file", "--approver", "alice", "--expires", "2999-12-31", "--subject", "main.go")
	if out, err := runCLIErr(t, "sast", dir, "--offline", "--format", "json"); err != nil {
		t.Fatalf("an accepted unanalyzed file must pass: %v\n%s", err, out)
	}
}
