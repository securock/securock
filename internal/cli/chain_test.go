package cli_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

// runCLIExpectError runs the CLI and fails the test when it exits 0.
func runCLIExpectError(t *testing.T, args ...string) {
	t.Helper()
	root := cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(args)
	if err := root.Execute(); err == nil {
		t.Fatalf("expected a non-zero exit, output:\n%s", out.String())
	}
}

// twoFuncsGo puts a dataflow finding and a boundary finding in one file but in
// different functions, so their chain is possible rather than confirmed.
const twoFuncsGo = `package main

import (
	"database/sql"
	"net/http"
)

func h(db *sql.DB, r *http.Request) {
	db.Query("SELECT * FROM t WHERE id = " + r.FormValue("id"))
}

func set(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "s", Value: "1"})
}
`

func TestChainJSONMatchesSchema(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, twoFuncsGo)

	raw := runCLI(t, "chain", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("chain-report.schema.json", raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	var report struct {
		Chains []struct {
			ID       string
			Status   string
			Severity string
			Nodes    []struct {
				FindingID string `json:"finding"`
				Stage     string
			}
		} `json:"chains"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Chains) != 2 {
		t.Fatalf("chains = %+v\n%s", report.Chains, raw)
	}
	var possible bool
	for _, c := range report.Chains {
		if c.Status == "possible" {
			possible = true
			if len(c.Nodes) != 2 || c.Nodes[0].Stage != "entry" || c.Nodes[1].Stage != "pivot" {
				t.Fatalf("possible chain = %+v", c)
			}
		}
	}
	if !possible {
		t.Fatalf("expected a possible chain:\n%s", raw)
	}
}

func TestChainSARIFShowsThePath(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)

	raw := runCLI(t, "chain", dir, "--offline", "--no-fail", "--format", "sarif")
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
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
	if len(res) != 1 || res[0].RuleID != "chain" {
		t.Fatalf("results = %+v", res)
	}
	if len(res[0].CodeFlows) != 1 || len(res[0].CodeFlows[0].ThreadFlows[0].Locations) != 2 {
		t.Fatalf("codeFlows = %+v", res[0])
	}
	if uri := res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "main.go" {
		t.Fatalf("uri = %s", uri)
	}
}

func TestChainFailsOnConfirmedChainOnly(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)

	runCLIExpectError(t, "chain", dir, "--offline")

	// A project whose only chains are possible never fails, whatever the threshold.
	dir = writeGo(t, `package main

import (
	"net/http"
	"os/exec"
)

func run(cmd string) {
	exec.Command(cmd).Run()
}

func set(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "s", Value: "1"})
}
`)
	out := runCLI(t, "chain", dir, "--offline", "--assume-params", "--fail-on", "low")
	if !bytes.HasPrefix(out, []byte("1 chain")) || !bytes.Contains(out, []byte("possible")) {
		t.Fatalf("output = %s", out)
	}

	clean := writeGo(t, "package main\n\nfunc main() {}\n")
	out = runCLI(t, "chain", clean, "--offline")
	if !bytes.HasPrefix(out, []byte("0 chains")) {
		t.Fatalf("output = %s", out)
	}
}
