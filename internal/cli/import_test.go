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

const importSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[
  {"ruleId":"go.sqli","level":"error","message":{"text":"SQL built from input"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"cmd/x.go"},"region":{"startLine":12}}}]},
  {"ruleId":"go.todo","level":"note","message":{"text":"tidy up"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"cmd/y.go"},"region":{"startLine":3}}}]}
]}]}`

func writeSARIF(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := os.WriteFile(path, []byte(importSARIF), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func execCLI(t *testing.T, stdin string, args ...string) ([]byte, error) {
	t.Helper()
	root := cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.Execute()
	return out.Bytes(), err
}

func TestImportJSONMatchesSchema(t *testing.T) {
	isolateHome(t)
	raw := runCLI(t, "import", writeSARIF(t), "--no-fail", "--format", "json")
	if err := schemas.Validate("import-report.schema.json", raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	var report struct {
		Findings []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Subject  string `json:"subject"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 || report.Findings[0].ID != "sarif:semgrep/go.sqli" || report.Findings[0].Severity != "high" || report.Findings[0].Subject != "cmd/x.go" {
		t.Fatalf("unexpected findings: %s", raw)
	}
}

func TestImportFailOn(t *testing.T) {
	isolateHome(t)
	path := writeSARIF(t)

	if _, err := execCLI(t, "", "import", path); err == nil {
		t.Fatal("a high finding must fail at the default threshold")
	}
	if _, err := execCLI(t, "", "import", path, "--fail-on", "critical"); err != nil {
		t.Fatalf("nothing is critical: %v", err)
	}
	if _, err := execCLI(t, "", "import", path, "--fail-on", "low"); err == nil {
		t.Fatal("--fail-on low must fail on the note")
	}
}

func TestImportHonorsExceptions(t *testing.T) {
	isolateHome(t)
	path := writeSARIF(t)
	ex := filepath.Join(t.TempDir(), "exceptions.yaml")

	runCLI(t, "accept", "sarif:semgrep/go.sqli", t.TempDir(), "--exceptions", ex,
		"--subject", "cmd/x.go", "--reason", "input is validated upstream", "--expires", "2999-12-31")
	out, err := execCLI(t, "", "import", path, "--exceptions", ex)
	if err != nil {
		t.Fatalf("an accepted finding must not fail the build: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "accepted until 2999-12-31") {
		t.Fatalf("the finding should stay in the report as suppressed:\n%s", out)
	}
}

func TestImportReadsStdinAndMergesFiles(t *testing.T) {
	isolateHome(t)
	out, err := execCLI(t, importSARIF, "import", "-", writeSARIF(t), "--no-fail", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(out, &report); err != nil || len(report.Findings) != 4 {
		t.Fatalf("want findings from both inputs: %v\n%s", err, out)
	}
}

func TestImportErrors(t *testing.T) {
	isolateHome(t)
	bad := filepath.Join(t.TempDir(), "bad.sarif")
	if err := os.WriteFile(bad, []byte(`{"version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no file":      {"import"},
		"missing file": {"import", filepath.Join(t.TempDir(), "none.sarif")},
		"bad version":  {"import", bad},
		"bad fail-on":  {"import", writeSARIF(t), "--fail-on", "loud"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := execCLI(t, "", args...); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestImportMakesPathsRelativeToTheWorkingDirectory(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	t.Chdir(dir)
	abs, err := os.Getwd() // the resolved path, which is what the command sees
	if err != nil {
		t.Fatal(err)
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[
	  {"ruleId":"r","level":"error","message":{"text":"m"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file://` + filepath.ToSlash(abs) + `/cmd/x.go"},"region":{"startLine":4}}}]}]}]}`
	path := filepath.Join(t.TempDir(), "abs.sarif")
	if err := os.WriteFile(path, []byte(sarif), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := execCLI(t, "", "import", path, "--no-fail", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), abs) || !strings.Contains(string(out), `"subject": "cmd/x.go"`) {
		t.Fatalf("the absolute path should be relative:\n%s", out)
	}
}
