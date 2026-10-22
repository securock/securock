package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

func runCLIErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestAcceptListRemove(t *testing.T) {
	dir := t.TempDir()
	out := string(runCLI(t, "accept", "known-vulnerability:GHSA-1", dir, "--reason", "not reachable", "--approver", "alice", "--expires", "2999-12-31", "--subject", "npm:lodash"))
	if !strings.Contains(out, "accepted known-vulnerability:GHSA-1 for npm:lodash until 2999-12-31") {
		t.Fatalf("accept output: %s", out)
	}
	file := filepath.Join(dir, ".securock", "exceptions.yaml")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"id: known-vulnerability:GHSA-1", "subject: npm:lodash", "reason: not reachable", "approver: alice", `expires: "2999-12-31"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("file missing %q:\n%s", want, raw)
		}
	}

	out = string(runCLI(t, "accept", "known-vulnerability:GHSA-1", dir, "--reason", "still not reachable", "--expires", "2999-12-30", "--subject", "npm:lodash"))
	if !strings.HasPrefix(out, "renewed ") {
		t.Fatalf("re-accepting should renew: %s", out)
	}

	text := string(runCLI(t, "accept", "list", dir))
	if !strings.Contains(text, "active") || !strings.Contains(text, "still not reachable") || strings.Count(text, "GHSA-1") != 1 {
		t.Fatalf("list output:\n%s", text)
	}
	var rows []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(runCLI(t, "accept", "list", dir, "--format", "json"), &rows); err != nil || len(rows) != 1 || rows[0].Status != "active" {
		t.Fatalf("json list: %v %+v", err, rows)
	}

	out = string(runCLI(t, "accept", "remove", "known-vulnerability:GHSA-1", dir, "--subject", "npm:lodash"))
	if !strings.HasPrefix(out, "removed ") {
		t.Fatalf("remove output: %s", out)
	}
	if got := string(runCLI(t, "accept", "list", dir)); !strings.Contains(got, "no accepted findings") {
		t.Fatalf("list after remove: %s", got)
	}
}

func TestAcceptValidation(t *testing.T) {
	dir := t.TempDir()
	tests := map[string][]string{
		"reason required":  {"accept", "a", dir, "--expires", "2999-12-31"},
		"expires required": {"accept", "a", dir, "--reason", "r"},
		"past date":        {"accept", "a", dir, "--reason", "r", "--expires", "2001-01-01"},
		"bad date":         {"accept", "a", dir, "--reason", "r", "--expires", "tomorrow"},
		"bad days":         {"accept", "a", dir, "--reason", "r", "--expires", "0d"},
		"remove missing":   {"accept", "remove", "a", dir},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := runCLIErr(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, ".securock")); err == nil {
		t.Fatal("failed accepts must not create the file")
	}
}

func TestAcceptRelativeDays(t *testing.T) {
	dir := t.TempDir()
	runCLI(t, "accept", "a", dir, "--reason", "r", "--expires", "30d")
	want := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	raw, _ := os.ReadFile(filepath.Join(dir, ".securock", "exceptions.yaml"))
	if !strings.Contains(string(raw), `expires: "`+want+`"`) {
		t.Fatalf("expected expires %s:\n%s", want, raw)
	}
}

func TestAuditHonorsAcceptedFindings(t *testing.T) {
	isolateHome(t)
	src := filepath.Join("..", "ecosystem", "npm", "testdata")
	exceptionsFile := filepath.Join(t.TempDir(), "exceptions.yaml")

	// Offline, every artifact reports two info-level "unchecked" findings.
	if _, err := runCLIErr(t, "audit", src, "--offline", "--fail-on", "info", "--exceptions", exceptionsFile); err == nil {
		t.Fatal("expected unchecked findings to fail at --fail-on info")
	}

	runCLI(t, "accept", "vulnerability-unchecked", src, "--exceptions", exceptionsFile, "--reason", "offline CI", "--expires", "2999-12-31")
	if _, err := runCLIErr(t, "audit", src, "--offline", "--fail-on", "info", "--exceptions", exceptionsFile); err == nil {
		t.Fatal("malicious-unchecked is still unaccepted")
	}
	runCLI(t, "accept", "missing-digest", src, "--exceptions", exceptionsFile, "--reason", "fixture has no digests", "--expires", "2999-12-31", "--subject", "npm:nested")
	runCLI(t, "accept", "malicious-unchecked", src, "--exceptions", exceptionsFile, "--reason", "offline CI", "--expires", "2999-12-31", "--approver", "alice")
	out, err := runCLIErr(t, "audit", src, "--offline", "--fail-on", "info", "--exceptions", exceptionsFile)
	if err != nil {
		t.Fatalf("all findings are accepted, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "0 findings") || !strings.Contains(out, "suppressed") {
		t.Fatalf("text output:\n%s", out)
	}

	js := runCLI(t, "audit", src, "--offline", "--fail-on", "info", "--exceptions", exceptionsFile, "--format", "json")
	if err := schemas.Validate("audit-report.schema.json", js); err != nil {
		t.Fatalf("audit json:\n%s\n%v", js, err)
	}
	if !bytes.Contains(js, []byte(`"approver": "alice"`)) {
		t.Fatalf("json missing the suppression:\n%s", js)
	}
	sarif := runCLI(t, "audit", src, "--offline", "--no-fail", "--exceptions", exceptionsFile, "--format", "sarif")
	if !bytes.Contains(sarif, []byte(`"suppressions"`)) {
		t.Fatalf("sarif missing suppressions:\n%s", sarif)
	}
}

func TestAuditExpiredExceptionFails(t *testing.T) {
	isolateHome(t)
	src := filepath.Join("..", "ecosystem", "npm", "testdata")
	file := filepath.Join(t.TempDir(), "exceptions.yaml")
	body := "version: 1\nexceptions:\n" +
		"  - id: vulnerability-unchecked\n    reason: offline CI\n    expires: 2001-01-01\n" +
		"  - id: malicious-unchecked\n    reason: offline CI\n    expires: 2999-12-31\n"
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLIErr(t, "audit", src, "--offline", "--fail-on", "medium", "--exceptions", file)
	if err == nil || !strings.Contains(out, "exception-expired") {
		t.Fatalf("an expired exception should surface at medium: err=%v\n%s", err, out)
	}
}

func TestAuditRejectsInvalidExceptions(t *testing.T) {
	isolateHome(t)
	src := filepath.Join("..", "ecosystem", "npm", "testdata")
	file := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(file, []byte("version: 1\nexceptions:\n  - id: a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLIErr(t, "audit", src, "--offline", "--no-fail", "--exceptions", file); err == nil {
		t.Fatal("an invalid exceptions file must be an error, not silently ignored")
	}
}
