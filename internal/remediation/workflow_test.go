package remediation_test

import (
	"context"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/remediation"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVerifiedFixPreservesCheckout(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		b, e := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
		if e != nil {
			t.Fatalf("%v %s", e, b)
		}
		return string(b)
	}
	run("init", "-q")
	run("config", "user.name", "Fixture")
	run("config", "user.email", "fixture@example.invalid")
	src := []byte("package fixture\nimport \"crypto/tls\"\nvar config = tls.Config{InsecureSkipVerify: true}\n")
	_ = os.WriteFile(filepath.Join(dir, "main.go"), src, 0600)
	run("add", "main.go")
	run("commit", "-q", "-m", "fixture")
	before := run("rev-parse", "HEAD")
	report := finding.New("sast", []finding.Finding{{ID: "sast:go/tls-verification-disabled", Severity: finding.SeverityHigh, Title: "TLS", Location: &finding.Location{File: "main.go", Line: 3}}})
	out, e := remediation.Fix(context.Background(), dir, "securock/verified", report, remediation.TestPlan{Commands: [][]string{{"git", "diff", "--check"}}})
	if e != nil {
		t.Fatal(e)
	}
	if !out.Verified || out.Tests != 1 || out.Revision == "" || run("rev-parse", "HEAD") != before {
		t.Fatal(out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "main.go"))
	if string(raw) != string(src) {
		t.Fatal("original checkout modified")
	}
	fixed := run("show", "securock/verified:main.go")
	if fixed == string(src) {
		t.Fatal("branch not fixed")
	}
	if _, e := remediation.Fix(context.Background(), dir, "securock/verified", report, remediation.TestPlan{Commands: [][]string{{"git", "diff", "--check"}}}); e == nil {
		t.Fatal("existing branch overwritten")
	}
}
