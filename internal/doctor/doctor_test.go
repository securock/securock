package doctor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/internal/doctor"
	"github.com/securock/securock/internal/finding"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ids(r finding.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}

func has(r finding.Report, prefix string) (finding.Finding, bool) {
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, prefix) {
			return f, true
		}
	}
	return finding.Finding{}, false
}

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
		id   string
		sev  finding.Severity
	}{
		{"http registry", ".npmrc", "registry=http://example.com/\n", "registry-insecure-http", finding.SeverityHigh},
		{"scoped http registry", ".npmrc", "@acme:registry=http://example.com/\n", "registry-insecure-http", finding.SeverityHigh},
		{"tls disabled", ".npmrc", "strict-ssl=false\n", "registry-tls-disabled", finding.SeverityHigh},
		{"literal token", ".npmrc", "//registry.npmjs.org/:_authToken=abc123\n", "registry-literal-credential", finding.SeverityCritical},
		{"yarn http", ".yarnrc.yml", "npmRegistryServer: \"http://example.com\"\n", "registry-insecure-http", finding.SeverityHigh},
		{"nuget http", "nuget.config", `<add key="a" value="http://example.com/index.json" />`, "registry-insecure-http", finding.SeverityHigh},
		{"unpinned action", ".github/workflows/ci.yml", "steps:\n  - uses: actions/checkout@v4\n", "action-not-pinned:", finding.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, tt.file, tt.body)
			f, ok := has(doctor.Run(doctor.Options{Root: dir}), tt.id)
			if !ok {
				t.Fatalf("finding %s not reported", tt.id)
			}
			if f.Severity != tt.sev {
				t.Fatalf("severity %s, want %s", f.Severity, tt.sev)
			}
		})
	}
}

func TestRunAcceptsSafeSetup(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".npmrc", "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
	sha := strings.Repeat("a", 40)
	write(t, dir, ".github/workflows/ci.yml", "steps:\n  - uses: actions/checkout@"+sha+" # v4\n  - uses: ./local\n")
	write(t, dir, ".github/rulesets/main.json", "{}")

	report := doctor.Run(doctor.Options{Root: dir, Profile: "strict"})
	got := ids(report)
	if len(got) != 1 || got[0] != "lock-missing" {
		t.Fatalf("expected only lock-missing, got %v", got)
	}
}

func TestLockAndPolicy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "securock.lock", "not json")
	write(t, dir, "policy.yaml", "version: 99\n")

	report := doctor.Run(doctor.Options{Root: dir, PolicyPath: filepath.Join(dir, "policy.yaml")})
	if _, ok := has(report, "lock-invalid"); !ok {
		t.Fatalf("lock-invalid not reported: %v", ids(report))
	}
	if _, ok := has(report, "policy-invalid"); !ok {
		t.Fatalf("policy-invalid not reported: %v", ids(report))
	}
	if _, ok := has(report, "rulesets-missing"); !ok {
		t.Fatalf("rulesets-missing not reported: %v", ids(report))
	}
}

func TestExceptions(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC) }
	body := `version: 1
exceptions:
  - id: known-vulnerability:GHSA-old
    subject: npm:old
    reason: waiting on upstream
    approver: alice
    expires: 2026-06-14
  - id: known-vulnerability:GHSA-soon
    reason: waiting on upstream
    approver: alice
    expires: 2026-06-20
  - id: capability:network
    reason: needed for telemetry
    expires: 2027-01-01
`
	dir := t.TempDir()
	write(t, dir, ".securock/exceptions.yaml", body)
	report := doctor.Run(doctor.Options{Root: dir, Now: clock})

	want := map[string]finding.Severity{
		"exception-expired":     finding.SeverityMedium,
		"exception-expiring":    finding.SeverityLow,
		"exception-no-approver": finding.SeverityInfo,
	}
	for id, sev := range want {
		f, ok := has(report, id)
		if !ok || f.Severity != sev {
			t.Fatalf("%s: got %+v (found %v) in %v", id, f, ok, ids(report))
		}
	}
	if f, _ := has(report, "exception-expired"); f.Subject != "npm:old" || !strings.Contains(f.Detail, "GHSA-old") {
		t.Fatalf("expired finding: %+v", f)
	}
	if n := countID(report, "exception-expired") + countID(report, "exception-expiring") + countID(report, "exception-no-approver"); n != 3 {
		t.Fatalf("each problem should be reported once, got %d in %v", n, ids(report))
	}
}

func countID(r finding.Report, id string) int {
	n := 0
	for _, f := range r.Findings {
		if f.ID == id {
			n++
		}
	}
	return n
}

func TestExceptionsOverrideAndInvalid(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "custom.yaml", "version: 1\nexceptions:\n  - id: a\n    reason: r\n    expires: nonsense\n")
	report := doctor.Run(doctor.Options{Root: dir, ExceptionsPath: "custom.yaml"})
	if f, ok := has(report, "exceptions-invalid"); !ok || f.Severity != finding.SeverityHigh {
		t.Fatalf("got %+v in %v", f, ids(report))
	}

	clean := doctor.Run(doctor.Options{Root: t.TempDir()})
	if _, ok := has(clean, "exception"); ok {
		t.Fatalf("no exceptions file should produce no exception findings: %v", ids(clean))
	}
}
