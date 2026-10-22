package doctor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
