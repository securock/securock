package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/internal/scanner"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

type fakeOSV struct {
	vulns map[string][]lockfile.Vulnerability
}

func (f fakeOSV) Query(_ context.Context, deps []ecosystem.Dependency) (map[string][]lockfile.Vulnerability, error) {
	out := make(map[string][]lockfile.Vulnerability, len(deps))
	for _, dep := range deps {
		key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		out[key] = f.vulns[key]
	}
	return out, nil
}

func TestScanOffline(t *testing.T) {
	result, err := scanner.Scan(context.Background(), scanner.Options{
		Path:    "../ecosystem/npm/testdata",
		Offline: true,
		Policy:  policy.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Artifacts) != 3 {
		t.Fatalf("got %d artifacts", len(result.Document.Artifacts))
	}
	trusted, untrusted, unknown := scanner.Summary(result.Document)
	if trusted != 0 || untrusted != 0 || unknown != 3 {
		t.Fatalf("summary = %d/%d/%d", trusted, untrusted, unknown)
	}
}

type fakeEvidence map[string]evidence.Record

func (f fakeEvidence) Collect(_ context.Context, deps []ecosystem.Dependency) (map[string]evidence.Record, error) {
	out := make(map[string]evidence.Record, len(deps))
	for _, dep := range deps {
		key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		out[key] = f[key]
	}
	return out, nil
}

func TestScanWithVulnerabilities(t *testing.T) {
	result, err := scanner.Scan(context.Background(), scanner.Options{
		Path:   "../ecosystem/npm/testdata",
		Policy: policy.Default(),
		Client: fakeOSV{vulns: map[string][]lockfile.Vulnerability{
			"npm:react@19.2.0": {{ID: "GHSA-test"}},
		}},
		Evidence: fakeEvidence{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, untrusted, _ := scanner.Summary(result.Document)
	if untrusted != 1 {
		t.Fatalf("untrusted = %d, want 1", untrusted)
	}
}

func TestScanPrivateNotQueried(t *testing.T) {
	dir := t.TempDir()
	raw := `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@company/internal-auth": {
      "version": "1.0.0",
      "resolved": "https://npm.company.example/@company/internal-auth/-/internal-auth-1.0.0.tgz",
      "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	client := &countingOSV{}
	result, err := scanner.Scan(context.Background(), scanner.Options{
		Path:   dir,
		Policy: policy.Default(),
		Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.n != 0 {
		t.Fatalf("queried %d private packages", client.n)
	}
	if result.Document.Artifacts[0].Evidence.Vulnerabilities.State != lockfile.VulnUnknown {
		t.Fatalf("state = %s", result.Document.Artifacts[0].Evidence.Vulnerabilities.State)
	}
	if result.Document.Artifacts[0].Trust.Status != lockfile.StatusUnknown {
		t.Fatalf("trust = %s", result.Document.Artifacts[0].Trust.Status)
	}
}

func TestScanPnpmChecksVulns(t *testing.T) {
	client := &countingOSV{}
	result, err := scanner.Scan(context.Background(), scanner.Options{
		Path:     "../ecosystem/pnpm/testdata",
		Policy:   policy.Default(),
		Client:   client,
		Evidence: fakeEvidence{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.n != 3 {
		t.Fatalf("queried %d packages, want 3", client.n)
	}
	for _, art := range result.Document.Artifacts {
		if art.Evidence.Vulnerabilities.State != lockfile.VulnChecked {
			t.Fatalf("%s state = %s", art.Subject.Name, art.Evidence.Vulnerabilities.State)
		}
		if art.Trust.Status != lockfile.StatusTrusted {
			t.Fatalf("%s trust = %s", art.Subject.Name, art.Trust.Status)
		}
	}
}

type countingOSV struct {
	n int
}

func (c *countingOSV) Query(_ context.Context, deps []ecosystem.Dependency) (map[string][]lockfile.Vulnerability, error) {
	c.n += len(deps)
	return map[string][]lockfile.Vulnerability{}, nil
}
