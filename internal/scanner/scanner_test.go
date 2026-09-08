package scanner_test

import (
	"context"
	"testing"
	"time"

	"github.com/securock/securock/internal/ecosystem"
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
		Now:     time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Artifacts) != 3 {
		t.Fatalf("got %d artifacts", len(result.Document.Artifacts))
	}
	trusted, untrusted, unknown := scanner.Summary(result.Document)
	if trusted != 3 || untrusted != 0 || unknown != 0 {
		t.Fatalf("summary = %d/%d/%d", trusted, untrusted, unknown)
	}
}

func TestScanWithVulnerabilities(t *testing.T) {
	result, err := scanner.Scan(context.Background(), scanner.Options{
		Path:   "../ecosystem/npm/testdata",
		Policy: policy.Default(),
		Client: fakeOSV{vulns: map[string][]lockfile.Vulnerability{
			"npm:react@19.2.0": {{ID: "GHSA-test"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, untrusted, _ := scanner.Summary(result.Document)
	if untrusted != 1 {
		t.Fatalf("untrusted = %d, want 1", untrusted)
	}
}
