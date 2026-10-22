package lockfile_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/pkg/lockfile"
)

func reachDoc() lockfile.Document {
	return lockfile.Document{
		Version: lockfile.SchemaVersion,
		Artifacts: []lockfile.Artifact{{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Evidence: lockfile.Evidence{
				Provenance:      lockfile.EvidenceUnknown,
				Signature:       lockfile.EvidenceUnknown,
				Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnUnknown},
				Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnUnknown},
				Capabilities:    lockfile.CapabilityEvidence{State: lockfile.CapUnknown},
				Behavior:        lockfile.BehaviorEvidence{State: lockfile.CapUnknown},
				Ownership:       lockfile.OwnershipEvidence{State: lockfile.CapUnknown},
				Chain:           lockfile.ChainEvidence{State: lockfile.EvidenceUnknown},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusUnknown},
		}},
	}
}

func TestValidateScopeAndReachability(t *testing.T) {
	doc := func(mutate func(*lockfile.Artifact)) lockfile.Document {
		d := reachDoc()
		d.Artifacts[0].Evidence.Vulnerabilities = lockfile.VulnEvidence{
			State: lockfile.VulnChecked,
			Items: []lockfile.Vulnerability{{ID: "GHSA-1"}},
		}
		mutate(&d.Artifacts[0])
		return d
	}
	tests := []struct {
		name    string
		mutate  func(*lockfile.Artifact)
		wantErr string
	}{
		{"none", func(*lockfile.Artifact) {}, ""},
		{"all fields", func(a *lockfile.Artifact) {
			a.Scope = lockfile.ScopeRuntime
			a.Dependencies = []string{"npm:b@1.0.0"}
			a.Evidence.Vulnerabilities.Items[0].Reachable = lockfile.ReachYes
			a.Evidence.Vulnerabilities.Items[0].Via = []string{"npm:a@1.0.0", "npm:react@19.2.0"}
		}, ""},
		{"unknown scope", func(a *lockfile.Artifact) { a.Scope = "build" }, "unknown scope"},
		{"unknown reachability", func(a *lockfile.Artifact) { a.Evidence.Vulnerabilities.Items[0].Reachable = "maybe" }, "unknown reachability"},
		{"empty dependency", func(a *lockfile.Artifact) { a.Dependencies = []string{""} }, "missing dependency id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lockfile.Validate(doc(tt.mutate))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalizeSortsDependencies(t *testing.T) {
	d := reachDoc()
	d.Artifacts[0].Dependencies = []string{"npm:z@1", "npm:a@1", "npm:z@1"}
	lockfile.Canonicalize(&d)
	got := d.Artifacts[0].Dependencies
	if len(got) != 2 || got[0] != "npm:a@1" || got[1] != "npm:z@1" {
		t.Fatalf("dependencies = %v", got)
	}
}

func TestValidateAdvisoryDetail(t *testing.T) {
	doc := func(v lockfile.Vulnerability) lockfile.Document {
		d := reachDoc()
		d.Artifacts[0].Evidence.Vulnerabilities = lockfile.VulnEvidence{State: lockfile.VulnChecked, Items: []lockfile.Vulnerability{v}}
		return d
	}
	if err := lockfile.Validate(doc(lockfile.Vulnerability{ID: "G", Severity: lockfile.SeverityHigh, Fixed: []string{"1.2.3"}})); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]lockfile.Vulnerability{
		"unknown severity": {ID: "G", Severity: "urgent"},
		"empty fixed":      {ID: "G", Fixed: []string{""}},
	} {
		if err := lockfile.Validate(doc(v)); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}
