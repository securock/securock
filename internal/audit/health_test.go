package audit_test

import (
	"testing"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

func TestHealthFindings(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		eco    string
		pkg    string
		health *lockfile.HealthEvidence
		want   map[string]finding.Severity
	}{
		{"nothing to report", "npm", "left-pad", &lockfile.HealthEvidence{Released: "2026-01-01", License: "MIT"}, nil},
		{"not checked", "npm", "left-pad", nil, nil},
		{"deprecated", "npm", "left-pad", &lockfile.HealthEvidence{Deprecated: "use x"}, map[string]finding.Severity{"deprecated-package": finding.SeverityMedium}},
		{"yanked", "pypi", "sample", &lockfile.HealthEvidence{Deprecated: "yanked: broken"}, map[string]finding.Severity{"deprecated-package": finding.SeverityMedium}},
		{"stale", "npm", "left-pad", &lockfile.HealthEvidence{Released: "2024-06-14"}, map[string]finding.Severity{"stale-release": finding.SeverityLow}},
		{"just under two years", "npm", "left-pad", &lockfile.HealthEvidence{Released: "2024-06-16"}, nil},
		{"unreadable date is ignored", "npm", "left-pad", &lockfile.HealthEvidence{Released: "sometime"}, nil},
		{"typosquat needs no health", "npm", "lodahs", nil, map[string]finding.Severity{"typosquat-suspect": finding.SeverityMedium}},
		{"all three", "npm", "lodahs", &lockfile.HealthEvidence{Deprecated: "x", Released: "2010-01-01"}, map[string]finding.Severity{
			"typosquat-suspect": finding.SeverityMedium, "deprecated-package": finding.SeverityMedium, "stale-release": finding.SeverityLow,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {
				a.Subject = lockfile.Subject{Ecosystem: tt.eco, Name: tt.pkg}
				a.Evidence.Health = tt.health
			})
			got := map[string]finding.Severity{}
			for _, f := range audit.RunAt(doc, now).Findings {
				switch f.ID {
				case "typosquat-suspect", "deprecated-package", "stale-release":
					got[f.ID] = f.Severity
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for id, sev := range tt.want {
				if got[id] != sev {
					t.Fatalf("%s: got %q, want %q (all: %v)", id, got[id], sev, got)
				}
			}
		})
	}
}
