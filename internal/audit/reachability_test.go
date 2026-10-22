package audit_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

func TestVulnerabilitySeverityFollowsReachability(t *testing.T) {
	tests := []struct {
		name  string
		vuln  lockfile.Vulnerability
		sev   finding.Severity
		title string
		in    string
	}{
		{"not recorded", lockfile.Vulnerability{ID: "GHSA-1"}, finding.SeverityHigh, "Known vulnerability", "GHSA-1"},
		{"unknown", lockfile.Vulnerability{ID: "GHSA-1", Reachable: lockfile.ReachUnknown}, finding.SeverityHigh, "Known vulnerability", "GHSA-1"},
		{"direct runtime", lockfile.Vulnerability{ID: "GHSA-1", Reachable: lockfile.ReachYes}, finding.SeverityHigh, "Known vulnerability", "runtime dependency"},
		{"via path", lockfile.Vulnerability{ID: "GHSA-1", Reachable: lockfile.ReachYes, Via: []string{"npm:a@1", "npm:b@1"}}, finding.SeverityHigh, "Known vulnerability", "npm:a@1 -> npm:b@1"},
		{"dev only", lockfile.Vulnerability{ID: "GHSA-1", Reachable: lockfile.ReachNo}, finding.SeverityLow, "development-only", "not part of the runtime"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {
				a.Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{tt.vuln}
			})
			var got *finding.Finding
			for _, f := range audit.Run(doc).Findings {
				if f.ID == "known-vulnerability:GHSA-1" {
					f := f
					got = &f
				}
			}
			if got == nil {
				t.Fatal("no finding")
			}
			if got.Severity != tt.sev || !strings.Contains(got.Title, tt.title) || !strings.Contains(got.Detail, tt.in) {
				t.Fatalf("got %+v", *got)
			}
		})
	}
}
