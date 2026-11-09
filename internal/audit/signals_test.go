package audit_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/exploit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

func TestExploitSignalsRaiseSeverity(t *testing.T) {
	tests := []struct {
		name      string
		advisory  lockfile.VulnSeverity
		reachable lockfile.Reachability
		sig       exploit.Signal
		want      finding.Severity
		note      string
	}{
		{"no signal", lockfile.SeverityMedium, "", exploit.Signal{}, finding.SeverityMedium, ""},
		{"kev raises to critical", lockfile.SeverityMedium, "", exploit.Signal{KEV: true}, finding.SeverityCritical, "actively exploited (CISA KEV)"},
		{"kev on low advisory", lockfile.SeverityLow, "", exploit.Signal{KEV: true, EPSS: 0.9, HasEPSS: true}, finding.SeverityCritical, "EPSS 90.0%"},
		{"high epss raises to high", lockfile.SeverityLow, "", exploit.Signal{EPSS: 0.5, HasEPSS: true}, finding.SeverityHigh, "EPSS 50.0%"},
		{"low epss changes nothing", lockfile.SeverityMedium, "", exploit.Signal{EPSS: 0.49, HasEPSS: true}, finding.SeverityMedium, "EPSS 49.0%"},
		{"never lowers a critical", lockfile.SeverityCritical, "", exploit.Signal{EPSS: 0.9, HasEPSS: true}, finding.SeverityCritical, ""},
		{"never lowers on a tiny score", lockfile.SeverityHigh, "", exploit.Signal{EPSS: 0.0004, HasEPSS: true}, finding.SeverityHigh, "EPSS 0.0%"},
		{"runtime dependency is raised", lockfile.SeverityMedium, lockfile.ReachYes, exploit.Signal{KEV: true}, finding.SeverityCritical, ""},
		{"dev-only stays low but shows the signal", lockfile.SeverityHigh, lockfile.ReachNo, exploit.Signal{KEV: true}, finding.SeverityLow, "actively exploited (CISA KEV)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {
				a.Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{{ID: "GHSA-x", Severity: tt.advisory, Reachable: tt.reachable}}
			})
			opts := audit.Options{Signals: map[string]exploit.Signal{"GHSA-x": tt.sig}}
			var got *finding.Finding
			for _, f := range audit.RunWith(doc, opts).Findings {
				if f.ID == "known-vulnerability:GHSA-x" {
					got = &f
				}
			}
			if got == nil {
				t.Fatal("finding keeps its ID, so exceptions still match it")
			}
			if got.Severity != tt.want {
				t.Errorf("severity = %s, want %s (%s)", got.Severity, tt.want, got.Detail)
			}
			if tt.note != "" && !strings.Contains(got.Detail, tt.note) {
				t.Errorf("detail %q should mention %q", got.Detail, tt.note)
			}
		})
	}
}

func TestExploitSignalsOnlyApplyToTheirAdvisory(t *testing.T) {
	doc := artifact(func(a *lockfile.Artifact) {
		a.Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{
			{ID: "GHSA-hot", Severity: lockfile.SeverityLow},
			{ID: "GHSA-cold", Severity: lockfile.SeverityLow},
		}
	})
	opts := audit.Options{Signals: map[string]exploit.Signal{"GHSA-hot": {KEV: true}}}
	got := map[string]finding.Severity{}
	for _, f := range audit.RunWith(doc, opts).Findings {
		got[f.ID] = f.Severity
	}
	if got["known-vulnerability:GHSA-hot"] != finding.SeverityCritical || got["known-vulnerability:GHSA-cold"] != finding.SeverityLow {
		t.Fatalf("unexpected severities: %v", got)
	}
}

func TestExploitSignalsUnavailable(t *testing.T) {
	doc := artifact(func(a *lockfile.Artifact) {})
	report := audit.RunWith(doc, audit.Options{SignalsUnavailable: "EPSS: status 429"})
	var found *finding.Finding
	for _, f := range report.Findings {
		if f.ID == "exploit-signals-unavailable" {
			found = &f
		}
	}
	if found == nil || found.Severity != finding.SeverityInfo || !strings.Contains(found.Detail, "429") {
		t.Fatalf("a failed lookup must be reported as info: %+v", found)
	}
	for _, f := range audit.RunWith(doc, audit.Options{}).Findings {
		if f.ID == "exploit-signals-unavailable" {
			t.Fatal("nothing to report when --prioritize was not used")
		}
	}
}
