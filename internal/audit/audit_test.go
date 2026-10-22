package audit_test

import (
	"testing"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

func artifact(mutate func(*lockfile.Artifact)) lockfile.Document {
	art := lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: "npm", Name: "left-pad"},
		Version: "1.0.0",
		Digest:  "sha512-abc",
		Evidence: lockfile.Evidence{
			Provenance:      lockfile.EvidenceVerified,
			Signature:       lockfile.EvidenceVerified,
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
		},
	}
	mutate(&art)
	return lockfile.Document{Artifacts: []lockfile.Artifact{art}}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lockfile.Artifact)
		id     string
		sev    finding.Severity
	}{
		{"malicious", func(a *lockfile.Artifact) {
			a.Evidence.Malicious.Reports = []lockfile.MaliciousReport{{ID: "MAL-1"}}
		}, "malicious-package:MAL-1", finding.SeverityCritical},
		{"vulnerability", func(a *lockfile.Artifact) {
			a.Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{{ID: "GHSA-1"}}
		}, "known-vulnerability:GHSA-1", finding.SeverityHigh},
		{"missing digest", func(a *lockfile.Artifact) { a.Digest = "" }, "missing-digest", finding.SeverityMedium},
		{"missing provenance", func(a *lockfile.Artifact) { a.Evidence.Provenance = lockfile.EvidenceMissing }, "missing-provenance", finding.SeverityLow},
		{"unchecked vulnerabilities", func(a *lockfile.Artifact) { a.Evidence.Vulnerabilities.State = lockfile.VulnUnknown }, "vulnerability-unchecked", finding.SeverityInfo},
		{"install scripts", func(a *lockfile.Artifact) {
			a.Evidence.Capabilities = lockfile.CapabilityEvidence{State: lockfile.CapChecked, InstallScripts: lockfile.Bool(true)}
		}, "capability:install-scripts", finding.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := audit.Run(artifact(tt.mutate))
			for _, f := range report.Findings {
				if f.ID == tt.id {
					if f.Severity != tt.sev {
						t.Fatalf("severity %s, want %s", f.Severity, tt.sev)
					}
					if f.Subject != "npm:left-pad@1.0.0" {
						t.Fatalf("subject %q", f.Subject)
					}
					return
				}
			}
			t.Fatalf("finding %s not reported: %+v", tt.id, report.Findings)
		})
	}
}

func TestRunCleanArtifact(t *testing.T) {
	report := audit.Run(artifact(func(*lockfile.Artifact) {}))
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", report.Findings)
	}
}
