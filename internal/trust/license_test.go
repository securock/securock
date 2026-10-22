package trust_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/internal/trust"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func licensed(declared string) lockfile.Artifact {
	return healthArtifact("npm", "thing", &lockfile.HealthEvidence{License: declared})
}

func withLicenses(rule policy.LicenseRule) policy.Document {
	pol := policy.Default()
	pol.Rules.Licenses = rule
	return pol
}

func TestLicenseRules(t *testing.T) {
	tests := []struct {
		name   string
		art    lockfile.Artifact
		rule   policy.LicenseRule
		want   lockfile.Status
		reason string
	}{
		{"off by default", licensed("GPL-3.0"), policy.LicenseRule{}, lockfile.StatusTrusted, ""},
		{"denied", licensed("GPL-3.0-only"), policy.LicenseRule{Deny: []string{"GPL-*"}}, lockfile.StatusUntrusted, "denied license: GPL-3.0-only"},
		{"a choice avoids the denied license", licensed("MIT OR GPL-3.0-only"), policy.LicenseRule{Deny: []string{"GPL-*"}}, lockfile.StatusTrusted, ""},
		{"allowed", licensed("MIT"), policy.LicenseRule{Allow: []string{"MIT", "Apache-2.0"}}, lockfile.StatusTrusted, ""},
		{"not on the allow list", licensed("ISC"), policy.LicenseRule{Allow: []string{"MIT"}}, lockfile.StatusUntrusted, "license not allowed: ISC"},
		{"undeclared fails an allow list", licensed(""), policy.LicenseRule{Allow: []string{"MIT"}}, lockfile.StatusUntrusted, "license not declared"},
		{"undeclared passes a deny list alone", licensed(""), policy.LicenseRule{Deny: []string{"GPL-*"}}, lockfile.StatusTrusted, ""},
		{"not checked", healthArtifact("npm", "thing", nil), policy.LicenseRule{Deny: []string{"GPL-*"}}, lockfile.StatusUnknown, "license not checked"},
		{"not checked but unchecked is allowed", healthArtifact("cargo", "thing", nil), policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "allow"}, lockfile.StatusTrusted, ""},
		{"unchecked allow does not excuse a bad license", licensed("GPL-3.0-only"), policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "allow"}, lockfile.StatusUntrusted, "denied license"},
		{"unchecked unknown is the default spelled out", healthArtifact("cargo", "thing", nil), policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "unknown"}, lockfile.StatusUnknown, "license not checked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			art := tt.art
			trust.Evaluate(&art, withLicenses(tt.rule))
			if art.Trust.Status != tt.want {
				t.Fatalf("status = %s (%v), want %s", art.Trust.Status, art.Trust.Reasons, tt.want)
			}
			if tt.reason != "" && !strings.Contains(strings.Join(art.Trust.Reasons, "|"), tt.reason) {
				t.Fatalf("reasons = %v, want %q", art.Trust.Reasons, tt.reason)
			}
		})
	}
}
