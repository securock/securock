package trust_test

import (
	"testing"

	"github.com/securock/securock/internal/trust"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func healthArtifact(eco, name string, health *lockfile.HealthEvidence) lockfile.Artifact {
	return lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: eco, Name: name},
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
			Health:          health,
		},
	}
}

func withHealthRule(rule policy.HealthRule) policy.Document {
	pol := policy.Default()
	pol.Rules.Health = rule
	return pol
}

func TestHealthRulesAreOffByDefault(t *testing.T) {
	art := healthArtifact("npm", "lodahs", &lockfile.HealthEvidence{Deprecated: "old"})
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusTrusted {
		t.Fatalf("status = %s (%v)", art.Trust.Status, art.Trust.Reasons)
	}
}

func TestDenyDeprecated(t *testing.T) {
	pol := withHealthRule(policy.HealthRule{Deprecated: "deny"})
	tests := []struct {
		name   string
		health *lockfile.HealthEvidence
		want   lockfile.Status
		reason string
	}{
		{"supported", &lockfile.HealthEvidence{License: "MIT"}, lockfile.StatusTrusted, ""},
		{"deprecated", &lockfile.HealthEvidence{Deprecated: "use x"}, lockfile.StatusUntrusted, "deprecated release"},
		{"not checked", nil, lockfile.StatusUnknown, "health not checked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			art := healthArtifact("npm", "thing", tt.health)
			trust.Evaluate(&art, pol)
			if art.Trust.Status != tt.want {
				t.Fatalf("status = %s (%v), want %s", art.Trust.Status, art.Trust.Reasons, tt.want)
			}
			if tt.reason != "" && (len(art.Trust.Reasons) != 1 || art.Trust.Reasons[0] != tt.reason) {
				t.Fatalf("reasons = %v, want [%s]", art.Trust.Reasons, tt.reason)
			}
		})
	}
}

func TestDenyTyposquat(t *testing.T) {
	pol := withHealthRule(policy.HealthRule{Typosquat: "deny"})

	art := healthArtifact("npm", "lodahs", nil)
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted || art.Trust.Reasons[0] != "possible typosquat of lodash" {
		t.Fatalf("status = %s, reasons = %v", art.Trust.Status, art.Trust.Reasons)
	}

	for _, ok := range []lockfile.Artifact{
		healthArtifact("npm", "lodash", nil),
		healthArtifact("cargo", "lodahs", nil),
		healthArtifact("npm", "my-app-utils", nil),
	} {
		trust.Evaluate(&ok, pol)
		if ok.Trust.Status != lockfile.StatusTrusted {
			t.Fatalf("%s: status = %s (%v)", ok.Subject.Name, ok.Trust.Status, ok.Trust.Reasons)
		}
	}
}

func TestTyposquatAllowListExemptsKnownGoodNames(t *testing.T) {
	pol := withHealthRule(policy.HealthRule{Typosquat: "deny", TyposquatAllow: []string{"lodahs"}})

	allowed := healthArtifact("npm", "lodahs", nil)
	trust.Evaluate(&allowed, pol)
	if allowed.Trust.Status != lockfile.StatusTrusted {
		t.Fatalf("an allowed name must pass: %s %v", allowed.Trust.Status, allowed.Trust.Reasons)
	}
	other := healthArtifact("npm", "lodsah", nil)
	trust.Evaluate(&other, pol)
	if other.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("the allow list is per name: %s %v", other.Trust.Status, other.Trust.Reasons)
	}
}
