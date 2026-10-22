package lockfile_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/pkg/lockfile"
)

func healthDoc(h *lockfile.HealthEvidence) lockfile.Document {
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
				Health:          h,
			},
			Trust: lockfile.Trust{Status: lockfile.StatusUnknown},
		}},
	}
}

func TestValidateHealth(t *testing.T) {
	tests := []struct {
		name    string
		health  *lockfile.HealthEvidence
		wantErr string
	}{
		{"absent", nil, ""},
		{"empty", &lockfile.HealthEvidence{}, ""},
		{"full", &lockfile.HealthEvidence{Released: "2025-01-31", Deprecated: "use x", License: "MIT"}, ""},
		{"bad date", &lockfile.HealthEvidence{Released: "31/01/2025"}, "YYYY-MM-DD"},
		{"timestamp", &lockfile.HealthEvidence{Released: "2025-01-31T00:00:00Z"}, "YYYY-MM-DD"},
		{"huge message", &lockfile.HealthEvidence{Deprecated: strings.Repeat("x", lockfile.MaxHealthText+1)}, "longer than"},
		{"huge license", &lockfile.HealthEvidence{License: strings.Repeat("x", lockfile.MaxHealthText+1)}, "longer than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lockfile.Validate(healthDoc(tt.health))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}
