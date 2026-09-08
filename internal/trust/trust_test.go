package trust_test

import (
	"testing"

	"github.com/securock/securock/internal/trust"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func TestEvaluateTrusted(t *testing.T) {
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Provenance: lockfile.EvidenceUnknown,
			Signature:  lockfile.EvidenceUnknown,
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
			},
		},
	}
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusTrusted {
		t.Fatalf("status = %s, reasons = %v", art.Trust.Status, art.Trust.Reasons)
	}
}

func TestEvaluateUntrustedVulns(t *testing.T) {
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
				Items: []lockfile.Vulnerability{{ID: "GHSA-test"}},
			},
		},
	}
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}

func TestEvaluateRequireProvenancePresent(t *testing.T) {
	pol := policy.Default()
	pol.Rules.RequireProvenance = true

	missing := lockfile.Artifact{
		Evidence: lockfile.Evidence{Provenance: lockfile.EvidenceUnknown},
	}
	trust.Evaluate(&missing, pol)
	if missing.Trust.Status != lockfile.StatusUntrusted {
		t.Fatal("unknown provenance must fail RequireProvenance")
	}

	present := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Provenance: lockfile.EvidencePresent,
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
			},
		},
	}
	trust.Evaluate(&present, pol)
	if present.Trust.Status != lockfile.StatusTrusted {
		t.Fatalf("present provenance should satisfy v0.1 policy: %s", present.Trust.Status)
	}
}

func TestEvaluateOfflineUnknown(t *testing.T) {
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnUnknown},
		},
	}
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusUnknown {
		t.Fatalf("status = %s, want unknown", art.Trust.Status)
	}
}

func TestEvaluateRequireDigest(t *testing.T) {
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
		},
	}
	pol := policy.Default()
	pol.Rules.RequireDigest = true
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}
