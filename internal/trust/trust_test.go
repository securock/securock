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
			Vulnerabilities: []lockfile.Vulnerability{{ID: "GHSA-test"}},
		},
	}
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}

func TestEvaluateRequireDigest(t *testing.T) {
	art := lockfile.Artifact{}
	pol := policy.Default()
	pol.Rules.RequireDigest = true
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}
