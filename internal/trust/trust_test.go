package trust_test

import (
	"strings"
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
			Malicious: lockfile.MaliciousEvidence{
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
			Malicious: lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
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
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnUnknown},
		},
	}
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusUnknown {
		t.Fatalf("status = %s, want unknown", art.Trust.Status)
	}
}

func TestEvaluateMaliciousPackage(t *testing.T) {
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious: lockfile.MaliciousEvidence{
				State:   lockfile.VulnChecked,
				Reports: []lockfile.MaliciousReport{{ID: "MAL-2026-2307"}},
			},
		},
	}
	trust.Evaluate(&art, policy.Default())
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
	if !strings.Contains(strings.Join(art.Trust.Reasons, ","), "malicious package") {
		t.Fatalf("reasons = %v", art.Trust.Reasons)
	}
}

func TestEvaluateRequireVerifiedProvenance(t *testing.T) {
	pol := policy.Default()
	pol.Rules.Provenance.Minimum = "verified"

	present := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Provenance: lockfile.EvidencePresent,
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
			},
			Malicious: lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
		},
	}
	trust.Evaluate(&present, pol)
	if present.Trust.Status != lockfile.StatusUntrusted {
		t.Fatal("present provenance must fail minimum verified")
	}

	verified := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Provenance: lockfile.EvidenceVerified,
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
			},
			Malicious: lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
		},
	}
	trust.Evaluate(&verified, pol)
	if verified.Trust.Status != lockfile.StatusTrusted {
		t.Fatalf("verified provenance should pass: %s", verified.Trust.Status)
	}
}

func TestEvaluateRequireDigest(t *testing.T) {
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
		},
	}
	pol := policy.Default()
	pol.Rules.RequireDigest = true
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}

func TestEvaluateDeniedCapability(t *testing.T) {
	pol := policy.Default()
	pol.Rules.Capabilities.Deny = []string{"shell", "install_scripts"}

	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
			Capabilities: lockfile.CapabilityEvidence{
				State:          lockfile.CapChecked,
				Shell:          lockfile.Bool(true),
				InstallScripts: lockfile.Bool(true),
				Network:        lockfile.Bool(false),
			},
		},
	}
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
	joined := strings.Join(art.Trust.Reasons, ",")
	if !strings.Contains(joined, "denied capability: shell") || !strings.Contains(joined, "denied capability: install_scripts") {
		t.Fatalf("reasons = %v", art.Trust.Reasons)
	}
}

func TestEvaluateFilesystemMaximum(t *testing.T) {
	pol := policy.Default()
	pol.Rules.Capabilities.Filesystem.Maximum = "read"

	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
			Capabilities: lockfile.CapabilityEvidence{
				State:      lockfile.CapChecked,
				Filesystem: lockfile.FilesystemWrite,
			},
		},
	}
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}

func TestEvaluateCapabilitiesUnknown(t *testing.T) {
	pol := policy.Default()
	pol.Rules.Capabilities.Deny = []string{"shell"}
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
			Capabilities:    lockfile.CapabilityEvidence{State: lockfile.CapUnknown},
		},
	}
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUnknown {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}

func TestEvaluateVulnerabilitiesAllowNone(t *testing.T) {
	pol := policy.Document{
		Version: 1,
		Rules: policy.Rules{
			Vulnerabilities: policy.VulnerabilityRule{Allow: "none"},
		},
	}
	art := lockfile.Artifact{
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
				Items: []lockfile.Vulnerability{{ID: "GHSA-x"}},
			},
			Malicious: lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
		},
	}
	trust.Evaluate(&art, pol)
	if art.Trust.Status != lockfile.StatusUntrusted {
		t.Fatalf("status = %s", art.Trust.Status)
	}
}
