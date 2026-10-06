package lockfile_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/pkg/lockfile"
)

func TestValidateOutdatedVersion(t *testing.T) {
	err := lockfile.Validate(lockfile.Document{Version: 1})
	if err == nil {
		t.Fatal("expected outdated version error")
	}
	if !strings.Contains(err.Error(), "outdated") || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnsupportedFutureVersion(t *testing.T) {
	err := lockfile.Validate(lockfile.Document{Version: 99})
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDigestFormat(t *testing.T) {
	base := lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: "npm", Name: "x"},
		Version: "1.0.0",
		Evidence: lockfile.Evidence{
			Provenance:      lockfile.EvidenceUnknown,
			Signature:       lockfile.EvidenceUnknown,
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnUnknown},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnUnknown},
			Capabilities:    lockfile.CapabilityEvidence{State: lockfile.CapUnknown},
			Behavior:        lockfile.BehaviorEvidence{State: lockfile.CapUnknown},
			Ownership:       lockfile.OwnershipEvidence{State: lockfile.CapUnknown},
			Chain:           lockfile.ChainEvidence{State: lockfile.EvidenceUnknown},
		},
		Trust: lockfile.Trust{Status: lockfile.StatusUnknown},
	}

	ok := base
	ok.Digest = "sha256:" + strings.Repeat("ab", 32)
	if err := lockfile.Validate(lockfile.Document{Version: 2, Artifacts: []lockfile.Artifact{ok}}); err != nil {
		t.Fatal(err)
	}

	bad := base
	bad.Digest = "sha256:abcd"
	if err := lockfile.Validate(lockfile.Document{Version: 2, Artifacts: []lockfile.Artifact{bad}}); err == nil {
		t.Fatal("short sha256 must fail validation")
	}

	badGoh1 := base
	badGoh1.Digest = "goh1:not-valid!!!"
	if err := lockfile.Validate(lockfile.Document{Version: 2, Artifacts: []lockfile.Artifact{badGoh1}}); err == nil {
		t.Fatal("malformed goh1 must fail validation")
	}
}
