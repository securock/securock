package policy_test

import (
	"testing"

	"github.com/securock/securock/pkg/policy"
)

const defaultFingerprint = "sha256:10bba8f8a88487c52d211613a3ff89ee600a779e89ca20d8a009e055374f6c4d"

func TestFingerprintDefaultGolden(t *testing.T) {
	got, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if got != defaultFingerprint {
		t.Fatalf("default fingerprint = %s, want %s", got, defaultFingerprint)
	}
}

func TestFingerprintStable(t *testing.T) {
	a, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Fingerprint(policy.Document{
		Version: 1,
		Rules: policy.Rules{
			RequireNoVulnerabilities: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("default fingerprint %s != implied public-only %s", a, b)
	}
	if a != defaultFingerprint {
		t.Fatalf("fingerprint = %s", a)
	}
}

func TestFingerprintIgnoresEmptyEvidenceRules(t *testing.T) {
	a, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Fingerprint(policy.Document{
		Version: 1,
		Network: policy.Network{Mode: policy.ModePublicOnly},
		Rules: policy.Rules{
			RequireNoVulnerabilities: true,
			Provenance:              policy.EvidenceRule{},
			Signature:               policy.EvidenceRule{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("empty evidence rules changed fingerprint: %s != %s", a, b)
	}
}

func TestFingerprintEvidenceMinimum(t *testing.T) {
	base, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Fingerprint(policy.Document{
		Version: 1,
		Network: policy.Network{Mode: policy.ModePublicOnly},
		Rules: policy.Rules{
			RequireNoVulnerabilities: true,
			Provenance:               policy.EvidenceRule{Minimum: "present"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == base {
		t.Fatal("provenance minimum must change fingerprint")
	}
}
