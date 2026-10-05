package policy_test

import (
	"testing"

	"github.com/securock/securock/pkg/policy"
)

const defaultFingerprint = "sha256:a7b760ed4719640b3b9c63f1441e3fda7a2d511fec8f731edbd4ac280367e5c1"

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
			RequireNoMalicious:       true,
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
			RequireNoMalicious:       true,
			Provenance:               policy.EvidenceRule{},
			Signature:                policy.EvidenceRule{},
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
			RequireNoMalicious:       true,
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

func TestFingerprintCapabilities(t *testing.T) {
	base, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Fingerprint(policy.Document{
		Version: 1,
		Network: policy.Network{Mode: policy.ModePublicOnly},
		Rules: policy.Rules{
			RequireNoVulnerabilities: true,
			RequireNoMalicious:       true,
			Capabilities: policy.CapabilityRule{
				Deny: []string{"shell", "native_code"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == base {
		t.Fatal("capability deny must change fingerprint")
	}
}

func TestValidateCapabilityAndOwnership(t *testing.T) {
	doc := policy.Document{
		Version: 1,
		Rules: policy.Rules{
			Capabilities: policy.CapabilityRule{
				Deny:       []string{"shell"},
				Filesystem: policy.FilesystemRule{Maximum: "read"},
			},
			Ownership: policy.OwnershipRule{
				PublisherChange:   policy.ActionDeny,
				MaintainerAdded:   policy.ActionWarn,
				MaintainerRemoved: policy.ActionReview,
			},
		},
	}
	if err := policy.Validate(doc); err != nil {
		t.Fatal(err)
	}
	doc.Rules.Capabilities.Deny = []string{"laser"}
	if err := policy.Validate(doc); err == nil {
		t.Fatal("unknown capability must fail")
	}
}
