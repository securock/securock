package policy_test

import (
	"testing"

	"github.com/securock/securock/pkg/policy"
)

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
	if a == "" || a[:7] != "sha256:" {
		t.Fatalf("fingerprint = %s", a)
	}
}
