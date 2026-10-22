package policy_test

import (
	"testing"

	"github.com/securock/securock/pkg/policy"
)

func TestHealthRuleValidation(t *testing.T) {
	tests := []struct {
		rule    policy.HealthRule
		wantErr bool
	}{
		{policy.HealthRule{}, false},
		{policy.HealthRule{Deprecated: "deny", Typosquat: "deny"}, false},
		{policy.HealthRule{Deprecated: "allow"}, false},
		{policy.HealthRule{Deprecated: "warn"}, true},
		{policy.HealthRule{Typosquat: "block"}, true},
	}
	for _, tt := range tests {
		doc := policy.Default()
		doc.Rules.Health = tt.rule
		if err := policy.Validate(doc); (err != nil) != tt.wantErr {
			t.Errorf("%+v: err = %v, wantErr %v", tt.rule, err, tt.wantErr)
		}
	}
}

func TestFingerprintHealthRule(t *testing.T) {
	base, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}

	empty := policy.Default()
	empty.Rules.Health = policy.HealthRule{}
	if got, _ := policy.Fingerprint(empty); got != base {
		t.Fatal("an unset health rule must not change the fingerprint")
	}

	seen := map[string]string{"none": base}
	for name, rule := range map[string]policy.HealthRule{
		"deprecated": {Deprecated: "deny"},
		"typosquat":  {Typosquat: "deny"},
		"both":       {Deprecated: "deny", Typosquat: "deny"},
	} {
		doc := policy.Default()
		doc.Rules.Health = rule
		got, err := policy.Fingerprint(doc)
		if err != nil {
			t.Fatal(err)
		}
		for other, fp := range seen {
			if fp == got {
				t.Fatalf("%s and %s share a fingerprint", name, other)
			}
		}
		seen[name] = got
	}
}
