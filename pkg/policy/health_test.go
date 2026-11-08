package policy_test

import (
	"testing"
	"time"

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
		{policy.HealthRule{Typosquat: "deny", TyposquatAllow: []string{"lodahs"}}, false},
		{policy.HealthRule{TyposquatAllow: []string{" "}}, true},
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

func TestLicenseRuleValidation(t *testing.T) {
	tests := []struct {
		rule    policy.LicenseRule
		wantErr bool
	}{
		{policy.LicenseRule{}, false},
		{policy.LicenseRule{Allow: []string{"MIT", "Apache-2.0"}, Deny: []string{"GPL-*", "AGPL-3.0-only"}}, false},
		{policy.LicenseRule{Allow: []string{""}}, true},
		{policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "allow"}, false},
		{policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "unknown"}, false},
		{policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "deny"}, true},
		{policy.LicenseRule{Deny: []string{"MIT OR ISC"}}, true},
		{policy.LicenseRule{Deny: []string{"(MIT)"}}, true},
		{policy.LicenseRule{Deny: []string{"G*L"}}, true},
		{policy.LicenseRule{Deny: []string{"*GPL"}}, true},
	}
	for _, tt := range tests {
		doc := policy.Default()
		doc.Rules.Licenses = tt.rule
		if err := policy.Validate(doc); (err != nil) != tt.wantErr {
			t.Errorf("%+v: err = %v, wantErr %v", tt.rule, err, tt.wantErr)
		}
	}
}

func TestFingerprintLicenseRule(t *testing.T) {
	base, _ := policy.Fingerprint(policy.Default())
	fp := func(rule policy.LicenseRule) string {
		doc := policy.Default()
		doc.Rules.Licenses = rule
		got, err := policy.Fingerprint(doc)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if fp(policy.LicenseRule{}) != base {
		t.Fatal("an unset license rule must not change the fingerprint")
	}
	if fp(policy.LicenseRule{Deny: []string{"GPL-*"}}) == base || fp(policy.LicenseRule{Allow: []string{"MIT"}}) == base {
		t.Fatal("a license rule must change the fingerprint")
	}
	if fp(policy.LicenseRule{Deny: []string{"b", "a", "a"}}) != fp(policy.LicenseRule{Deny: []string{"a", "b"}}) {
		t.Fatal("entry order and duplicates must not matter")
	}
	if fp(policy.LicenseRule{Deny: []string{"GPL-*"}}) == fp(policy.LicenseRule{Deny: []string{"GPL-*"}, Unchecked: "allow"}) {
		t.Fatal("unchecked must change the fingerprint")
	}
	if fp(policy.LicenseRule{Allow: []string{"MIT"}}) == fp(policy.LicenseRule{Deny: []string{"MIT"}}) {
		t.Fatal("allow and deny must differ")
	}
}

func TestFingerprintTyposquatAllow(t *testing.T) {
	fp := func(allow ...string) string {
		doc := policy.Default()
		doc.Rules.Health = policy.HealthRule{Typosquat: "deny", TyposquatAllow: allow}
		got, err := policy.Fingerprint(doc)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if fp() == fp("a") || fp("a") == fp("b") {
		t.Fatal("the allow list must change the fingerprint")
	}
	if fp("b", "a", "a") != fp("a", "b") {
		t.Fatal("order and duplicates must not matter")
	}
}

func TestMinReleaseAge(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"72h", 72 * time.Hour, false},
		{"0d", 0, false},
		{"soon", 0, true},
		{"-3d", 0, true},
		{"xd", 0, true},
		{"-1h", 0, true},
	} {
		got, err := policy.ParseAge(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseAge(%q) = %v, %v; want %v, err %v", tt.in, got, err, tt.want, tt.wantErr)
		}
		doc := policy.Default()
		doc.Rules.Health.MinReleaseAge = tt.in
		if err := policy.Validate(doc); (err != nil) != tt.wantErr {
			t.Errorf("Validate(min_release_age %q): err = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
	}
}

// Trust status must not change because time passed, so the cooldown is audit-only and
// must leave the fingerprint recorded in securock.lock alone.
func TestFingerprintIgnoresMinReleaseAge(t *testing.T) {
	base, err := policy.Fingerprint(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Default()
	doc.Rules.Health.MinReleaseAge = "7d"
	got, err := policy.Fingerprint(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Fatal("min_release_age must not change the fingerprint")
	}
	if doc.Rules.Health.Configured() {
		t.Fatal("min_release_age alone must not make the health rule configured")
	}
}
