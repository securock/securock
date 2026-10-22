package license

import (
	"reflect"
	"testing"
)

func TestParseAndString(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"MIT", "MIT", true},
		{"mit or apache-2.0", "MIT OR Apache-2.0", true},
		{"MIT OR (Apache-2.0 AND BSD-3-Clause)", "MIT OR (Apache-2.0 AND BSD-3-Clause)", true},
		{"(MIT)", "MIT", true},
		{"GPL-2.0 WITH Classpath-exception-2.0", "GPL-2.0-only", true},
		{"GPL-3.0+", "GPL-3.0-or-later", true},
		{"MIT AND Apache-2.0 AND ISC", "MIT AND Apache-2.0 AND ISC", true},
		{"(MIT OR ISC) AND Zlib", "(MIT OR ISC) AND Zlib", true},
		{"", "", false},
		{"MIT OR", "", false},
		{"AND MIT", "", false},
		{"(MIT", "", false},
		{"MIT)", "", false},
		{"MIT Apache-2.0", "", false},
		{"GPL-2.0 WITH", "", false},
	}
	for _, tt := range tests {
		n, ok := parse(tt.in)
		if ok != tt.ok || (ok && n.String() != tt.want) {
			t.Errorf("parse(%q) = %q, %v; want %q, %v", tt.in, n.String(), ok, tt.want, tt.ok)
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"mit": "MIT", "MIT License": "MIT", "Apache Software License": "Apache-2.0",
		"GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later", "gpl-3.0-or-later": "GPL-3.0-or-later",
		"GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
		// Names that do not pick out one license, and unknown text, are left alone.
		"BSD License": "BSD License", "  Proprietary  ": "Proprietary", "": "",
	}
	for in, want := range tests {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NormalizeExpression("mit or gpl-3.0"); got != "MIT OR GPL-3.0-only" {
		t.Errorf("NormalizeExpression = %q", got)
	}
	if got := NormalizeExpression("Some Custom License"); got != "Some Custom License" {
		t.Errorf("NormalizeExpression of prose = %q", got)
	}
}

func TestIsSPDX(t *testing.T) {
	for in, want := range map[string]bool{
		"MIT": true, "MIT OR Apache-2.0": true, "GPL-2.0-only WITH Classpath-exception-2.0": true,
		"MIT License": false, "MIT OR Custom-1.0": false, "": false, "BSD License": false,
	} {
		if got := IsSPDX(in); got != want {
			t.Errorf("IsSPDX(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name        string
		declared    string
		allow, deny []string
		want        Verdict
		hit         []string
	}{
		{"no rules", "GPL-3.0", nil, nil, Allowed, nil},
		{"denied", "GPL-3.0", nil, []string{"GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"denied by glob", "AGPL-3.0-or-later", nil, []string{"AGPL-*", "GPL-*"}, Denied, []string{"AGPL-3.0-or-later"}},
		{"glob matches the deprecated spelling", "GPL-2.0", nil, []string{"GPL-*"}, Denied, []string{"GPL-2.0-only"}},
		{"OR offers a way out", "MIT OR GPL-3.0-only", nil, []string{"GPL-*"}, Allowed, nil},
		{"AND leaves no way out", "MIT AND GPL-3.0-only", nil, []string{"GPL-*"}, Denied, []string{"GPL-3.0-only"}},
		{"nested", "(MIT OR GPL-3.0-only) AND Apache-2.0", nil, []string{"GPL-*"}, Allowed, nil},
		{"allow list passes", "MIT", []string{"MIT", "Apache-2.0"}, nil, Allowed, nil},
		{"allow list is case insensitive", "mit", []string{"MIT"}, nil, Allowed, nil},
		{"allow list rejects", "ISC", []string{"MIT", "Apache-2.0"}, nil, NotAllowed, []string{"ISC"}},
		{"OR passes if one side is allowed", "ISC OR MIT", []string{"MIT"}, nil, Allowed, nil},
		{"AND needs both allowed", "MIT AND ISC", []string{"MIT"}, nil, NotAllowed, []string{"MIT", "ISC"}},
		{"allow wildcard", "Apache-2.0", []string{"Apache-*"}, nil, Allowed, nil},
		{"deny wins over allow", "GPL-3.0-only", []string{"GPL-*"}, []string{"GPL-3.0-only"}, Denied, []string{"GPL-3.0-only"}},
		{"prose matches only exactly", "Custom Terms", []string{"Custom Terms"}, nil, Allowed, nil},
		{"prose is not allowed by default", "Custom Terms", []string{"MIT"}, nil, NotAllowed, []string{"Custom Terms"}},
		{"registry name is normalized", "MIT License", []string{"MIT"}, nil, Allowed, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, hit := Check(tt.declared, tt.allow, tt.deny)
			if got != tt.want || !reflect.DeepEqual(hit, tt.hit) {
				t.Fatalf("Check(%q) = %v %v, want %v %v", tt.declared, got, hit, tt.want, tt.hit)
			}
		})
	}
}

func TestKnownListIsCanonical(t *testing.T) {
	for lower, id := range known {
		if lower != toLower(id) {
			t.Errorf("%q is filed under %q", id, lower)
		}
	}
	for _, id := range deprecated {
		if !Known(id) {
			t.Errorf("deprecated spelling maps to unknown id %q", id)
		}
	}
	for name, id := range aliases {
		if !Known(id) {
			t.Errorf("alias %q maps to unknown id %q", name, id)
		}
	}
}

func toLower(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}
