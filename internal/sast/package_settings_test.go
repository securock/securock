package sast_test

import (
	"slices"
	"testing"
)

func TestGoPackageLevelSecuritySettings(t *testing.T) {
	for _, tc := range []struct {
		name, src, rule string
		want            bool
	}{
		{"tls config", "import \"crypto/tls\"\nvar config = tls.Config{InsecureSkipVerify: true}", "sast:go/tls-verification-disabled", true},
		{"safe tls config", "import \"crypto/tls\"\nvar config = tls.Config{InsecureSkipVerify: false}", "sast:go/tls-verification-disabled", false},
		{"initializer closure", "import \"crypto/tls\"\nvar config = func() tls.Config { return tls.Config{InsecureSkipVerify: true} }()", "sast:go/tls-verification-disabled", true},
		{"weak TLS minimum", "import \"crypto/tls\"\nvar config = tls.Config{MinVersion: tls.VersionTLS10}", "sast:go/tls-verification-disabled", true},
		{"secure minimum", "import \"crypto/tls\"\nvar config = tls.Config{MinVersion: tls.VersionTLS12}", "sast:go/tls-verification-disabled", false},
		{"string decoy", "var note = `tls.Config{InsecureSkipVerify: true}`", "sast:go/tls-verification-disabled", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"main.go": "package fixture\n" + tc.src + "\n"})
			if slices.Contains(got, tc.rule) != tc.want {
				t.Fatalf("got %v want %s=%v", got, tc.rule, tc.want)
			}
		})
	}
}
