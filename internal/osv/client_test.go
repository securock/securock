package osv_test

import (
	"testing"

	"github.com/securock/securock/internal/osv"
)

func TestEcosystem(t *testing.T) {
	cases := map[string]string{
		"npm":   "npm",
		"pnpm":  "npm",
		"cargo": "crates.io",
		"go":    "Go",
		"pypi":  "PyPI",
	}
	for in, want := range cases {
		if got := osv.Ecosystem(in); got != want {
			t.Errorf("%s = %q, want %q", in, got, want)
		}
	}
}
