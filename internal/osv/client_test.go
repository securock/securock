package osv_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem"
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

func TestQueryEcosystemSkipsPrivateCargo(t *testing.T) {
	dep := ecosystem.Dependency{
		Ecosystem: "cargo",
		Name:      "foo",
		Version:   "1.0.0",
		Registry:  "https://cargo.internal.example/index",
	}
	if osv.Queryable(dep) {
		t.Fatal("custom cargo registry must not map to crates.io")
	}
	public := ecosystem.Dependency{
		Ecosystem: "cargo",
		Name:      "serde",
		Version:   "1.0.210",
		Registry:  "https://github.com/rust-lang/crates.io-index",
	}
	if osv.QueryEcosystem(public) != "crates.io" {
		t.Fatal("crates.io cargo must map to crates.io")
	}
}
