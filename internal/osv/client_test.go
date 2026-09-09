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
		"yarn":  "npm",
		"bun":   "npm",
		"deno":  "npm",
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

func TestQueryEcosystemSkipsJSRAndURL(t *testing.T) {
	jsr := ecosystem.Dependency{Ecosystem: "jsr", Name: "@std/assert", Version: "1.0.6", Registry: "https://jsr.io"}
	if osv.Queryable(jsr) {
		t.Fatal("jsr must not be sent to OSV yet")
	}
	remote := ecosystem.Dependency{Ecosystem: "url", Name: "https://example.com/mod.ts", Version: "abc"}
	if osv.Queryable(remote) {
		t.Fatal("url artifacts must not be sent to OSV")
	}
}
