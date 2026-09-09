package pnpm_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/pnpm"
)

func TestDependencies(t *testing.T) {
	eco := pnpm.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected pnpm lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep.Digest
	}

	if got["react@19.2.0"] == "" || got["@scope/pkg@1.2.3"] == "" || got["lodash@4.17.21"] == "" {
		t.Fatalf("missing packages: %#v", got)
	}
	if len(got) != 3 {
		t.Fatalf("got %d deps, want 3: %#v", len(got), got)
	}
	for _, dep := range deps {
		if dep.Ecosystem != "npm" || dep.Resolver != "pnpm" {
			t.Fatalf("ecosystem/resolver = %s/%s, want npm/pnpm", dep.Ecosystem, dep.Resolver)
		}
		if dep.Registry != "https://registry.npmjs.org" {
			t.Fatalf("%s registry = %q", dep.Name, dep.Registry)
		}
	}
}
