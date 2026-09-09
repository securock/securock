package yarn_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/yarn"
)

func TestClassicDependencies(t *testing.T) {
	eco := yarn.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected yarn.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep
	}
	react := got["react@19.2.0"]
	if react.Ecosystem != "npm" || react.Resolver != "yarn" {
		t.Fatalf("react identity = %s/%s", react.Ecosystem, react.Resolver)
	}
	if react.SourceKind != core.SourceRegistry {
		t.Fatalf("react kind = %q", react.SourceKind)
	}
	if react.Registry != "https://registry.npmjs.org" {
		t.Fatalf("react registry = %q", react.Registry)
	}
	if react.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("react digest = %q", react.Digest)
	}
	if got["@scope/pkg@1.2.3"].Name != "@scope/pkg" {
		t.Fatalf("missing scoped package: %#v", got)
	}
}

func TestBerryVirtualPackages(t *testing.T) {
	deps, err := yarn.New().Dependencies("testdata/berry")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep
	}
	if len(got) != 2 {
		t.Fatalf("got %d deps, want 2 (virtual react collapsed): %#v", len(got), got)
	}
	react := got["react@19.2.0"]
	if react.Resolver != "yarn" || react.Ecosystem != "npm" {
		t.Fatalf("react identity = %s/%s", react.Ecosystem, react.Resolver)
	}
	if react.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("react digest = %q", react.Digest)
	}
	local := got["local-pkg@0.0.1"]
	if local.SourceKind != core.SourceWorkspace {
		t.Fatalf("local-pkg kind = %q", local.SourceKind)
	}
}
