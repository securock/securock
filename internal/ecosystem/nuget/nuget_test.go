package nuget_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/nuget"
)

func TestDependencies(t *testing.T) {
	eco := nuget.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected packages.lock.json to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1 (project refs skipped): %#v", len(deps), deps)
	}
	dep := deps[0]
	if dep.Ecosystem != "nuget" || dep.Resolver != "nuget" {
		t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
	}
	if dep.Name != "Newtonsoft.Json" || dep.Version != "13.0.3" {
		t.Fatalf("nuget pkg = %+v", dep)
	}
	if dep.SourceKind != core.SourceRegistry || dep.Registry != "https://api.nuget.org" {
		t.Fatalf("source = %+v", dep)
	}
	if dep.Digest != "sha512:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("digest = %q", dep.Digest)
	}
}
