package mix_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/mix"
)

func TestDependencies(t *testing.T) {
	eco := mix.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected mix.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "hex" || dep.Resolver != "mix" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	jason := got["jason"]
	if jason.Version != "1.4.4" {
		t.Fatalf("jason = %+v", jason)
	}
	if jason.SourceKind != core.SourceRegistry || jason.Registry != "https://repo.hex.pm" {
		t.Fatalf("jason source = %+v", jason)
	}
	if jason.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("jason digest = %q", jason.Digest)
	}
	if got["local_pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local_pkg kind = %q", got["local_pkg"].SourceKind)
	}
}
