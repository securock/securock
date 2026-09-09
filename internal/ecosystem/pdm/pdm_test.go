package pdm_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pdm"
)

func TestDependencies(t *testing.T) {
	eco := pdm.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected pdm.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "pypi" || dep.Resolver != "pdm" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	req := got["requests"]
	if req.Version != "2.32.3" || req.Filename != "requests-2.32.3.tar.gz" {
		t.Fatalf("requests = %+v", req)
	}
	if req.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("requests digest = %q", req.Digest)
	}
	if req.SourceKind != core.SourceRegistry || req.Registry != "https://pypi.org" {
		t.Fatalf("requests source = %+v", req)
	}
	if got["local-pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local-pkg kind = %q", got["local-pkg"].SourceKind)
	}
}
