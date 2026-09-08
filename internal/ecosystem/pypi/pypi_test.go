package pypi_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/pypi"
)

func TestDependencies(t *testing.T) {
	eco := pypi.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected uv lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2: %#v", len(deps), deps)
	}

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep.Digest
	}
	if got["requests@2.32.3"] != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("requests digest = %q", got["requests@2.32.3"])
	}
	if got["idna@3.10"] != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("idna digest = %q", got["idna@3.10"])
	}
}
