package cargo_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/cargo"
)

func TestDependencies(t *testing.T) {
	eco := cargo.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected cargo lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1: %#v", len(deps), deps)
	}
	if deps[0].Name != "serde" || deps[0].Version != "1.0.210" {
		t.Fatalf("unexpected dependency: %#v", deps[0])
	}
	if deps[0].Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("digest = %q", deps[0].Digest)
	}
}
