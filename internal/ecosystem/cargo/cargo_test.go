package cargo_test

import (
	"os"
	"path/filepath"
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
	if deps[0].Registry != "https://github.com/rust-lang/crates.io-index" {
		t.Fatalf("registry = %q", deps[0].Registry)
	}
}

func TestSparseRegistry(t *testing.T) {
	dir := t.TempDir()
	raw := `version = 3

[[package]]
name = "serde"
version = "1.0.210"
source = "sparse+https://index.crates.io/"
checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := cargo.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1: %#v", len(deps), deps)
	}
	if deps[0].Registry != "https://index.crates.io" {
		t.Fatalf("registry = %q", deps[0].Registry)
	}
}

func TestPrivateSparseRegistryIsRecorded(t *testing.T) {
	dir := t.TempDir()
	raw := `version = 3

[[package]]
name = "private-crate"
version = "1.0.0"
source = "sparse+https://crates.company.example/index/"
checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := cargo.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1: %#v", len(deps), deps)
	}
	if deps[0].Registry != "https://crates.company.example/index" {
		t.Fatalf("registry = %q", deps[0].Registry)
	}
}
