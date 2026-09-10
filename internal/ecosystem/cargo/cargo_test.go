package cargo_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cargo"
	"github.com/securock/securock/internal/ecosystem/core"
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
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
	}
	serde := got["serde"]
	if serde.Version != "1.0.210" {
		t.Fatalf("serde = %#v", serde)
	}
	if serde.SourceKind != core.SourceRegistry {
		t.Fatalf("serde kind = %q", serde.SourceKind)
	}
	if serde.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("digest = %q", serde.Digest)
	}
	if serde.Registry != "https://github.com/rust-lang/crates.io-index" {
		t.Fatalf("registry = %q", serde.Registry)
	}
	local := got["local-path"]
	if local.SourceKind != core.SourceFile || local.Artifact != "" {
		t.Fatalf("path dep must omit location: %#v", local)
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

func TestGitDependency(t *testing.T) {
	dir := t.TempDir()
	raw := `version = 3

[[package]]
name = "foo"
version = "0.1.0"
source = "git+https://github.com/example/foo?branch=main#0123456789abcdef0123456789abcdef01234567"
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
	dep := deps[0]
	if dep.SourceKind != core.SourceGit {
		t.Fatalf("kind = %q", dep.SourceKind)
	}
	if dep.Artifact != "https://github.com/example/foo" {
		t.Fatalf("artifact = %q", dep.Artifact)
	}
	if dep.Resolved != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("resolved = %q", dep.Resolved)
	}
	if dep.Registry != "" {
		t.Fatalf("git dep must not set a registry: %#v", dep)
	}
}
