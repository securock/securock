package bun_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem/bun"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestDependencies(t *testing.T) {
	eco := bun.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected bun.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
	}
	react := got["react"]
	if react.Ecosystem != "npm" || react.Resolver != "bun" || react.Version != "19.2.0" {
		t.Fatalf("react = %+v", react)
	}
	if react.Registry != "https://registry.npmjs.org" {
		t.Fatalf("react registry = %q", react.Registry)
	}
	if react.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("react digest = %q", react.Digest)
	}
	if got["@scope/pkg"].Version != "1.2.3" {
		t.Fatalf("scoped = %+v", got["@scope/pkg"])
	}
	if got["local-pkg"].SourceKind != core.SourceWorkspace {
		t.Fatalf("local-pkg kind = %q", got["local-pkg"].SourceKind)
	}
}

func TestRejectsBinaryLockfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bun.lockb"), []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !bun.New().Detect(dir) {
		t.Fatal("bun.lockb should be detected so we can fail closed")
	}
	_, err := bun.New().Dependencies(dir)
	if err == nil || !strings.Contains(err.Error(), "bun.lockb is unsupported") {
		t.Fatalf("got %v", err)
	}
}
