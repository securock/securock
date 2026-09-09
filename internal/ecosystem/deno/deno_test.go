package deno_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/deno"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")
}

func TestDependencies(t *testing.T) {
	isolate(t)
	eco := deno.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected deno.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Ecosystem+":"+dep.Name] = dep
	}
	react := got["npm:react"]
	if react.Ecosystem != "npm" || react.Resolver != "deno" || react.Version != "19.2.0" {
		t.Fatalf("npm react = %+v", react)
	}
	if react.SourceKind != core.SourceRegistry {
		t.Fatalf("react kind = %q", react.SourceKind)
	}
	if react.Registry != "https://registry.npmjs.org" {
		t.Fatalf("react registry = %q", react.Registry)
	}
	std := got["jsr:@std/assert"]
	if std.Version != "1.0.6" || std.Registry != "https://jsr.io" {
		t.Fatalf("jsr = %+v", std)
	}
	remote := got["url:https://example.com/mod.ts"]
	if remote.SourceKind != core.SourceURL || remote.Version == "" {
		t.Fatalf("url = %+v", remote)
	}
	if remote.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("url digest = %q", remote.Digest)
	}
}

func TestV3Packages(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `{
  "version": "3",
  "packages": {
    "npm": {
      "chalk@5.3.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "chalk" || deps[0].Version != "5.3.0" {
		t.Fatalf("v3 npm = %#v", deps)
	}
}

func TestDependenciesUnprovenRegistry(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "deno.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range deps {
		if dep.Ecosystem != "npm" {
			continue
		}
		if dep.Registry != "" {
			t.Fatalf("%s registry = %q, want empty", dep.Name, dep.Registry)
		}
	}
}
