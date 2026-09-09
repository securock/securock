package pnpm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pnpm"
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
	eco := pnpm.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected pnpm lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep.Digest
	}

	if got["react@19.2.0"] == "" || got["@scope/pkg@1.2.3"] == "" || got["lodash@4.17.21"] == "" {
		t.Fatalf("missing packages: %#v", got)
	}
	if len(got) != 3 {
		t.Fatalf("got %d deps, want 3: %#v", len(got), got)
	}
	for _, dep := range deps {
		if dep.Ecosystem != "npm" || dep.Resolver != "pnpm" {
			t.Fatalf("ecosystem/resolver = %s/%s, want npm/pnpm", dep.Ecosystem, dep.Resolver)
		}
		if dep.SourceKind != core.SourceRegistry {
			t.Fatalf("%s source = %q", dep.Name, dep.SourceKind)
		}
		if dep.Registry != "https://registry.npmjs.org" {
			t.Fatalf("%s registry = %q", dep.Name, dep.Registry)
		}
	}
}

func TestDependenciesUnprovenRegistry(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	deps, err := pnpm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deps", len(deps))
	}
	for _, dep := range deps {
		if dep.SourceKind != core.SourceRegistry {
			t.Fatalf("%s source = %q", dep.Name, dep.SourceKind)
		}
		if dep.Registry != "" {
			t.Fatalf("%s registry = %q, want empty", dep.Name, dep.Registry)
		}
	}
}
