package nuget_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/nuget"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
}

func TestDependencies(t *testing.T) {
	isolate(t)
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
	if dep.SourceKind != core.SourceRegistry || dep.Registry != "" {
		t.Fatalf("unproven nuget registry = %+v", dep)
	}
	if dep.Digest != "sha512:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("digest = %q", dep.Digest)
	}
}

func TestProvenanceFromNugetConfig(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `<?xml version="1.0"?><configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "nuget.config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://api.nuget.org" {
		t.Fatalf("public nuget = %#v", deps)
	}
}

func TestPrivateFeedUnknown(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `<?xml version="1.0"?><configuration><packageSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  <add key="company" value="https://nuget.company.example/v3/index.json" />
</packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "nuget.config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("mixed nuget feeds must be unknown: %#v", deps)
	}
}
