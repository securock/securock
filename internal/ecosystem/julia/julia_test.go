package julia_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/julia"
)

func load(t *testing.T, files map[string]string) []core.Dependency {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	deps, err := julia.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func TestDependencies(t *testing.T) {
	eco := julia.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected Manifest.toml to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		order = append(order, dep.Name)
		got[dep.Name] = dep
		if dep.Ecosystem != "julia" || dep.Resolver != "julia" {
			t.Fatalf("%s ecosystem/resolver = %s/%s", dep.Name, dep.Ecosystem, dep.Resolver)
		}
		if dep.Digest != "" || dep.Registry != "" {
			t.Fatalf("%s digest/registry = %q/%q, the manifest proves neither", dep.Name, dep.Digest, dep.Registry)
		}
	}
	// Base64 is a standard library: it ships with Julia and is skipped.
	want := []string{"Fork", "HTTP", "Local", "Test", "URIs"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}

	tests := []struct {
		name, version, kind, artifact, resolved, scope string
	}{
		{"HTTP", "1.10.8", core.SourceRegistry, "", "0123456789abcdef0123456789abcdef01234567", core.ScopeRuntime},
		// Reached from HTTP, so runtime as well, even though Test also uses it.
		{"URIs", "1.5.1", core.SourceRegistry, "", "89abcdef0123456789abcdef0123456789abcdef", core.ScopeRuntime},
		{"Fork", "0.3.0", core.SourceGit, "https://github.com/acme/Fork.jl.git", "fedcba9876543210fedcba9876543210fedcba98", core.ScopeRuntime},
		{"Local", "0.1.0", core.SourceFile, "", "", ""},
		{"Test", "2.0.0", core.SourceRegistry, "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", core.ScopeDev},
	}
	for _, tt := range tests {
		dep := got[tt.name]
		if dep.Version != tt.version || dep.SourceKind != tt.kind || dep.Artifact != tt.artifact ||
			dep.Resolved != tt.resolved || dep.Scope != tt.scope {
			t.Errorf("%s = %+v", tt.name, dep)
		}
	}
	if want := []string{"julia:URIs@1.5.1"}; !reflect.DeepEqual(got["HTTP"].DependsOn, want) {
		t.Errorf("HTTP DependsOn = %v, want %v (Base64 is not recorded)", got["HTTP"].DependsOn, want)
	}
}

func TestNoScopeWithoutProject(t *testing.T) {
	deps := load(t, map[string]string{"Manifest.toml": `manifest_format = "2.0"

[[deps.A]]
git-tree-sha1 = "0123456789abcdef0123456789abcdef01234567"
version = "1.0.0"
`})
	if len(deps) != 1 || deps[0].Scope != "" {
		t.Fatalf("deps = %+v, scope must stay unknown without Project.toml", deps)
	}
}

func TestOriginalLayoutAndDepsTable(t *testing.T) {
	deps := load(t, map[string]string{"Manifest.toml": `[[A]]
git-tree-sha1 = "0123456789abcdef0123456789abcdef01234567"
version = "1.0.0"
deps = ["B"]

[[B]]
git-tree-sha1 = "89abcdef0123456789abcdef0123456789abcdef"
version = "2.0.0"
`})
	if len(deps) != 2 || !reflect.DeepEqual(deps[0].DependsOn, []string{"julia:B@2.0.0"}) {
		t.Fatalf("deps = %+v", deps)
	}

	deps = load(t, map[string]string{"Manifest.toml": `manifest_format = "2.0"

[[deps.A]]
git-tree-sha1 = "0123456789abcdef0123456789abcdef01234567"
version = "1.0.0"
[deps.A.deps]
B = "11111111-2222-3333-4444-555555555555"

[[deps.B]]
git-tree-sha1 = "89abcdef0123456789abcdef0123456789abcdef"
version = "2.0.0"
`})
	if len(deps) != 2 || !reflect.DeepEqual(deps[0].DependsOn, []string{"julia:B@2.0.0"}) {
		t.Fatalf("deps with a uuid table = %+v", deps)
	}
}

func TestMalformed(t *testing.T) {
	dir := t.TempDir()
	if _, err := julia.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for a missing manifest")
	}
	if err := os.WriteFile(filepath.Join(dir, "Manifest.toml"), []byte("[[deps"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := julia.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for malformed TOML")
	}
}
