package cabal_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cabal"
	"github.com/securock/securock/internal/ecosystem/core"
)

func load(t *testing.T, files map[string]string) []core.Dependency {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	deps, err := cabal.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func TestDependencies(t *testing.T) {
	eco := cabal.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected cabal.project.freeze to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, dep := range deps {
		got = append(got, dep.Name+"@"+dep.Version)
		if dep.Ecosystem != "hackage" || dep.Resolver != "cabal" || dep.SourceKind != core.SourceRegistry {
			t.Fatalf("%+v", dep)
		}
		if dep.Registry != "https://hackage.haskell.org" {
			t.Fatalf("%s registry = %q", dep.Name, dep.Registry)
		}
		if dep.Digest != "" || dep.Scope != "" || len(dep.DependsOn) != 0 {
			t.Fatalf("%s records data the freeze file does not hold: %+v", dep.Name, dep)
		}
	}
	// base is installed (no version), text is a range, setup.Cabal is qualified, aeson is repeated.
	want := []string{"Cabal@3.10.1.0", "aeson@2.2.1.0", "containers@0.6.7", "zlib@0.6.3.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deps = %v, want %v", got, want)
	}
}

func TestRegistryMustBeProven(t *testing.T) {
	const constraints = "constraints: any.aeson ==2.2.1.0\n"
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"hackage only", map[string]string{"cabal.project.freeze": "active-repositories: hackage.haskell.org:merge\n" + constraints}, "https://hackage.haskell.org"},
		{"missing line", map[string]string{"cabal.project.freeze": constraints}, ""},
		{"other repository", map[string]string{"cabal.project.freeze": "active-repositories: hackage.haskell.org:merge, corp:rest\n" + constraints}, ""},
		{"custom stanza", map[string]string{
			"cabal.project.freeze": "active-repositories: hackage.haskell.org:merge\n" + constraints,
			"cabal.project":        "packages: .\n\nrepository hackage.haskell.org\n  url: https://mirror.example/\n",
		}, ""},
		{"plain project file", map[string]string{
			"cabal.project.freeze": "active-repositories: hackage.haskell.org:merge\n" + constraints,
			"cabal.project":        "packages: .\n",
		}, "https://hackage.haskell.org"},
	}
	for _, tt := range tests {
		deps := load(t, tt.files)
		if len(deps) != 1 || deps[0].Registry != tt.want {
			t.Errorf("%s: deps = %+v, want registry %q", tt.name, deps, tt.want)
		}
	}
}

func TestEmptyAndGarbage(t *testing.T) {
	for _, body := range []string{"", "not a freeze file", "constraints:\n"} {
		if deps := load(t, map[string]string{"cabal.project.freeze": body}); len(deps) != 0 {
			t.Errorf("%q: deps = %+v", body, deps)
		}
	}
	if _, err := cabal.New().Dependencies(t.TempDir()); err == nil {
		t.Fatal("expected an error for a missing freeze file")
	}
}
