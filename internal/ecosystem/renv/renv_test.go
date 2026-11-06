package renv_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/renv"
)

func TestDependencies(t *testing.T) {
	eco := renv.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected renv.lock to be detected")
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
		if dep.Ecosystem != "cran" || dep.Resolver != "renv" {
			t.Fatalf("%s ecosystem/resolver = %s/%s", dep.Name, dep.Ecosystem, dep.Resolver)
		}
		if dep.Digest != "" {
			t.Fatalf("%s digest = %q, renv Hash is not an artifact digest", dep.Name, dep.Digest)
		}
	}
	want := []string{"BiocGenerics", "gh", "internal", "jsonlite", "mine"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v (an entry without a version is skipped)", order, want)
	}

	tests := []struct {
		name, kind, registry, artifact, resolved string
	}{
		{"jsonlite", core.SourceRegistry, "https://cloud.r-project.org", "", ""},
		// Not CRAN: no registry, so it is never sent to OSV as a CRAN package.
		{"BiocGenerics", core.SourceRegistry, "", "", ""},
		{"internal", core.SourceRegistry, "", "", ""},
		{"gh", core.SourceGit, "", "https://github.com/r-lib/gh", "0123456789abcdef0123456789abcdef01234567"},
		{"mine", core.SourceFile, "", "", ""},
	}
	for _, tt := range tests {
		dep := got[tt.name]
		if dep.SourceKind != tt.kind || dep.Registry != tt.registry || dep.Artifact != tt.artifact || dep.Resolved != tt.resolved {
			t.Errorf("%s = %+v", tt.name, dep)
		}
	}
}

func TestCRANRegistryMustBeProvenPublic(t *testing.T) {
	for name, repos := range map[string]string{
		"mirror":  `[{"Name":"CRAN","URL":"https://packagemanager.posit.co/cran/latest"}]`,
		"missing": `[]`,
		"cran":    `[{"Name":"CRAN","URL":"https://cran.r-project.org"}]`,
	} {
		dir := t.TempDir()
		body := `{"R":{"Repositories":` + repos + `},"Packages":{"a":{"Package":"a","Version":"1.0","Source":"Repository","Repository":"CRAN"}}}`
		if err := os.WriteFile(filepath.Join(dir, "renv.lock"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		deps, err := renv.New().Dependencies(dir)
		if err != nil || len(deps) != 1 {
			t.Fatalf("%s: deps = %v, err = %v", name, deps, err)
		}
		want := ""
		if name == "cran" {
			want = "https://cran.r-project.org"
		}
		if deps[0].Registry != want {
			t.Errorf("%s: registry = %q, want %q", name, deps[0].Registry, want)
		}
	}
}

func TestMalformed(t *testing.T) {
	dir := t.TempDir()
	if _, err := renv.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for a missing lockfile")
	}
	if err := os.WriteFile(filepath.Join(dir, "renv.lock"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := renv.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}
