package pipenv_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pipenv"
)

func TestDependencies(t *testing.T) {
	eco := pipenv.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected Pipfile.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		if _, dup := got[dep.Name]; dup {
			t.Fatalf("%s listed twice", dep.Name)
		}
		got[dep.Name] = dep
		if dep.Ecosystem != "pypi" || dep.Resolver != "pipenv" {
			t.Fatalf("%s ecosystem/resolver = %s/%s", dep.Name, dep.Ecosystem, dep.Resolver)
		}
	}
	if _, ok := got["unpinned"]; ok {
		t.Fatal("an unpinned entry has no artifact and must be skipped")
	}

	const sha3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	tests := []struct {
		name     string
		version  string
		scope    string
		kind     string
		registry string
		digest   string
		artifact string
		resolved string
	}{
		// In both sections: runtime wins. Two hashes cannot be tied to one file: no digest.
		{"requests", "2.31.0", core.ScopeRuntime, core.SourceRegistry, "https://pypi.org", "", "", ""},
		{"Single_Hash", "1.0.0", core.ScopeRuntime, core.SourceRegistry, "https://pypi.org", sha3, "", ""},
		{"corp-lib", "0.5.0", core.ScopeRuntime, core.SourceRegistry, "https://pypi.internal.example", "sha256:4444444444444444444444444444444444444444444444444444444444444444", "", ""},
		// Two sources and no index: not resolvable, so no registry.
		{"noindex", "3.0.0", core.ScopeRuntime, core.SourceRegistry, "", "sha256:5555555555555555555555555555555555555555555555555555555555555555", "", ""},
		{"gitpkg", "0123456789abcdef0123456789abcdef01234567", core.ScopeRuntime, core.SourceGit, "", "", "https://github.com/acme/gitpkg.git", "0123456789abcdef0123456789abcdef01234567"},
		{"localpkg", "path", core.ScopeRuntime, core.SourceFile, "", "", "", ""},
		{"pytest", "8.0.0", core.ScopeDev, core.SourceRegistry, "https://pypi.org", "sha256:6666666666666666666666666666666666666666666666666666666666666666", "", ""},
	}
	for _, tt := range tests {
		dep, ok := got[tt.name]
		if !ok {
			t.Errorf("%s missing", tt.name)
			continue
		}
		if dep.Version != tt.version || dep.Scope != tt.scope || dep.SourceKind != tt.kind ||
			dep.Registry != tt.registry || dep.Digest != tt.digest || dep.Artifact != tt.artifact || dep.Resolved != tt.resolved {
			t.Errorf("%s = %+v", tt.name, dep)
		}
	}
}

func TestSoleSourceIsDefault(t *testing.T) {
	dir := t.TempDir()
	body := `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple"}]},"default":{"a":{"version":"==1.0"}},"develop":{}}`
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pipenv.New().Dependencies(dir)
	if err != nil || len(deps) != 1 {
		t.Fatalf("deps = %v, err = %v", deps, err)
	}
	if deps[0].Registry != "https://pypi.org" {
		t.Fatalf("registry = %q", deps[0].Registry)
	}
}

func TestMalformed(t *testing.T) {
	dir := t.TempDir()
	if _, err := pipenv.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for a missing lockfile")
	}
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pipenv.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}
