package poetry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/poetry"
)

func TestDependencies(t *testing.T) {
	eco := poetry.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected poetry.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "pypi" || dep.Resolver != "poetry" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	req := got["requests"]
	if req.Version != "2.32.3" || req.Filename != "requests-2.32.3.tar.gz" {
		t.Fatalf("requests = %+v", req)
	}
	if req.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("requests digest = %q", req.Digest)
	}
	if req.SourceKind != core.SourceRegistry || req.Registry != "https://pypi.org" {
		t.Fatalf("requests source = %+v", req)
	}
	if got["local-pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local-pkg kind = %q", got["local-pkg"].SourceKind)
	}
}

func TestGitSource(t *testing.T) {
	dir := t.TempDir()
	raw := `[[package]]
name = "git-pkg"
version = "1.0.0"
files = []

[package.source]
type = "git"
url = "https://github.com/example/git-pkg.git"
reference = "main"
resolved_reference = "0123456789abcdef0123456789abcdef01234567"
`
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := poetry.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	dep := deps[0]
	if dep.SourceKind != core.SourceGit || dep.Registry != "" {
		t.Fatalf("git = %+v", dep)
	}
	if dep.Artifact != "https://github.com/example/git-pkg.git" {
		t.Fatalf("artifact = %q", dep.Artifact)
	}
	if dep.Resolved != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("resolved = %q", dep.Resolved)
	}
}
