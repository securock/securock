package pub_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pub"
)

func TestDependencies(t *testing.T) {
	eco := pub.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected pubspec.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "pub" || dep.Resolver != "pub" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	httpDep := got["http"]
	if httpDep.Version != "1.2.1" {
		t.Fatalf("http = %+v", httpDep)
	}
	if httpDep.SourceKind != core.SourceRegistry || httpDep.Registry != "https://pub.dev" {
		t.Fatalf("http source = %+v", httpDep)
	}
	if httpDep.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("http digest = %q", httpDep.Digest)
	}
	if got["local_pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local_pkg kind = %q", got["local_pkg"].SourceKind)
	}
}

func TestGitSource(t *testing.T) {
	dir := t.TempDir()
	raw := `packages:
  foo:
    dependency: "direct main"
    description:
      resolved-ref: "0123456789abcdef0123456789abcdef01234567"
      url: "https://github.com/example/foo.git"
    source: git
    version: "1.0.0"
`
	if err := os.WriteFile(filepath.Join(dir, "pubspec.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pub.New().Dependencies(dir)
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
	if dep.Artifact != "https://github.com/example/foo.git" {
		t.Fatalf("artifact = %q", dep.Artifact)
	}
	if dep.Resolved != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("resolved = %q", dep.Resolved)
	}
}
