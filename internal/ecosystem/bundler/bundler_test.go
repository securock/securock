package bundler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/bundler"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestDependencies(t *testing.T) {
	eco := bundler.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected Gemfile.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "rubygems" || dep.Resolver != "bundler" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	rack := got["rack"]
	if rack.Version != "3.0.8" {
		t.Fatalf("rack = %+v", rack)
	}
	if rack.SourceKind != core.SourceRegistry || rack.Registry != "https://rubygems.org" {
		t.Fatalf("rack source = %+v", rack)
	}
	if rack.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("rack digest = %q", rack.Digest)
	}
	if got["local-pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local-pkg kind = %q", got["local-pkg"].SourceKind)
	}
	if _, ok := got["rack-session"]; !ok {
		t.Fatalf("missing rack-session: %#v", got)
	}
}

func TestGitSource(t *testing.T) {
	dir := t.TempDir()
	raw := `GIT
  remote: https://github.com/example/foo.git
  revision: 0123456789abcdef0123456789abcdef01234567
  specs:
    foo (1.0.0)

BUNDLED WITH
   2.5.11
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := bundler.New().Dependencies(dir)
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
