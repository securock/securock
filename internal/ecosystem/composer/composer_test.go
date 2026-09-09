package composer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/composer"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestDependencies(t *testing.T) {
	eco := composer.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected composer.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "packagist" || dep.Resolver != "composer" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	log := got["psr/log"]
	if log.Version != "3.0.2" {
		t.Fatalf("psr/log = %+v", log)
	}
	if log.SourceKind != core.SourceRegistry || log.Registry != "https://repo.packagist.org" {
		t.Fatalf("psr/log registry = %+v", log)
	}
	if log.Artifact != "https://api.github.com/repos/php-fig/log/zipball/f16e1d5863e37f8d8c2a01719f5b34baa2b714d3" {
		t.Fatalf("psr/log artifact = %q", log.Artifact)
	}
	if log.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("psr/log digest = %q", log.Digest)
	}
	if got["phpunit/phpunit"].SourceKind != core.SourceGit {
		t.Fatalf("phpunit kind = %q", got["phpunit/phpunit"].SourceKind)
	}
}

func TestDistURLIsNotRegistry(t *testing.T) {
	dir := t.TempDir()
	raw := `{
  "packages": [
    {
      "name": "psr/log",
      "version": "3.0.2",
      "dist": {
        "type": "zip",
        "url": "https://api.github.com/repos/php-fig/log/zipball/abc",
        "shasum": ""
      }
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := composer.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	if deps[0].Registry != "" {
		t.Fatalf("github dist must not become registry: %+v", deps[0])
	}
	if deps[0].Artifact == "" {
		t.Fatal("missing artifact url")
	}
}
