package composer_test

import (
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
		t.Fatalf("psr/log source = %+v", log)
	}
	if log.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("psr/log digest = %q", log.Digest)
	}
	if got["phpunit/phpunit"].SourceKind != core.SourceGit {
		t.Fatalf("phpunit kind = %q", got["phpunit/phpunit"].SourceKind)
	}
}
