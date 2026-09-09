package bundler_test

import (
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
