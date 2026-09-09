package gradle_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/gradle"
)

func TestDependencies(t *testing.T) {
	eco := gradle.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected gradle.lockfile to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "maven" || dep.Resolver != "gradle" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
		if dep.SourceKind != core.SourceRegistry {
			t.Fatalf("%s kind = %q", dep.Name, dep.SourceKind)
		}
		if dep.Registry != "" {
			t.Fatalf("%s registry = %q, want empty", dep.Name, dep.Registry)
		}
	}
	lang := got["org.apache.commons:commons-lang3"]
	if lang.Version != "3.14.0" {
		t.Fatalf("commons-lang3 = %+v", lang)
	}
	if got["com.google.guava:guava"].Version != "33.0.0-jre" {
		t.Fatalf("guava = %+v", got["com.google.guava:guava"])
	}
	if _, ok := got["empty"]; ok {
		t.Fatal("empty sentinel must be skipped")
	}
}
