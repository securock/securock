package swiftpm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/swiftpm"
)

func TestDependencies(t *testing.T) {
	eco := swiftpm.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected Package.resolved to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps: %#v", len(deps), deps)
	}
	dep := deps[0]
	if dep.Ecosystem != "swift" || dep.Resolver != "swiftpm" {
		t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
	}
	if dep.Name != "swift-argument-parser" || dep.Version != "1.2.3" {
		t.Fatalf("pin = %+v", dep)
	}
	if dep.SourceKind != core.SourceRegistry || dep.Registry != "https://github.com/apple/swift-argument-parser" {
		t.Fatalf("source = %+v", dep)
	}
}

func TestV1Pins(t *testing.T) {
	dir := t.TempDir()
	raw := `{
  "object": {
    "pins": [
      {
        "package": "swift-argument-parser",
        "repositoryURL": "https://github.com/apple/swift-argument-parser",
        "state": { "revision": "0fbc8848e389af3bb55c182bc19ca9d5dc2f255b", "version": "1.2.3" }
      }
    ]
  },
  "version": 1
}`
	if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := swiftpm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "swift-argument-parser" || deps[0].Version != "1.2.3" {
		t.Fatalf("v1 = %#v", deps)
	}
}
