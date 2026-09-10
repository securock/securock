package osv_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/osv"
)

func TestEcosystem(t *testing.T) {
	cases := map[string]string{
		"npm":       "npm",
		"pnpm":      "npm",
		"yarn":      "npm",
		"bun":       "npm",
		"deno":      "npm",
		"cargo":     "crates.io",
		"go":        "Go",
		"pypi":      "PyPI",
		"packagist": "Packagist",
		"rubygems":  "RubyGems",
		"nuget":     "NuGet",
		"swift":     "SwiftURL",
		"pub":       "Pub",
		"hex":       "Hex",
		"maven":     "Maven",
	}
	for in, want := range cases {
		if got := osv.Ecosystem(in); got != want {
			t.Errorf("%s = %q, want %q", in, got, want)
		}
	}
}

func TestQueryEcosystemSkipsPrivateCargo(t *testing.T) {
	dep := ecosystem.Dependency{
		Ecosystem: "cargo",
		Name:      "foo",
		Version:   "1.0.0",
		Registry:  "https://cargo.internal.example/index",
	}
	if osv.Queryable(dep) {
		t.Fatal("custom cargo registry must not map to crates.io")
	}
	public := ecosystem.Dependency{
		Ecosystem: "cargo",
		Name:      "serde",
		Version:   "1.0.210",
		Registry:  "https://github.com/rust-lang/crates.io-index",
	}
	if osv.QueryEcosystem(public) != "crates.io" {
		t.Fatal("crates.io cargo must map to crates.io")
	}
}

func TestQueryEcosystemSkipsJSRAndURL(t *testing.T) {
	jsr := ecosystem.Dependency{Ecosystem: "jsr", Name: "@std/assert", Version: "1.0.6", Registry: "https://jsr.io"}
	if osv.Queryable(jsr) {
		t.Fatal("jsr must not be sent to OSV yet")
	}
	remote := ecosystem.Dependency{Ecosystem: "url", Name: "https://example.com/mod.ts", Version: "abc"}
	if osv.Queryable(remote) {
		t.Fatal("url artifacts must not be sent to OSV")
	}
}

func TestQueryNameUsesSwiftLocation(t *testing.T) {
	dep := ecosystem.Dependency{
		Ecosystem: "swift",
		Name:      "swift-argument-parser",
		Version:   "1.2.3",
		Registry:  "https://github.com/apple/swift-argument-parser",
	}
	if osv.QueryName(dep) != "github.com/apple/swift-argument-parser" {
		t.Fatal("swift OSV queries must drop the transport scheme")
	}
	if osv.QueryEcosystem(dep) != "SwiftURL" {
		t.Fatal("swift must map to SwiftURL")
	}
}

func TestQueryNameStripsSwiftDotGit(t *testing.T) {
	dep := ecosystem.Dependency{
		Ecosystem: "swift",
		Name:      "grpc-swift",
		Version:   "1.0.0",
		Registry:  "https://github.com/grpc/grpc-swift.git",
	}
	if osv.QueryName(dep) != "github.com/grpc/grpc-swift" {
		t.Fatalf("swift OSV query name = %q", osv.QueryName(dep))
	}
}

func TestQueryNameUsesGoReplaceArtifact(t *testing.T) {
	dep := ecosystem.Dependency{
		Ecosystem: "go",
		Name:      "example.com/foo",
		Version:   "v1.3.0",
		Artifact:  "example.com/fork/foo",
		Resolved:  "v1.3.0",
		Registry:  "https://proxy.golang.org",
	}
	if osv.QueryName(dep) != "example.com/fork/foo" {
		t.Fatalf("go replace OSV name = %q", osv.QueryName(dep))
	}
}
