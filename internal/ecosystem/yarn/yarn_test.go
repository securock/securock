package yarn_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/yarn"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")
}

func TestClassicDependencies(t *testing.T) {
	isolate(t)
	eco := yarn.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected yarn.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep
	}
	react := got["react@19.2.0"]
	if react.Ecosystem != "npm" || react.Resolver != "yarn" {
		t.Fatalf("react identity = %s/%s", react.Ecosystem, react.Resolver)
	}
	if react.SourceKind != core.SourceRegistry {
		t.Fatalf("react kind = %q", react.SourceKind)
	}
	if react.Registry != "https://registry.npmjs.org" {
		t.Fatalf("react registry = %q", react.Registry)
	}
	if react.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("react digest = %q", react.Digest)
	}
	if got["@scope/pkg@1.2.3"].Name != "@scope/pkg" {
		t.Fatalf("missing scoped package: %#v", got)
	}
}

func TestBerryVirtualPackages(t *testing.T) {
	isolate(t)
	deps, err := yarn.New().Dependencies("testdata/berry")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep
	}
	if len(got) != 2 {
		t.Fatalf("got %d deps, want 2 (virtual react collapsed): %#v", len(got), got)
	}
	react := got["react@19.2.0"]
	if react.Resolver != "yarn" || react.Ecosystem != "npm" {
		t.Fatalf("react identity = %s/%s", react.Ecosystem, react.Resolver)
	}
	if react.Registry != "https://registry.npmjs.org" {
		t.Fatalf("berry registry = %q", react.Registry)
	}
	if react.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("react digest = %q", react.Digest)
	}
	local := got["local-pkg@0.0.1"]
	if local.SourceKind != core.SourceWorkspace {
		t.Fatalf("local-pkg kind = %q", local.SourceKind)
	}
}

func TestBerryPrivateScope(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	lock := `__metadata:
  version: 8
"@company/internal-auth@npm:1.0.0":
  version: 1.0.0
  resolution: "@company/internal-auth@npm:1.0.0"
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "npmRegistryServer: https://registry.npmjs.org\nnpmScopes:\n  company:\n    npmRegistryServer: https://npm.company.example\n"
	if err := os.WriteFile(filepath.Join(dir, ".yarnrc.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := yarn.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://npm.company.example" {
		t.Fatalf("private yarn scope = %#v", deps)
	}
}

func TestBerryDefaultRegistry(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	lock := `__metadata:
  version: 8
"react@npm:19.2.0":
  version: 19.2.0
  resolution: "react@npm:19.2.0"
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := yarn.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://registry.yarnpkg.com" {
		t.Fatalf("yarn default registry = %#v", deps)
	}
}

func TestBerryParentPrivateScope(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	project := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `__metadata:
  version: 8
"@company/internal-auth@npm:1.0.0":
  version: 1.0.0
  resolution: "@company/internal-auth@npm:1.0.0"
`
	if err := os.WriteFile(filepath.Join(project, "yarn.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "npmRegistryServer: https://registry.npmjs.org\nnpmScopes:\n  company:\n    npmRegistryServer: https://npm.company.example\n"
	if err := os.WriteFile(filepath.Join(root, ".yarnrc.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := yarn.New().Dependencies(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://npm.company.example" {
		t.Fatalf("parent yarn scope = %#v", deps)
	}
}
