package npmrc_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/npmrc"
)

func TestRegistryDefault(t *testing.T) {
	got := npmrc.Registry(t.TempDir(), "react", "")
	if got != npmrc.DefaultRegistry {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryFromTarball(t *testing.T) {
	got := npmrc.Registry(".", "react", "https://registry.npmjs.org/react/-/react-19.2.0.tgz")
	if got != "https://registry.npmjs.org" {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryLocalTarball(t *testing.T) {
	got := npmrc.Registry(".", "react", "file:../react.tgz")
	if got != "" {
		t.Fatalf("local tarball must not use a registry, got %q", got)
	}
}

func TestRegistryFromNpmrc(t *testing.T) {
	dir := t.TempDir()
	raw := "registry=https://registry.npmjs.org/\n@company:registry=https://npm.company.example/\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := npmrc.Registry(dir, "react", ""); got != "https://registry.npmjs.org" {
		t.Fatalf("public = %q", got)
	}
	if got := npmrc.Registry(dir, "@company/internal-auth", ""); got != "https://npm.company.example" {
		t.Fatalf("scoped = %q", got)
	}
}
