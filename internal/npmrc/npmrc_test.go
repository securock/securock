package npmrc_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/npmrc"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")
}

func TestRegistryUnknownWithoutConfig(t *testing.T) {
	isolate(t)
	got := npmrc.Registry(t.TempDir(), "react", "")
	if got != "" {
		t.Fatalf("unproven registry must be empty, got %q", got)
	}
}

func TestRegistryFromTarball(t *testing.T) {
	isolate(t)
	got := npmrc.Registry(".", "react", "https://registry.npmjs.org/react/-/react-19.2.0.tgz")
	if got != "https://registry.npmjs.org" {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryLocalTarball(t *testing.T) {
	isolate(t)
	got := npmrc.Registry(".", "react", "file:../react.tgz")
	if got != "" {
		t.Fatalf("local tarball must not use a registry, got %q", got)
	}
}

func TestRegistryFromNpmrc(t *testing.T) {
	isolate(t)
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

func TestRegistryFromUserNpmrc(t *testing.T) {
	isolate(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	raw := "registry=https://registry.npmjs.org/\n@company:registry=https://npm.company.example/\n"
	if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := npmrc.Registry(t.TempDir(), "react", ""); got != "https://registry.npmjs.org" {
		t.Fatalf("user public = %q", got)
	}
	if got := npmrc.Registry(t.TempDir(), "@company/internal-auth", ""); got != "https://npm.company.example" {
		t.Fatalf("user scoped = %q", got)
	}
}

func TestRegistryEnvOverridesNpmrc(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("npm_config_registry", "https://npm.company.example/")
	if got := npmrc.Registry(dir, "react", ""); got != "https://npm.company.example" {
		t.Fatalf("env registry = %q", got)
	}
}
