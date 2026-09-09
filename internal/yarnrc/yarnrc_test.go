package yarnrc_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/yarnrc"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestRegistryUnknownWithoutConfig(t *testing.T) {
	isolate(t)
	if got := yarnrc.Registry(t.TempDir(), "react", ""); got != "" {
		t.Fatalf("unproven = %q", got)
	}
}

func TestRegistryFromYarnrc(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := "npmRegistryServer: https://registry.npmjs.org\nnpmScopes:\n  company:\n    npmRegistryServer: https://npm.company.example\n"
	if err := os.WriteFile(filepath.Join(dir, ".yarnrc.yml"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := yarnrc.Registry(dir, "react", ""); got != "https://registry.npmjs.org" {
		t.Fatalf("public = %q", got)
	}
	if got := yarnrc.Registry(dir, "@company/internal-auth", ""); got != "https://npm.company.example" {
		t.Fatalf("scoped = %q", got)
	}
}

func TestRegistryFromTarball(t *testing.T) {
	isolate(t)
	got := yarnrc.Registry(".", "react", "https://registry.npmjs.org/react/-/react-19.2.0.tgz")
	if got != "https://registry.npmjs.org" {
		t.Fatalf("got %q", got)
	}
}
