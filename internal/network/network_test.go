package network_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
	"github.com/securock/securock/pkg/policy"
)

func TestAllowPublicOnly(t *testing.T) {
	npm := core.Dependency{
		Ecosystem: "npm",
		Name:      "react",
		Version:   "19.2.0",
		Registry:  "https://registry.npmjs.org",
	}
	if !network.Allow(policy.ModePublicOnly, nil, npm) {
		t.Fatal("public npm must be allowed")
	}

	private := core.Dependency{
		Ecosystem: "npm",
		Name:      "@company/internal-auth",
		Version:   "1.0.0",
		Registry:  "https://npm.company.example",
	}
	if network.Allow(policy.ModePublicOnly, nil, private) {
		t.Fatal("private npm must not be queried")
	}

	missing := core.Dependency{
		Ecosystem: "npm",
		Name:      "secret-project-sdk",
		Version:   "1.0.0",
	}
	if network.Allow(policy.ModePublicOnly, nil, missing) {
		t.Fatal("missing registry must not be queried")
	}
}

func TestAllowOffline(t *testing.T) {
	dep := core.Dependency{
		Ecosystem: "npm",
		Name:      "react",
		Version:   "19.2.0",
		Registry:  "https://registry.npmjs.org",
	}
	if network.Allow(policy.ModeOffline, nil, dep) {
		t.Fatal("offline must not query")
	}
}

func TestAllowAll(t *testing.T) {
	dep := core.Dependency{
		Ecosystem: "npm",
		Name:      "@company/internal-auth",
		Version:   "1.0.0",
		Registry:  "https://npm.company.example",
	}
	if !network.Allow(policy.ModeAllowAll, nil, dep) {
		t.Fatal("allow-all must query private packages")
	}
}

func TestGoPrivate(t *testing.T) {
	t.Setenv("GOPRIVATE", "github.com/company/*")
	dep := core.Dependency{
		Ecosystem: "go",
		Name:      "github.com/company/secret-project-sdk",
		Version:   "v1.0.0",
		Registry:  "https://proxy.golang.org",
	}
	if network.Allow(policy.ModePublicOnly, nil, dep) {
		t.Fatal("GOPRIVATE modules must not be queried")
	}
}

func TestSparseCargoRegistry(t *testing.T) {
	got := network.RegistryURL("registry+sparse+https://index.crates.io/")
	if got != "https://index.crates.io" {
		t.Fatalf("got %q", got)
	}
	dep := core.Dependency{
		Ecosystem: "cargo",
		Name:      "serde",
		Version:   "1.0.210",
		Registry:  got,
	}
	if !network.Allow(policy.ModePublicOnly, nil, dep) {
		t.Fatal("crates.io sparse index must be public")
	}
}
