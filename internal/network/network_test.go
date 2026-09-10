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

	yarnpkg := core.Dependency{
		Ecosystem: "npm",
		Name:      "react",
		Version:   "19.2.0",
		Registry:  "https://registry.yarnpkg.com",
	}
	if !network.Allow(policy.ModePublicOnly, nil, yarnpkg) {
		t.Fatal("yarn default registry must be public npm")
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

func TestAllowSkipsWorkspace(t *testing.T) {
	dep := core.Dependency{
		Ecosystem:  "npm",
		Name:       "local-pkg",
		Version:    "0.0.1",
		SourceKind: core.SourceWorkspace,
	}
	if network.Allow(policy.ModeAllowAll, nil, dep) {
		t.Fatal("workspace packages must not be queried")
	}
}

func isolateGo(t *testing.T) {
	t.Helper()
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
}

func TestGoPrivate(t *testing.T) {
	isolateGo(t)
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

	public := core.Dependency{
		Ecosystem: "go",
		Name:      "golang.org/x/mod",
		Version:   "v0.41.0",
		Registry:  "https://proxy.golang.org",
	}
	if !network.Allow(policy.ModePublicOnly, nil, public) {
		t.Fatal("modules outside GOPRIVATE must still be queried")
	}
}

func TestGoPrivateWildcardHost(t *testing.T) {
	isolateGo(t)
	t.Setenv("GOPRIVATE", "*.corp.example.com")
	private := core.Dependency{
		Ecosystem: "go",
		Name:      "git.corp.example.com/xyzzy",
		Version:   "v1.0.0",
		Registry:  "https://proxy.golang.org",
	}
	if network.Allow(policy.ModePublicOnly, nil, private) {
		t.Fatal("GOPRIVATE host wildcards must match module path prefixes")
	}

	public := core.Dependency{
		Ecosystem: "go",
		Name:      "github.com/public/mod",
		Version:   "v1.0.0",
		Registry:  "https://proxy.golang.org",
	}
	if !network.Allow(policy.ModePublicOnly, nil, public) {
		t.Fatal("unrelated modules must not match GOPRIVATE host wildcards")
	}
}

func TestGoNoProxy(t *testing.T) {
	isolateGo(t)
	t.Setenv("GONOPROXY", "example.com/foo")
	dep := core.Dependency{
		Ecosystem: "go",
		Name:      "example.com/foo",
		Version:   "v1.2.3",
		Registry:  "https://proxy.golang.org",
	}
	if network.Allow(policy.ModePublicOnly, nil, dep) {
		t.Fatal("GONOPROXY modules must not be queried")
	}
}

func TestGoReplacePrivacyUsesFork(t *testing.T) {
	isolateGo(t)
	t.Setenv("GOPRIVATE", "example.com/fork/*")
	dep := core.Dependency{
		Ecosystem: "go",
		Name:      "example.com/foo",
		Version:   "v1.3.0",
		Artifact:  "example.com/fork/foo",
		Registry:  "https://proxy.golang.org",
	}
	if network.Allow(policy.ModePublicOnly, nil, dep) {
		t.Fatal("private replacement module must not be queried")
	}
	public := core.Dependency{
		Ecosystem: "go",
		Name:      "example.com/foo",
		Version:   "v1.3.0",
		Artifact:  "github.com/public/foo",
		Registry:  "https://proxy.golang.org",
	}
	if !network.Allow(policy.ModePublicOnly, nil, public) {
		t.Fatal("public replacement module may be queried")
	}
}

func TestGoReplacePrivacyFollowsForkNotRequire(t *testing.T) {
	isolateGo(t)
	t.Setenv("GOPRIVATE", "example.com/foo")
	dep := core.Dependency{
		Ecosystem: "go",
		Name:      "example.com/foo",
		Version:   "v1.3.0",
		Artifact:  "github.com/public/foo",
		Registry:  "https://proxy.golang.org",
	}
	if !network.Allow(policy.ModePublicOnly, nil, dep) {
		t.Fatal("privacy must follow the replacement module, not the require path")
	}
}

func TestGoCompanyProxy(t *testing.T) {
	isolateGo(t)
	dep := core.Dependency{
		Ecosystem: "go",
		Name:      "github.com/spf13/cobra",
		Version:   "v1.9.1",
		Registry:  "https://proxy.company.example",
	}
	if network.Allow(policy.ModePublicOnly, nil, dep) {
		t.Fatal("custom GOPROXY must not look public")
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

func TestAllowlistDoesNotMatchParentPath(t *testing.T) {
	allow := map[string][]string{
		"npm": {"https://repo.example/npm-public"},
	}
	parent := core.Dependency{
		Ecosystem: "npm",
		Name:      "foo",
		Version:   "1.0.0",
		Registry:  "https://repo.example",
	}
	if network.Allow(policy.ModePublicOnly, allow, parent) {
		t.Fatal("parent registry URL must not match a path-scoped allowlist")
	}
	child := core.Dependency{
		Ecosystem: "npm",
		Name:      "foo",
		Version:   "1.0.0",
		Registry:  "https://repo.example/npm-public",
	}
	if !network.Allow(policy.ModePublicOnly, allow, child) {
		t.Fatal("exact allowlisted path must be allowed")
	}
	nested := core.Dependency{
		Ecosystem: "npm",
		Name:      "foo",
		Version:   "1.0.0",
		Registry:  "https://repo.example/npm-public/extra",
	}
	if !network.Allow(policy.ModePublicOnly, allow, nested) {
		t.Fatal("nested path under allowlist must be allowed")
	}
	sibling := core.Dependency{
		Ecosystem: "npm",
		Name:      "foo",
		Version:   "1.0.0",
		Registry:  "https://repo.example/npm-private",
	}
	if network.Allow(policy.ModePublicOnly, allow, sibling) {
		t.Fatal("sibling path must not match")
	}
}

func TestProvenance(t *testing.T) {
	if got := network.Provenance("nuget", nil); got != "" {
		t.Fatalf("unknown = %q", got)
	}
	if got := network.Provenance("nuget", []string{"https://api.nuget.org/v3/index.json"}); got != "https://api.nuget.org" {
		t.Fatalf("public nuget = %q", got)
	}
	if got := network.Provenance("nuget", []string{
		"https://api.nuget.org/v3/index.json",
		"https://nuget.company.example/v3/index.json",
	}); got != "" {
		t.Fatalf("mixed = %q", got)
	}
	if got := network.Provenance("pypi", []string{"https://pypi.company.example/simple"}); got != "https://pypi.company.example" {
		t.Fatalf("single private = %q", got)
	}
}
