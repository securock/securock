package poetry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/poetry"
)

func scopes(t *testing.T, files map[string]string) map[string]core.Dependency {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list, err := poetry.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range list {
		out[dep.Name] = dep
	}
	return out
}

func pkg(name, extra string) string {
	return `
[[package]]
name = "` + name + `"
version = "1.0.0"
` + extra + `
files = [
    {file = "` + name + `-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
}

func TestGroupsDecideScope(t *testing.T) {
	deps := scopes(t, map[string]string{"poetry.lock": pkg("main-pkg", `groups = ["main", "dev"]`) +
		pkg("dev-pkg", `groups = ["dev"]`) + pkg("test-pkg", `groups = ["test", "docs"]`)})
	want := map[string]string{"main-pkg": core.ScopeRuntime, "dev-pkg": core.ScopeDev, "test-pkg": core.ScopeDev}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
}

func TestCategoryDecidesScope(t *testing.T) {
	deps := scopes(t, map[string]string{"poetry.lock": pkg("main-pkg", `category = "main"`) + pkg("dev-pkg", `category = "dev"`)})
	if deps["main-pkg"].Scope != core.ScopeRuntime || deps["dev-pkg"].Scope != core.ScopeDev {
		t.Fatalf("scopes = %q, %q", deps["main-pkg"].Scope, deps["dev-pkg"].Scope)
	}
}

func TestPyprojectRootsForLocksWithoutGroups(t *testing.T) {
	deps := scopes(t, map[string]string{
		"poetry.lock": pkg("Requests", "\n[package.dependencies]\nidna = \">=2\"\nUrllib3 = {version = \"*\", optional = true}\n") +
			pkg("idna", "") + pkg("urllib3", "") +
			pkg("pytest", "\n[package.dependencies]\npluggy = \"*\"\nidna = \"*\"\n") + pkg("pluggy", "") +
			pkg("extra-only", "optional = true") + pkg("unreferenced", ""),
		"pyproject.toml": `[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2"

[tool.poetry.group.dev.dependencies]
pytest = "*"
`,
	})
	want := map[string]string{
		"Requests": core.ScopeRuntime, "idna": core.ScopeRuntime, "urllib3": core.ScopeRuntime,
		"pytest": core.ScopeDev, "pluggy": core.ScopeDev,
		"extra-only": core.ScopeOptional, "unreferenced": "",
	}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
	// Dependency names are matched after normalization.
	if got := deps["Requests"].DependsOn; len(got) != 2 {
		t.Errorf("Requests edges = %v", got)
	}
}

func TestPEP621Pyproject(t *testing.T) {
	deps := scopes(t, map[string]string{
		"poetry.lock": pkg("lib", "") + pkg("tester", "") + pkg("fast", ""),
		"pyproject.toml": `[project]
name = "app"
dependencies = ["lib>=1; python_version >= '3.8'"]

[project.optional-dependencies]
speed = ["fast"]

[dependency-groups]
dev = ["tester", {include-group = "other"}]
`,
	})
	want := map[string]string{"lib": core.ScopeRuntime, "tester": core.ScopeDev, "fast": core.ScopeOptional}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
}
