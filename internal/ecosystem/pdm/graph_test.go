package pdm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pdm"
)

func pkg(name string, groups string, deps ...string) string {
	out := `
[[package]]
name = "` + name + `"
version = "1.0.0"
groups = ` + groups + `
files = [
    {file = "` + name + `-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if len(deps) > 0 {
		out += "dependencies = ["
		for _, d := range deps {
			out += `"` + d + `", `
		}
		out += "]\n"
	}
	return out
}

func load(t *testing.T, files map[string]string) map[string]core.Dependency {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list, err := pdm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range list {
		out[dep.Name] = dep
	}
	return out
}

func TestGroupsAndEdges(t *testing.T) {
	deps := load(t, map[string]string{
		"pdm.lock": pkg("requests", `["default"]`, "idna>=2.5", "urllib3[socks]<3,>=1.21; python_version >= '3.8'") +
			pkg("idna", `["default", "dev"]`) + pkg("urllib3", `["default"]`) +
			pkg("pytest", `["dev"]`, "pluggy") + pkg("pluggy", `["dev"]`) +
			pkg("ujson", `["speed"]`) + pkg("mystery", `["internal-group"]`),
		"pyproject.toml": `[project]
name = "app"

[project.optional-dependencies]
speed = ["ujson"]

[tool.pdm.dev-dependencies]
dev = ["pytest"]
`,
	})
	want := map[string]string{
		"requests": core.ScopeRuntime, "idna": core.ScopeRuntime, "urllib3": core.ScopeRuntime,
		"pytest": core.ScopeDev, "pluggy": core.ScopeDev,
		"ujson": core.ScopeOptional, "mystery": "",
	}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
	edges := deps["requests"].DependsOn
	if len(edges) != 2 || edges[0] != "pypi:idna@1.0.0#idna-1.0.0.tar.gz" || edges[1] != "pypi:urllib3@1.0.0#urllib3-1.0.0.tar.gz" {
		t.Errorf("requests edges = %v", edges)
	}
}

func TestUnknownGroupsWithoutPyproject(t *testing.T) {
	deps := load(t, map[string]string{"pdm.lock": pkg("a", `["default"]`) + pkg("b", `["dev"]`)})
	if deps["a"].Scope != core.ScopeRuntime {
		t.Errorf("a = %q", deps["a"].Scope)
	}
	if deps["b"].Scope != "" {
		t.Errorf("without pyproject.toml the dev group is not understood, got %q", deps["b"].Scope)
	}
}
