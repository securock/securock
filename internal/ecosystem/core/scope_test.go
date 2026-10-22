package core_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
)

func dep(name string, edges ...string) core.Dependency {
	return core.Dependency{Ecosystem: "npm", Name: name, Version: "1.0.0", DependsOn: edges}
}

func TestApplyScopes(t *testing.T) {
	deps := []core.Dependency{
		dep("app", "npm:shared@1.0.0", "npm:only-app@1.0.0"),
		dep("tool", "npm:shared@1.0.0", "npm:only-tool@1.0.0"),
		dep("shared"),
		dep("only-app"),
		dep("only-tool"),
		dep("orphan"),
		dep("optional-root"),
	}
	core.ApplyScopes(deps, map[string]string{
		"npm:app@1.0.0":           core.ScopeRuntime,
		"npm:tool@1.0.0":          core.ScopeDev,
		"npm:optional-root@1.0.0": core.ScopeOptional,
		"npm:not-installed@1.0.0": core.ScopeRuntime,
	})
	want := map[string]string{
		"app": core.ScopeRuntime, "shared": core.ScopeRuntime, "only-app": core.ScopeRuntime,
		"tool": core.ScopeDev, "only-tool": core.ScopeDev,
		"optional-root": core.ScopeOptional,
		"orphan":        "",
	}
	for _, d := range deps {
		if d.Scope != want[d.Name] {
			t.Errorf("%s scope = %q, want %q", d.Name, d.Scope, want[d.Name])
		}
	}
}

func TestApplyScopesHandlesCycles(t *testing.T) {
	deps := []core.Dependency{
		dep("a", "npm:b@1.0.0"),
		dep("b", "npm:a@1.0.0"),
	}
	core.ApplyScopes(deps, map[string]string{"npm:a@1.0.0": core.ScopeRuntime})
	if deps[0].Scope != core.ScopeRuntime || deps[1].Scope != core.ScopeRuntime {
		t.Fatalf("scopes = %q, %q", deps[0].Scope, deps[1].Scope)
	}
}

func TestApplyScopesKeepsExistingStrongerScope(t *testing.T) {
	deps := []core.Dependency{{Ecosystem: "npm", Name: "a", Version: "1.0.0", Scope: core.ScopeRuntime}}
	core.ApplyScopes(deps, map[string]string{"npm:a@1.0.0": core.ScopeDev})
	if deps[0].Scope != core.ScopeRuntime {
		t.Fatalf("scope = %q", deps[0].Scope)
	}
}

func TestMergeScopeAndUnion(t *testing.T) {
	cases := [][3]string{
		{"", "", ""}, {"", core.ScopeDev, core.ScopeDev}, {core.ScopeDev, core.ScopeOptional, core.ScopeOptional},
		{core.ScopeOptional, core.ScopeRuntime, core.ScopeRuntime}, {core.ScopeRuntime, core.ScopeDev, core.ScopeRuntime},
	}
	for _, c := range cases {
		if got := core.MergeScope(c[0], c[1]); got != c[2] {
			t.Errorf("MergeScope(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	if got := core.UnionIdentities([]string{"b", "a"}, []string{"c", "a"}); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("union = %v", got)
	}
	if core.UnionIdentities(nil, nil) != nil {
		t.Error("union of nothing should be nil")
	}
}

func pyDep(name, version, file string) core.Dependency {
	return core.Dependency{Ecosystem: "pypi", Name: name, Version: version, Filename: file}
}

func TestApplyPackageGraph(t *testing.T) {
	deps := []core.Dependency{
		pyDep("app", "1", "app-1.tar.gz"),
		pyDep("lib", "2", "lib-2.whl"),
		pyDep("lib", "2", "lib-2.tar.gz"),
		pyDep("tool", "3", "tool-3.whl"),
		pyDep("loose", "4", "loose-4.whl"),
		pyDep("flagged", "5", "flagged-5.whl"),
	}
	key := func(d core.Dependency) string { return d.Name + "@" + d.Version }
	core.ApplyPackageGraph(deps, key, core.PackageGraph{
		Edges: map[string][]string{
			"app@1":  {"lib@2", "missing@9"},
			"tool@3": {"lib@2"},
		},
		Roots: map[string]string{"app@1": core.ScopeRuntime, "tool@3": core.ScopeDev},
		Fixed: map[string]string{"flagged@5": core.ScopeDev},
	})

	scopes := map[string]string{}
	for _, d := range deps {
		scopes[d.Filename] = d.Scope
	}
	want := map[string]string{
		"app-1.tar.gz": core.ScopeRuntime, "lib-2.whl": core.ScopeRuntime, "lib-2.tar.gz": core.ScopeRuntime,
		"tool-3.whl": core.ScopeDev, "loose-4.whl": "", "flagged-5.whl": core.ScopeDev,
	}
	for file, scope := range want {
		if scopes[file] != scope {
			t.Errorf("%s scope = %q, want %q", file, scopes[file], scope)
		}
	}

	// Edges are recorded once per package, between first artifacts.
	if got := deps[0].DependsOn; len(got) != 1 || got[0] != "pypi:lib@2#lib-2.whl" {
		t.Errorf("app edges = %v", got)
	}
	if got := deps[3].DependsOn; len(got) != 1 || got[0] != "pypi:lib@2#lib-2.whl" {
		t.Errorf("tool edges = %v", got)
	}
	if len(deps[2].DependsOn) != 0 {
		t.Errorf("a second artifact of a package carries no edges: %v", deps[2].DependsOn)
	}
}

func TestPythonNames(t *testing.T) {
	names := map[string]string{
		"Jinja2": "jinja2", "zope.interface": "zope-interface", "typing_extensions": "typing-extensions", " Foo__Bar ": "foo-bar",
	}
	for in, want := range names {
		if got := core.NormalizePythonName(in); got != want {
			t.Errorf("NormalizePythonName(%q) = %q, want %q", in, got, want)
		}
	}
	reqs := map[string]string{
		"requests>=2.0": "requests",
		"requests[security]>=2.0; python_version >= '3.8'": "requests",
		"Jinja2 (>=2.0)":                    "jinja2",
		"pkg @ https://example.com/pkg.whl": "pkg",
		"plain":                             "plain",
		"urllib3<3,>=1.21.1":                "urllib3",
	}
	for in, want := range reqs {
		if got := core.PythonRequirementName(in); got != want {
			t.Errorf("PythonRequirementName(%q) = %q, want %q", in, got, want)
		}
	}
}
