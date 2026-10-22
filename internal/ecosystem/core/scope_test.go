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
