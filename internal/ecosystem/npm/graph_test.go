package npm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/npm"
)

func loadLock(t *testing.T, body string) map[string]core.Dependency {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := npm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range deps {
		out[core.Identity(dep)] = dep
	}
	return out
}

func assertGraph(t *testing.T, deps map[string]core.Dependency, id, scope string, edges ...string) {
	t.Helper()
	dep, ok := deps[id]
	if !ok {
		t.Fatalf("%s not found in %v", id, keys(deps))
	}
	if dep.Scope != scope {
		t.Errorf("%s scope = %q, want %q", id, dep.Scope, scope)
	}
	if len(dep.DependsOn) != len(edges) {
		t.Fatalf("%s depends on %v, want %v", id, dep.DependsOn, edges)
	}
	for i, want := range edges {
		if dep.DependsOn[i] != want {
			t.Errorf("%s depends on %v, want %v", id, dep.DependsOn, edges)
		}
	}
}

func keys(m map[string]core.Dependency) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPackageLockScopeAndEdges(t *testing.T) {
	deps := loadLock(t, `{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0", "dependencies": { "app-lib": "^1" }, "devDependencies": { "jest": "^29" } },
    "node_modules/app-lib": { "version": "1.0.0", "dependencies": { "shared": "^2", "nested-user": "^1" }, "peerDependencies": { "peer-dep": "*" } },
    "node_modules/app-lib/node_modules/shared": { "version": "2.0.0" },
    "node_modules/shared": { "version": "1.0.0" },
    "node_modules/nested-user": { "version": "1.0.0", "dependencies": { "shared": "^1", "missing": "*" } },
    "node_modules/peer-dep": { "version": "3.0.0" },
    "node_modules/jest": { "version": "29.0.0", "dev": true, "dependencies": { "jest-util": "^29" } },
    "node_modules/jest-util": { "version": "29.0.0", "dev": true },
    "node_modules/fsevents": { "version": "2.3.0", "optional": true },
    "node_modules/both": { "version": "1.0.0", "devOptional": true },
    "packages/lib": { "name": "lib", "version": "0.0.0", "dependencies": { "shared": "*" } }
  }
}`)

	assertGraph(t, deps, "npm:app-lib@1.0.0", core.ScopeRuntime, "npm:nested-user@1.0.0", "npm:peer-dep@3.0.0", "npm:shared@2.0.0")
	assertGraph(t, deps, "npm:shared@2.0.0", core.ScopeRuntime)
	assertGraph(t, deps, "npm:nested-user@1.0.0", core.ScopeRuntime, "npm:shared@1.0.0")
	assertGraph(t, deps, "npm:jest@29.0.0", core.ScopeDev, "npm:jest-util@29.0.0")
	assertGraph(t, deps, "npm:jest-util@29.0.0", core.ScopeDev)
	assertGraph(t, deps, "npm:fsevents@2.3.0", core.ScopeOptional)
	assertGraph(t, deps, "npm:both@1.0.0", core.ScopeOptional)
	assertGraph(t, deps, "npm:lib@0.0.0", core.ScopeRuntime, "npm:shared@1.0.0")
}

func TestPackageLockV1ScopeAndEdges(t *testing.T) {
	deps := loadLock(t, `{
  "lockfileVersion": 1,
  "dependencies": {
    "app-lib": {
      "version": "1.0.0",
      "requires": { "shared": "^2", "top": "^1" },
      "dependencies": { "shared": { "version": "2.0.0" } }
    },
    "top": { "version": "1.0.0", "requires": { "shared": "^1" } },
    "shared": { "version": "1.0.0" },
    "tester": { "version": "1.0.0", "dev": true, "requires": { "shared": "^1" } }
  }
}`)

	assertGraph(t, deps, "npm:app-lib@1.0.0", core.ScopeRuntime, "npm:shared@2.0.0", "npm:top@1.0.0")
	assertGraph(t, deps, "npm:top@1.0.0", core.ScopeRuntime, "npm:shared@1.0.0")
	assertGraph(t, deps, "npm:tester@1.0.0", core.ScopeDev, "npm:shared@1.0.0")
}

func TestCollectMergesCopiesOfOneArtifact(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/a": { "version": "1.0.0", "dependencies": { "dup": "*", "only-a": "*" } },
    "node_modules/b": { "version": "1.0.0", "dev": true, "dependencies": { "dup": "*", "only-b": "*" } },
    "node_modules/dup": { "version": "1.0.0", "dev": true },
    "node_modules/a/node_modules/dup": { "version": "1.0.0" },
    "node_modules/only-a": { "version": "1.0.0" },
    "node_modules/only-b": { "version": "1.0.0", "dev": true }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := ecosystem.Collect(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[core.Identity(dep)] = dep
	}
	if len(got) != len(deps) {
		t.Fatalf("expected one entry per artifact, got %d entries for %d artifacts", len(deps), len(got))
	}
	// dup is dev at the top level but a runtime copy sits under a: the runtime need wins.
	if got["npm:dup@1.0.0"].Scope != core.ScopeRuntime {
		t.Fatalf("dup scope = %q", got["npm:dup@1.0.0"].Scope)
	}
	if got["npm:only-b@1.0.0"].Scope != core.ScopeDev {
		t.Fatalf("only-b scope = %q", got["npm:only-b@1.0.0"].Scope)
	}
}
