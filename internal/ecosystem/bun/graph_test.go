package bun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/bun"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestScopeAndEdges(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": { "app-lib": "^1.0.0" },
      "devDependencies": { "tester": "^2.0.0" },
      "optionalDependencies": { "fsevents": "*" },
    },
    "packages/web": {
      "name": "web",
      "dependencies": { "@scope/ui": "^1.0.0" },
    },
  },
  "packages": {
    "app-lib": ["app-lib@1.2.0", "https://registry.npmjs.org/app-lib/-/app-lib-1.2.0.tgz", { "dependencies": { "shared": "^2.0.0", "missing": "*" } }, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "app-lib/shared": ["shared@2.0.0", "https://registry.npmjs.org/shared/-/shared-2.0.0.tgz", {}, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "shared": ["shared@1.0.0", "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz", {}, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "tester": ["tester@2.1.0", "https://registry.npmjs.org/tester/-/tester-2.1.0.tgz", { "dependencies": { "shared": "^1.0.0", "tester-only": "^1.0.0" } }, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "tester-only": ["tester-only@1.0.0", "https://registry.npmjs.org/tester-only/-/tester-only-1.0.0.tgz", {}, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "fsevents": ["fsevents@2.3.0", "https://registry.npmjs.org/fsevents/-/fsevents-2.3.0.tgz", {}, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "@scope/ui": ["@scope/ui@1.0.0", "https://registry.npmjs.org/@scope/ui/-/ui-1.0.0.tgz", { "dependencies": { "tester-only": "*" } }, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
    "@scope/ui/tester-only": ["tester-only@3.0.0", "https://registry.npmjs.org/tester-only/-/tester-only-3.0.0.tgz", {}, "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="],
  },
}`
	if err := os.WriteFile(filepath.Join(dir, "bun.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := bun.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	deps := map[string]core.Dependency{}
	for _, dep := range list {
		deps[core.Identity(dep)] = dep
	}

	expect := func(id, scope string, edges ...string) {
		t.Helper()
		dep, ok := deps[id]
		if !ok {
			t.Fatalf("%s not found", id)
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
	// app-lib has its own nested shared 2.0.0, so it does not use the top-level 1.0.0.
	expect("npm:app-lib@1.2.0", core.ScopeRuntime, "npm:shared@2.0.0")
	expect("npm:shared@2.0.0", core.ScopeRuntime)
	// The top-level shared 1.0.0 is only used by the dev tool.
	expect("npm:shared@1.0.0", core.ScopeDev)
	expect("npm:tester@2.1.0", core.ScopeDev, "npm:shared@1.0.0", "npm:tester-only@1.0.0")
	expect("npm:tester-only@1.0.0", core.ScopeDev)
	expect("npm:fsevents@2.3.0", core.ScopeOptional)
	expect("npm:@scope/ui@1.0.0", core.ScopeRuntime, "npm:tester-only@3.0.0")
	expect("npm:tester-only@3.0.0", core.ScopeRuntime)
}
