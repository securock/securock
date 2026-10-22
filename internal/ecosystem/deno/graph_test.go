package deno_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/deno"
)

func TestScopeAndEdges(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "version": "5",
  "specifiers": {
    "jsr:@std/assert@1": "1.0.6",
    "jsr:@std/internal@^1.0.4": "1.0.5",
    "npm:react@19": "19.2.0",
    "npm:chalk@5": "5.3.0",
    "npm:unused@1": "1.0.0"
  },
  "jsr": {
    "@std/assert@1.0.6": {
      "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
      "dependencies": ["jsr:@std/internal@^1.0.4", "npm:chalk@5"]
    },
    "@std/internal@1.0.5": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" }
  },
  "npm": {
    "react@19.2.0": {
      "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
      "dependencies": ["loose-envify", "ms@2.0.0"]
    },
    "loose-envify@1.4.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" },
    "ms@2.0.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" },
    "ms@2.1.3": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" },
    "chalk@5.3.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" },
    "unused@1.0.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" }
  },
  "workspace": {
    "dependencies": ["jsr:@std/assert@1", "npm:react@19"]
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := deno.New().Dependencies(dir)
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
	expect("jsr:@std/assert@1.0.6", core.ScopeRuntime, "jsr:@std/internal@1.0.5", "npm:chalk@5.3.0")
	expect("jsr:@std/internal@1.0.5", core.ScopeRuntime)
	expect("npm:chalk@5.3.0", core.ScopeRuntime)
	// "loose-envify" is locked once, so a bare name is enough; ms is locked twice, so react names the version.
	expect("npm:react@19.2.0", core.ScopeRuntime, "npm:loose-envify@1.4.0", "npm:ms@2.0.0")
	expect("npm:loose-envify@1.4.0", core.ScopeRuntime)
	expect("npm:ms@2.0.0", core.ScopeRuntime)
	// Nothing reaches these, so the lockfile says nothing about how they enter the project.
	expect("npm:ms@2.1.3", "")
	expect("npm:unused@1.0.0", "")
}
