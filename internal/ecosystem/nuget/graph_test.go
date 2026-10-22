package nuget_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/nuget"
)

func TestScopeAndEdges(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "App.Lib": { "type": "Project", "dependencies": { "Newtonsoft.Json": "13.0.3" } },
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3", "contentHash": "aaaa" },
      "Serilog": { "type": "Direct", "resolved": "3.0.0", "contentHash": "bbbb", "dependencies": { "Microsoft.Extensions.Logging": "8.0.0", "Absent": "1.0.0" } },
      "Microsoft.Extensions.Logging": { "type": "Transitive", "resolved": "8.0.0", "contentHash": "cccc" },
      "Orphan": { "type": "Transitive", "resolved": "1.0.0", "contentHash": "dddd" }
    },
    "net6.0": {
      "Serilog": { "type": "Direct", "resolved": "3.0.0", "contentHash": "bbbb", "dependencies": { "Microsoft.Extensions.Logging": "6.0.0" } },
      "Microsoft.Extensions.Logging": { "type": "Transitive", "resolved": "6.0.0", "contentHash": "eeee" }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	deps := map[string]core.Dependency{}
	for _, dep := range list {
		deps[core.Identity(dep)] = dep
	}

	want := map[string]string{
		"nuget:Newtonsoft.Json@13.0.3":             core.ScopeRuntime,
		"nuget:Serilog@3.0.0":                      core.ScopeRuntime,
		"nuget:Microsoft.Extensions.Logging@8.0.0": core.ScopeRuntime,
		"nuget:Microsoft.Extensions.Logging@6.0.0": core.ScopeRuntime,
		"nuget:Orphan@1.0.0":                       "",
	}
	for id, scope := range want {
		dep, ok := deps[id]
		if !ok {
			t.Fatalf("%s not found", id)
		}
		if dep.Scope != scope {
			t.Errorf("%s = %q, want %q", id, dep.Scope, scope)
		}
	}
	// Serilog resolves a different logging package in each target framework, and the
	// edge from the missing package is dropped.
	if got := deps["nuget:Serilog@3.0.0"].DependsOn; len(got) != 2 ||
		got[0] != "nuget:Microsoft.Extensions.Logging@6.0.0" || got[1] != "nuget:Microsoft.Extensions.Logging@8.0.0" {
		t.Errorf("Serilog edges = %v", got)
	}
}
