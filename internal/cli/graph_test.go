package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGraphCommand(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"a": "1.0.0"}},
    "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "dependencies": {"b": "1.0.0"}},
    "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	tree := string(runCLI(t, "graph", dir, "--offline"))
	if !strings.Contains(tree, "a@1.0.0") || !strings.Contains(tree, "└── b@1.0.0") {
		t.Fatalf("b should hang under a:\n%s", tree)
	}
	// Offline evidence is unknown, so every package is a problem and nothing is dropped.
	if got := string(runCLI(t, "graph", dir, "--offline", "--problems")); got != tree {
		t.Fatalf("--problems dropped unknown packages:\n%s", got)
	}
	mermaid := string(runCLI(t, "graph", dir, "--offline", "--format", "mermaid"))
	if !strings.Contains(mermaid, "graph LR") || !strings.Contains(mermaid, "n0 --> n1") {
		t.Fatalf("unexpected mermaid:\n%s", mermaid)
	}
	if !strings.Contains(string(runCLI(t, "graph", dir, "--offline", "--format", "dot")), "digraph securock") {
		t.Fatal("dot output missing")
	}
	if _, err := runCLIErr(t, "graph", dir, "--offline", "--format", "svg"); err == nil {
		t.Fatal("an unknown format should fail")
	}
}
