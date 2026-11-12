package cli_test

import (
	"github.com/securock/securock/schemas"
	"os"
	"path/filepath"
	"testing"
)

func TestCallReachabilityCommandSchema(t *testing.T) {
	isolateHome(t)
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "main.go"), []byte("package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello\")}\n"), 0600)
	manifest := filepath.Join(d, "symbols.json")
	os.WriteFile(manifest, []byte(`{"version":1,"symbols":[{"id":"ADVISORY","symbol":"fmt.Println"}]}`), 0600)
	out := runCLI(t, "reachability", manifest, "--project", d, "--entry", "main.main", "--offline", "--format", "json")
	if e := schemas.Validate("reachability-report.schema.json", out); e != nil {
		t.Fatal(e, string(out))
	}
}
