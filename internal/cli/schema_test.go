package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

func isolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")
}

func runCLI(t *testing.T, args ...string) []byte {
	t.Helper()
	root := cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	return out.Bytes()
}

func TestJSONSchemaConformance(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{
  "version": "5",
  "redirects": {
    "https://esm.sh/preact": "https://esm.sh/preact@10.26.8"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	scan := runCLI(t, "scan", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("scan-report.schema.json", scan); err != nil {
		t.Fatalf("scan json:\n%s\n%v", scan, err)
	}

	runCLI(t, "lock", dir, "--offline", "--no-fail")

	lock = `{
  "version": "5",
  "redirects": {
    "https://esm.sh/preact": "https://esm.sh/preact@10.26.9"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	diff := runCLI(t, "diff", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("diff-report.schema.json", diff); err != nil {
		t.Fatalf("diff json:\n%s\n%v", diff, err)
	}
	if !bytes.Contains(diff, []byte(`"resolved"`)) {
		t.Fatalf("diff json missing resolved:\n%s", diff)
	}

	verify := runCLI(t, "verify", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("verify-report.schema.json", verify); err != nil {
		t.Fatalf("verify json:\n%s\n%v", verify, err)
	}
}

func TestJSONSchemaNPMScan(t *testing.T) {
	dir := filepath.Join("..", "ecosystem", "npm", "testdata")
	scan := runCLI(t, "scan", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("scan-report.schema.json", scan); err != nil {
		t.Fatalf("npm scan json:\n%s\n%v", scan, err)
	}
}
