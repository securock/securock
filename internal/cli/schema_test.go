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

func TestReachabilityJSONSchema(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/app-lib": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/app-lib/-/app-lib-1.0.0.tgz", "dependencies": { "shared": "^1" } },
    "node_modules/shared": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz" },
    "node_modules/jest": { "version": "29.0.0", "resolved": "https://registry.npmjs.org/jest/-/jest-29.0.0.tgz", "dev": true }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	plain := runCLI(t, "scan", dir, "--offline", "--no-fail", "--format", "json")
	if bytes.Contains(plain, []byte(`"scope"`)) || bytes.Contains(plain, []byte(`"dependencies"`)) {
		t.Fatalf("scope and dependencies must be opt-in:\n%s", plain)
	}

	scan := runCLI(t, "scan", dir, "--offline", "--no-fail", "--format", "json", "--reachability")
	if err := schemas.Validate("scan-report.schema.json", scan); err != nil {
		t.Fatalf("scan json:\n%s\n%v", scan, err)
	}
	for _, want := range []string{`"scope": "runtime"`, `"scope": "dev"`, `"npm:shared@1.0.0"`} {
		if !bytes.Contains(scan, []byte(want)) {
			t.Fatalf("missing %s:\n%s", want, scan)
		}
	}

	runCLI(t, "lock", dir, "--offline", "--no-fail", "--reachability")
	// The lockfile with extra fields still verifies against a plain scan: scope and edges
	// are not trust drift.
	out := runCLI(t, "verify", dir, "--offline", "--no-fail")
	if !bytes.Contains(out, []byte("ok")) {
		t.Fatalf("verify:\n%s", out)
	}
}
