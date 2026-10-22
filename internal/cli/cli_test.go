package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

func TestScanOffline(t *testing.T) {
	dir := filepath.Join("..", "ecosystem", "npm", "testdata")
	root := cli.NewRoot("test", "none", "unknown")
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"scan", dir, "--offline", "--no-fail"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("ecosystems  npm")) {
		t.Fatalf("unexpected output:\n%s", buf.String())
	}
}

func TestLockAndVerify(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("..", "ecosystem", "npm", "testdata", "package-lock.json")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRoot("test", "none", "unknown")
	root.SetArgs([]string{"lock", dir, "--offline", "--no-fail"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	root = cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetArgs([]string{"verify", dir, "--offline"})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify: %v\n%s", err, out.String())
	}
}

func TestExamples(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")

	examples := []string{"npm", "pnpm", "yarn", "bun", "uv", "poetry", "go", "cargo"}
	for _, name := range examples {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "examples", name)
			root := cli.NewRoot("test", "none", "unknown")
			out := &bytes.Buffer{}
			root.SetOut(out)
			root.SetErr(out)
			root.SetArgs([]string{"verify", dir, "--offline"})
			if err := root.Execute(); err != nil {
				t.Fatalf("examples/%s verify: %v\n%s", name, err, out.String())
			}
		})
	}
}

func TestAuditOffline(t *testing.T) {
	isolateHome(t)
	dir := filepath.Join("..", "ecosystem", "npm", "testdata")

	text := runCLI(t, "audit", dir, "--offline", "--no-fail")
	if !bytes.Contains(text, []byte("findings")) {
		t.Fatalf("unexpected output:\n%s", text)
	}

	js := runCLI(t, "audit", dir, "--offline", "--no-fail", "--format", "json")
	if err := schemas.Validate("audit-report.schema.json", js); err != nil {
		t.Fatalf("audit json:\n%s\n%v", js, err)
	}

	sarif := runCLI(t, "audit", dir, "--offline", "--no-fail", "--format", "sarif")
	if !bytes.Contains(sarif, []byte(`"version": "2.1.0"`)) {
		t.Fatalf("unexpected sarif:\n%s", sarif)
	}
}

func TestAuditFailOn(t *testing.T) {
	isolateHome(t)
	dir := filepath.Join("..", "ecosystem", "npm", "testdata")

	root := cli.NewRoot("test", "none", "unknown")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"audit", dir, "--offline", "--fail-on", "info"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected a failure: offline scans always report unchecked evidence at info")
	}

	root = cli.NewRoot("test", "none", "unknown")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"audit", dir, "--offline", "--fail-on", "urgent"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected an error for an unknown severity")
	}
}

func TestDoctor(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=http://example.com/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	js := runCLI(t, "doctor", dir, "--no-fail", "--format", "json")
	if err := schemas.Validate("doctor-report.schema.json", js); err != nil {
		t.Fatalf("doctor json:\n%s\n%v", js, err)
	}
	if !bytes.Contains(js, []byte("registry-insecure-http")) {
		t.Fatalf("missing finding:\n%s", js)
	}

	root := cli.NewRoot("test", "none", "unknown")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"doctor", dir})
	if err := root.Execute(); err == nil {
		t.Fatal("expected a failure for a high severity finding")
	}
}
