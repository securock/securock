package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/cli"
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

func TestExampleNPM(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")

	dir := filepath.Join("..", "..", "examples", "npm")
	root := cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"verify", dir, "--offline"})
	if err := root.Execute(); err != nil {
		t.Fatalf("examples/npm verify: %v\n%s", err, out.String())
	}
}
