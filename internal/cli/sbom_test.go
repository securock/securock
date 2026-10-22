package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

func lockedDenoProject(t *testing.T) string {
	t.Helper()
	isolateHome(t)
	dir := t.TempDir()
	lock := `{"version": "5", "redirects": {"https://esm.sh/preact": "https://esm.sh/preact@10.26.8"}}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	runCLI(t, "lock", dir, "--offline", "--no-fail")
	return dir
}

func TestSBOMExportAndVerify(t *testing.T) {
	dir := lockedDenoProject(t)

	for _, spec := range []string{"cyclonedx", "spdx"} {
		t.Run(spec, func(t *testing.T) {
			raw := runCLI(t, "sbom", "export", dir, "--spec", spec)
			if !json.Valid(raw) {
				t.Fatalf("export is not JSON:\n%s", raw)
			}
			again := runCLI(t, "sbom", "export", dir, "--spec", spec)
			if !bytes.Equal(raw, again) {
				t.Fatal("export is not deterministic")
			}

			file := filepath.Join(t.TempDir(), spec+".json")
			if err := os.WriteFile(file, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			out := runCLI(t, "sbom", "verify", file, dir, "--format", "json")
			if err := schemas.Validate("sbom-verify-report.schema.json", out); err != nil {
				t.Fatalf("verify json:\n%s\n%v", out, err)
			}
			if !bytes.Contains(out, []byte(`"findings": []`)) {
				t.Fatalf("unexpected findings:\n%s", out)
			}
		})
	}
}

func TestSBOMVerifyFailsOnDrift(t *testing.T) {
	dir := lockedDenoProject(t)
	raw := runCLI(t, "sbom", "export", dir)
	file := filepath.Join(t.TempDir(), "bom.json")
	stale := strings.ReplaceAll(string(raw), "esm.sh/preact", "esm.sh/preacx")
	if err := os.WriteFile(file, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRoot("test", "none", "unknown")
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"sbom", "verify", file, dir})
	if err := root.Execute(); err == nil {
		t.Fatalf("expected a failure for a stale SBOM:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "sbom-") {
		t.Fatalf("expected sbom findings:\n%s", out.String())
	}

	root = cli.NewRoot("test", "none", "unknown")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"sbom", "verify", file, dir, "--no-fail"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--no-fail should always exit 0: %v", err)
	}
}

func TestSBOMErrors(t *testing.T) {
	dir := lockedDenoProject(t)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"unknown spec":     {"sbom", "export", dir, "--spec", "xml"},
		"missing lockfile": {"sbom", "export", t.TempDir()},
		"missing sbom":     {"sbom", "verify", filepath.Join(t.TempDir(), "none.json"), dir},
		"unrecognized":     {"sbom", "verify", bad, dir},
	} {
		t.Run(name, func(t *testing.T) {
			root := cli.NewRoot("test", "none", "unknown")
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(args)
			if err := root.Execute(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
