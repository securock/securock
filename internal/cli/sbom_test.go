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
	// SPDX stamps the current time unless asked for a reproducible document.
	t.Setenv("SOURCE_DATE_EPOCH", "1781515800")

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

func TestSBOMTimestamps(t *testing.T) {
	dir := lockedDenoProject(t)

	t.Setenv("SOURCE_DATE_EPOCH", "")
	cdx := runCLI(t, "sbom", "export", dir)
	if bytes.Contains(cdx, []byte(`"timestamp"`)) {
		t.Fatalf("CycloneDX has no timestamp by default, so the export stays deterministic:\n%s", cdx)
	}
	spdx := runCLI(t, "sbom", "export", dir, "--spec", "spdx")
	if bytes.Contains(spdx, []byte("1970-01-01")) || !bytes.Contains(spdx, []byte(`"created": "20`)) {
		t.Fatalf("SPDX says when it was made unless asked otherwise:\n%s", spdx)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1781515800")
	for _, spec := range []string{"cyclonedx", "spdx"} {
		if a, b := runCLI(t, "sbom", "export", dir, "--spec", spec), runCLI(t, "sbom", "export", dir, "--spec", spec); !bytes.Equal(a, b) || !bytes.Contains(a, []byte("2026-06-15T09:30:00Z")) {
			t.Fatalf("%s must be reproducible and use SOURCE_DATE_EPOCH:\n%s", spec, a)
		}
	}
}

func TestSBOMVerifySARIFPointsAtTheSBOM(t *testing.T) {
	dir := lockedDenoProject(t)
	raw := runCLI(t, "sbom", "export", dir)
	file := filepath.Join(t.TempDir(), "bom.json")
	stale := strings.ReplaceAll(string(raw), "esm.sh/preact", "esm.sh/preacx")
	if err := os.WriteFile(file, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runCLI(t, "sbom", "verify", file, dir, "--format", "sarif", "--no-fail")
	if !bytes.Contains(out, []byte(`"uri": "`+filepath.ToSlash(file)+`"`)) {
		t.Fatalf("SARIF results should point at the SBOM:\n%s", out)
	}
}
