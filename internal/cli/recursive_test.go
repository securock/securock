package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cli"
)

func monorepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	lock := func(name string) string {
		return `{"name":"` + name + `","lockfileVersion":3,"packages":{"":{"name":"` + name + `"},"node_modules/ms":{"version":"2.1.3","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz","integrity":"sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="}}}`
	}
	for _, p := range []string{"services/api", "services/web"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p, "package-lock.json"), []byte(lock(filepath.Base(p))), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRecursiveLockAndVerify(t *testing.T) {
	isolateHome(t)
	root := monorepo(t)

	out := string(runCLI(t, "lock", root, "--recursive", "--offline", "--no-fail"))
	for _, want := range []string{"== services/api ==", "== services/web =="} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, p := range []string{"services/api", "services/web"} {
		if _, err := os.Stat(filepath.Join(root, p, "securock.lock")); err != nil {
			t.Errorf("%s has no securock.lock: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "securock.lock")); err == nil {
		t.Error("the root is not a project and must not get a lock")
	}

	// Both projects match their lock, so verify passes; -r is the short form.
	if out := string(runCLI(t, "verify", root, "-r", "--offline")); strings.Count(out, "ok ") != 2 {
		t.Fatalf("expected two passing projects:\n%s", out)
	}
}

func TestRecursiveReportsEveryProjectAndTheWorstExit(t *testing.T) {
	isolateHome(t)
	root := monorepo(t)
	runCLI(t, "lock", root, "--recursive", "--offline", "--no-fail")

	// Drift only services/api: its lockfile now holds a second package.
	api := filepath.Join(root, "services", "api", "package-lock.json")
	drifted := `{"name":"api","lockfileVersion":3,"packages":{"":{"name":"api"},"node_modules/ms":{"version":"2.1.2","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.2.tgz","integrity":"sha512-sGkPx+VYMvRAXcheezDyAn2bwmqqIEyH1G46hQwiiVMPsfnWC+Qd7FXY5QNKnP+HSXLjSb3TIBuTRwmcsUz+Mw=="}}}`
	if err := os.WriteFile(api, []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}

	root2 := cli.NewRoot("test", "none", "unknown")
	var out, errOut bytes.Buffer
	root2.SetOut(&out)
	root2.SetErr(&errOut)
	root2.SetArgs([]string{"verify", root, "--recursive", "--offline"})
	err := root2.Execute()
	if err == nil {
		t.Fatalf("drift in one project must fail the run:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "1 of 2 projects failed") {
		t.Fatalf("err = %v", err)
	}
	// The second project is still checked after the first fails.
	if !strings.Contains(out.String(), "== services/web ==") || !strings.Contains(out.String(), "ok ") {
		t.Fatalf("services/web was not reported:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "services/api: trust drift detected") {
		t.Fatalf("the failing project must be named:\n%s", errOut.String())
	}
}

func TestRecursiveRefusesMachineReadableFormats(t *testing.T) {
	isolateHome(t)
	root := monorepo(t)
	for _, format := range []string{"json", "sarif", "junit"} {
		if _, err := runCLIErr(t, "verify", root, "--recursive", "--offline", "--format", format); err == nil {
			t.Errorf("--format %s should be refused with --recursive", format)
		}
	}
	if out := string(runCLI(t, "scan", root, "--recursive", "--offline", "--no-fail", "--format", "markdown")); !strings.Contains(out, "# `services/api`") {
		t.Fatalf("markdown should be allowed:\n%s", out)
	}
}

func TestRecursiveWithoutProjects(t *testing.T) {
	isolateHome(t)
	if _, err := runCLIErr(t, "verify", t.TempDir(), "--recursive", "--offline"); err == nil {
		t.Fatal("no projects must be an error, not a pass")
	}
}
