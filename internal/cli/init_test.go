package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
)

const initLockfile = `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/ms":{"version":"2.1.3","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz","integrity":"sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="}}}`

func initProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(initLockfile), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInitWritesLockAndPolicy(t *testing.T) {
	isolateHome(t)
	dir := initProject(t)

	out := string(runCLI(t, "init", dir, "--offline", "--no-fail", "--write-policy", "--profile", "strict"))
	for _, want := range []string{"detected npm", "securock.lock", ".securock/policy.yaml", "1 artifacts", "next:", "--policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if _, _, err := lock.Read(filepath.Join(dir, "securock.lock")); err != nil {
		t.Fatalf("the lock does not read back: %v", err)
	}
	// The written policy is the profile, and it loads and verifies.
	got, err := policy.Load(filepath.Join(dir, ".securock", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Rules.RequireDigest || got.Rules.Provenance.Minimum != "verified" {
		t.Fatalf("not the strict profile: %+v", got.Rules)
	}
	runCLI(t, "verify", dir, "--offline", "--policy", filepath.Join(dir, ".securock", "policy.yaml"))
}

func TestInitWithoutPolicyFlagWritesNoPolicy(t *testing.T) {
	isolateHome(t)
	dir := initProject(t)
	runCLI(t, "init", dir, "--offline", "--no-fail")
	if _, err := os.Stat(filepath.Join(dir, ".securock")); err == nil {
		t.Fatal("no policy was asked for")
	}
}

func TestInitFailsOnUnknownButStillWrites(t *testing.T) {
	isolateHome(t)
	dir := initProject(t)
	// Like lock: an offline first run has unknown evidence, so it exits 1 after writing.
	out, err := runCLIErr(t, "init", dir, "--offline")
	if err == nil {
		t.Fatal("expected exit 1 for unknown artifacts")
	}
	if !strings.Contains(out, "unknown means the evidence was not collected") {
		t.Fatalf("unknown evidence must be explained:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "securock.lock")); err != nil {
		t.Fatalf("the lock must be written even when init exits 1: %v", err)
	}
}

func TestInitRefusals(t *testing.T) {
	isolateHome(t)

	if _, err := runCLIErr(t, "init", t.TempDir(), "--offline"); err == nil {
		t.Error("a project with no lockfile must be refused")
	}

	dir := initProject(t)
	runCLI(t, "init", dir, "--offline", "--no-fail")
	before, _ := os.ReadFile(filepath.Join(dir, "securock.lock"))
	if _, err := runCLIErr(t, "init", dir, "--offline", "--no-fail"); err == nil {
		t.Error("init must not overwrite an existing securock.lock")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "securock.lock")); string(after) != string(before) {
		t.Error("the existing securock.lock was changed")
	}

	// An existing policy is never overwritten, and nothing is written when it blocks init.
	dir = initProject(t)
	if err := os.MkdirAll(filepath.Join(dir, ".securock"), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := "version: 1\nrules:\n  require_no_malicious: true\n"
	if err := os.WriteFile(filepath.Join(dir, ".securock", "policy.yaml"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLIErr(t, "init", dir, "--offline", "--no-fail", "--write-policy"); err == nil {
		t.Error("an existing policy file must block --write-policy")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, ".securock", "policy.yaml")); string(got) != custom {
		t.Error("the existing policy was overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "securock.lock")); err == nil {
		t.Error("nothing should be written when init is refused")
	}

	if _, err := runCLIErr(t, "init", initProject(t), "--offline", "--write-policy", "--policy", "p.yaml"); err == nil {
		t.Error("--write-policy with --policy must be refused")
	}
}
