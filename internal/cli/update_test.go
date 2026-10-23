package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

// updatedProject is a locked Deno project whose dependency then moves to a new version.
func updatedProject(t *testing.T) (dir, lockPath string) {
	t.Helper()
	isolateHome(t)
	dir = t.TempDir()
	writeDenoLock(t, dir, "10.26.8")
	runCLI(t, "lock", dir, "--offline", "--no-fail")
	writeDenoLock(t, dir, "10.26.9")
	return dir, filepath.Join(dir, "securock.lock")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestUpdatePreviewLeavesTheLockfileAlone(t *testing.T) {
	dir, lockPath := updatedProject(t)
	before := readFile(t, lockPath)

	out := string(runCLI(t, "update", dir, "--offline"))
	if !strings.Contains(out, "10.26.9") || !strings.Contains(out, "was not changed") {
		t.Fatalf("preview should show the drift and say nothing was written:\n%s", out)
	}
	if got := readFile(t, lockPath); got != before {
		t.Fatalf("preview rewrote the lockfile:\n%s", got)
	}
}

func TestUpdateWriteRecordsTheNewState(t *testing.T) {
	dir, lockPath := updatedProject(t)
	before := readFile(t, lockPath)

	out := string(runCLI(t, "update", dir, "--offline", "--write", "--no-fail"))
	if !strings.Contains(out, "wrote "+lockPath) {
		t.Fatalf("output: %s", out)
	}
	after := readFile(t, lockPath)
	if after == before || !strings.Contains(after, "10.26.9") {
		t.Fatalf("lockfile was not refreshed:\n%s", after)
	}

	// The recorded state now matches the tree, so a second run has nothing to do.
	out = string(runCLI(t, "update", dir, "--offline", "--write", "--no-fail"))
	if !strings.Contains(out, "up to date") {
		t.Fatalf("second run: %s", out)
	}
	if readFile(t, lockPath) != after {
		t.Fatal("an up-to-date lockfile must stay byte-identical")
	}
}

func TestUpdateWriteRefusesAnUnapprovedState(t *testing.T) {
	dir, lockPath := updatedProject(t)
	before := readFile(t, lockPath)

	// Offline, nothing is checked, so the artifacts are unknown rather than trusted.
	out, err := runCLIErr(t, "update", dir, "--offline", "--write")
	if err == nil || !strings.Contains(err.Error(), "not writing") || !strings.Contains(err.Error(), "unknown artifacts") {
		t.Fatalf("want a refusal, got %v\n%s", err, out)
	}
	if got := readFile(t, lockPath); got != before {
		t.Fatalf("a refused update must not touch the lockfile:\n%s", got)
	}
}

func TestUpdateJSONIsTheDiffReport(t *testing.T) {
	dir, _ := updatedProject(t)

	root := cli.NewRoot("test", "none", "unknown")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"update", dir, "--offline", "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := schemas.Validate("diff-report.schema.json", stdout.Bytes()); err != nil {
		t.Fatalf("stdout must be only the report:\n%s\n%v", stdout, err)
	}
	if !strings.Contains(stderr.String(), "was not changed") {
		t.Fatalf("status line should go to stderr: %q", stderr)
	}
}

func TestUpdateNeedsALockfile(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	writeDenoLock(t, dir, "10.26.8")

	_, err := runCLIErr(t, "update", dir, "--offline")
	if err == nil || !strings.Contains(err.Error(), "securock lock") {
		t.Fatalf("want a hint to run lock, got %v", err)
	}
}

func TestUpdateRejectsSARIF(t *testing.T) {
	dir, _ := updatedProject(t)

	_, err := runCLIErr(t, "update", dir, "--offline", "--format", "sarif")
	if err == nil || !strings.Contains(err.Error(), "text or json") {
		t.Fatalf("got %v", err)
	}
}
